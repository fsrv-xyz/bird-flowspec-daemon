//go:build linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"bird-flowspec-daemon/internal/metrics"
	"bird-flowspec-daemon/internal/route"
	"bird-flowspec-daemon/internal/rulebuilder"
	"bird-flowspec-daemon/internal/rulesum"
)

func birdCommand(ctx context.Context, command string) (string, error) {
	defer func(start time.Time) {
		metrics.BirdSocketQueryDurationSeconds.Observe(time.Since(start).Seconds())
	}(time.Now())
	slog.Debug("Reading BIRD rules", slog.String("command", command))
	defer func() {
		slog.Debug("Finished reading BIRD rules", slog.String("command", command))
	}()

	// Connect to the Bird socket
	conn, err := net.Dial("unix", config.birdSocketPath)
	if err != nil {
		return "", fmt.Errorf("failed to connect to bird socket: %v", err)
	}
	defer conn.Close()

	// Create a channel to handle the scanner
	done := make(chan struct{})
	var response strings.Builder
	errChan := make(chan error, 1)

	// Send the command to retrieve all routes
	_, err = conn.Write([]byte(fmt.Sprintf("%s\n", command)))
	if err != nil {
		return "", fmt.Errorf("failed to write to bird socket: %v", err)
	}

	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			response.WriteString(line + "\n")
			if strings.HasPrefix(line, "0000 ") {
				break
			}
		}
		if err := scanner.Err(); err != nil {
			errChan <- fmt.Errorf("error reading from bird socket: %v", err)
		} else {
			close(done)
		}
	}()

	// Wait for either the context to be done or the reading to complete
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("operation canceled: %v", ctx.Err())
	case err := <-errChan:
		return "", err
	case <-done:
		return response.String(), nil
	}
}

type configuration struct {
	birdSocketPath       string
	debug                bool
	metricsListenAddress string
	interval             time.Duration
	enableCounter        bool
}

var config = configuration{}

func init() {
	app := kingpin.New("bird-flowspec-daemon", "A BIRD flowspec daemon")
	app.Flag("debug", "Enable debug mode").Short('d').BoolVar(&config.debug)
	app.Flag("bird-socket", "Path to BIRD socket").Envar("BIRD_SOCKET_PATH").Default("/run/bird/bird.ctl").ExistingFileVar(&config.birdSocketPath)
	app.Flag("metrics.listen-address", "Address to listen on for metrics").Default("127.0.0.1:9302").StringVar(&config.metricsListenAddress)
	app.Flag("interval", "Interval to check for new routes").Envar("CHECK_INTERVAL").Default("10s").DurationVar(&config.interval)
	app.Flag("enable-counter", "Enable counter in nftables rules").Envar("ENABLE_COUNTER").Default("false").BoolVar(&config.enableCounter)
	app.HelpFlag.Short('h')
	kingpin.MustParse(app.Parse(os.Args[1:]))

	logLevel := slog.LevelInfo
	if config.debug {
		logLevel = slog.LevelDebug
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     logLevel,
	})))
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-ch
		slog.Info("Received termination, signaling shutdown")
		cancel()
	}()

	metricsServer := &http.Server{Addr: config.metricsListenAddress}
	go func() {
		prometheus.DefaultRegisterer.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
		slog.Info("serving metrics", slog.String("address", metricsServer.Addr))
		slog.Error("failed to server metrics endpoint", slog.String("error", metricsServer.ListenAndServe().Error()))
	}()
	go func() {
		<-ctx.Done()
		slog.Info("shutting down metrics server")
		metricsServer.Shutdown(context.Background())
	}()

	nft, nftablesConnectError := nftables.New()
	if nftablesConnectError != nil {
		slog.Error("nftables connection error", slog.String("error", nftablesConnectError.Error()))
		panic(nftablesConnectError)
	}

	table := nft.CreateTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})
	if err := nft.Flush(); err != nil {
		slog.Debug("nftables flush error: %v", slog.String("error", err.Error()))
	}

	chain := nft.AddChain(&nftables.Chain{
		Name:  "flowspec",
		Table: table,
	})
	if err := nft.Flush(); err != nil {
		panic(err)
	}

	lastChecksum := [16]byte{}

	ticker := time.NewTicker(config.interval)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Shutting down")
			return
		case <-ticker.C:
			timeoutCtx, cancel := context.WithTimeout(ctx, config.interval)
			response, commandError := birdCommand(timeoutCtx, "show route where ((net.type = NET_FLOW4 || net.type = NET_FLOW6) && source = RTS_BGP) all")
			if commandError != nil {
				slog.Error("error running bird command", slog.String("error", commandError.Error()))
				continue
			}

			rawRoutes := strings.Split(response, "flow")
			cancel()

			var nftRules []*nftables.Rule

			for _, flowRoute := range rawRoutes {
				// Ignore lines that aren't a valid IPv4/IPv6 flowspec route
				if !(strings.HasPrefix(flowRoute, "4") || strings.HasPrefix(flowRoute, "6")) {
					continue
				}

				flowSpecRoute, parseError := route.ParseFlowSpecRoute(flowRoute)
				if parseError != nil {
					slog.Warn("error parsing flowspec route", slog.String("error", parseError.Error()))
					continue
				}

				ruleExpressions, buildError := rulebuilder.BuildRuleExpressions(flowSpecRoute, config.enableCounter)
				if buildError != nil {
					slog.Warn("error building rule expressions", slog.String("error", buildError.Error()))
					continue
				}

				rule := &nftables.Rule{
					Table: table,
					Chain: chain,
					Exprs: ruleExpressions,
				}

				//slog.Debug("Added rule", slog.String("rule", fmt.Sprintf("%#v", flowSpecRoute)))
				nftRules = append(nftRules, rule)
			}

			// get the current number of rules in the nftables chain
			existingRules, getRulesError := nft.GetRules(table, chain)
			if getRulesError != nil {
				slog.Error("error getting existing rules", slog.String("error", getRulesError.Error()))
			}
			if len(existingRules) != len(nftRules) {
				slog.Info("number of rules in nftables chain does not match, reapplying all rules")
				lastChecksum = [16]byte{}
			}

			checksum := rulesum.CheckSum(nftRules)
			if checksum == lastChecksum {
				slog.Debug("Checksums match, skipping nftables update", slog.String("checksum", fmt.Sprintf("%x", checksum)))
				continue
			}
			lastChecksum = checksum

			slog.Info("updating nftables", slog.String("checksum", fmt.Sprintf("%x", checksum)))
			metrics.FlowSpecRoutesTotal.Set(float64(len(nftRules)))
			nft.FlushChain(chain)
			for _, rule := range nftRules {
				nft.AddRule(rule)
			}
			start := time.Now()
			if err := nft.Flush(); err != nil {
				panic(err)
			}
			slog.Info("nftables updated", slog.String("duration", time.Since(start).String()))
			metrics.NftablesFlushDurationSeconds.Observe(time.Since(start).Seconds())
		}
	}
}
