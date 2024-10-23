//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
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

// Buffered io Reader
func bufferedRead(reader io.Reader) string {
	slog.Debug("Reading from BIRD socket")
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 32)
	for {
		n, err := reader.Read(tmp)
		if err != nil {
			slog.Error("read error: %s\n", slog.String("error", err.Error()))
			panic(err)
		}
		buf = append(buf, tmp[:n]...)
		// TODO: check why is stuck with trailing newline character
		if strings.Contains(string(tmp), "0000 ") {
			return string(buf)
		}
	}
}

// TODO: implement error handling
func birdCommand(command string) string {
	defer func(start time.Time) {
		elapsed := time.Since(start)
		metrics.BirdSocketQueryDurationSeconds.Observe(elapsed.Seconds())
	}(time.Now())

	slog.Debug("Connecting to BIRD socket")
	conn, err := net.Dial("unix", config.birdSocketPath)
	if err != nil {
		slog.Error("BIRD socket connect: %v", slog.String("error", err.Error()))
		panic(err)
	}
	//goland:noinspection ALL
	defer conn.Close()

	slog.Debug("Connected to BIRD socket")
	//connResp := bufferedRead(conn)
	//if !strings.HasSuffix(connResp, "ready.\n") {
	//	log.Fatalf("BIRD connection response: %s", connResp)
	//}

	slog.Debug("Sending BIRD command", slog.String("command", command))
	_, err = conn.Write([]byte(strings.Trim(command, "\n") + "\n"))
	slog.Debug("Sent BIRD command", slog.String("command", command))
	if err != nil {
		slog.Error("BIRD command write: %v", slog.String("error", err.Error()))
		panic(err)
	}

	return bufferedRead(conn)
}

type configuration struct {
	birdSocketPath       string
	debug                bool
	metricsListenAddress string
	interval             time.Duration
}

var config = configuration{}

func init() {
	app := kingpin.New("bird-flowspec-daemon", "A BIRD flowspec daemon")
	app.Flag("debug", "Enable debug mode").Short('d').BoolVar(&config.debug)
	app.Flag("bird-socket", "Path to BIRD socket").Default("/run/bird/bird.ctl").ExistingFileVar(&config.birdSocketPath)
	app.Flag("metrics.listen-address", "Address to listen on for metrics").Default("127.0.0.1:9302").StringVar(&config.metricsListenAddress)
	app.Flag("interval", "Interval to check for new routes").Default("10s").DurationVar(&config.interval)
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
			rawRoutes := strings.Split(birdCommand("show route where (net.type = NET_FLOW4 || net.type = NET_FLOW6) all"), "flow")

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

				ruleExpressions, buildError := rulebuilder.BuildRuleExpressions(flowSpecRoute)
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
