//go:build linux

package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/google/nftables"

	"bird-flowspec-daemon/internal/route"
	"bird-flowspec-daemon/internal/rulebuilder"
)

var birdSocket = "/run/bird/bird.ctl"

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
	slog.Debug("Connecting to BIRD socket")
	conn, err := net.Dial("unix", birdSocket)
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

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
		//Level: slog.LevelInfo,
	})))
}

func main() {
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
		slog.Warn("nftables flush error: %v", slog.String("error", err.Error()))
	}

	chain := nft.AddChain(&nftables.Chain{
		Name:  "flowspec",
		Table: table,
	})
	if err := nft.Flush(); err != nil {
		panic(err)
	}
	nft.FlushChain(chain)

	rawRoutes := strings.Split(birdCommand("show route where (net.type = NET_FLOW4 || net.type = NET_FLOW6) all"), "flow")
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
		nft.AddRule(rule)

		slog.Debug("Added rule", slog.String("rule", fmt.Sprintf("%#v", flowSpecRoute)))
	}
	if err := nft.Flush(); err != nil {
		panic(err)
	}
}
