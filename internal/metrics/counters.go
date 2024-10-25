package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	counterNamespace = "nftables"
	labelCounterName = "name"
)
const (
	CounterFlowSpecHandled      = "flowspec_handled"
	CounterFlowSpecDropped      = "flowspec_dropped"
	CounterFlowSpecLimitMatched = "flowspec_limit_matched"
)

type counterMetricsRegistry struct {
	packets *prometheus.GaugeVec
	bytes   *prometheus.GaugeVec
}

var (
	counters       = []string{CounterFlowSpecHandled, CounterFlowSpecDropped, CounterFlowSpecLimitMatched}
	counterMetrics = counterMetricsRegistry{}
)

func InstallNamedCounters(table *nftables.Table) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()

	for _, c := range counters {
		nft.AddObject(&nftables.CounterObj{
			Name:  c,
			Table: table,
		})
	}

	// Create prometheus metrics
	counterMetrics.packets = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: counterNamespace,
		Name:      "counter_packets",
		Help:      "counted packets per counter",
	}, []string{labelCounterName})
	counterMetrics.bytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: counterNamespace,
		Name:      "counter_bytes",
		Help:      "counted bytes per counter",
	}, []string{labelCounterName})

	return nft.Flush()
}

func queryCounterMetrics(table *nftables.Table) {
	nft, err := nftables.New()
	if err != nil {
		return
	}
	defer nft.CloseLasting()

	namedObjects, getObjectsError := nft.GetObjects(table)
	if getObjectsError != nil {
		slog.Error("failed to get named nftalbes objects", slog.String("error", getObjectsError.Error()))
	}
	for _, obj := range namedObjects {
		switch obj.(type) {
		case *nftables.CounterObj:
			counterObject := obj.(*nftables.CounterObj)
			for _, counter := range counters {
				if counter != counterObject.Name {
					continue
				}
				counterMetrics.packets.With(prometheus.Labels{labelCounterName: counter}).Set(float64(counterObject.Packets))
				counterMetrics.bytes.With(prometheus.Labels{labelCounterName: counter}).Set(float64(counterObject.Bytes))
				break
			}
		default:
			continue
		}
	}
}

func CounterMetricsWorker(ctx context.Context, table *nftables.Table) {
	queryCounterMetrics(table)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Debug("querying counter metrics")
			queryCounterMetrics(table)
		}
	}
}
