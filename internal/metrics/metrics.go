package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	BirdSocketQueryDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "bird_socket_query_duration_seconds",
		Help:    "duration of BIRD socket queries",
		Buckets: prometheus.ExponentialBuckets(0.0001, 1.5, 15),
	})

	FlowSpecRoutesTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "flowspec_routes_total",
		Help: "Total number of flowspec routes",
	})

	NftablesFlushDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "nftables_flush_duration_seconds",
		Help: "duration of nftables flush operations",
	})
)
