package route

import (
	"net"
)

type matchAttrs struct {
	Source          net.IPNet
	Destination     net.IPNet
	Protocol        uint64
	SourcePort      uint16
	DestinationPort uint16
}

type sessionAttrs struct {
	SessionName     string
	NeighborAddress net.IP
	ImportTime      string
}

type FlowspecRoute struct {
	MatchAttrs   matchAttrs
	SessionAttrs sessionAttrs
	Action       int64
	Argument     int64
}

// See rfc 8955
// https://datatracker.ietf.org/doc/html/rfc8955#traffic_extended_communities
const (
	ActionTrafficRateBytes   = 0x8006
	ActionTrafficRatePackets = 0x800c
	ActionTrafficAction      = 0x8007
	ActionRedirect           = 0x8008
	ActionTrafficMarking     = 0x8009
)
