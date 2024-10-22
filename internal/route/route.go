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

// RFC 5575
// 0x8006, traffic-rate, 2-byte as#, 4-byte float
// 0x8007, traffic-action, bitmask
// 0x8008, redirect, 6-byte Route Target
// 0x8009, traffic-marking, DSCP value
const (
	ActionTrafficRate    = 0x8006
	ActionTrafficAction  = 0x8007
	ActionRedirect       = 0x8008
	ActionTrafficMarking = 0x8009
)
