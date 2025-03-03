package rulebuilder

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"bird-flowspec-daemon/internal/metrics"
	"bird-flowspec-daemon/internal/route"
)

func actionDropExpressions(enableCounter bool) []expr.Any {
	var expressions []expr.Any
	if enableCounter {
		expressions = append(expressions, []expr.Any{
			&expr.Objref{
				Type: int(nftables.ObjTypeCounter),
				Name: metrics.CounterFlowSpecDropped,
			},
			&expr.Counter{},
		}...)
	}
	// Add a drop verdict for packets exceeding the rate limit
	expressions = append(expressions, &expr.Verdict{
		Kind: expr.VerdictDrop,
	})

	return expressions
}

func BuildRuleExpressions(flowSpecRoute route.FlowspecRoute, enableCounter bool) ([]expr.Any, error) {
	var expressions []expr.Any

	addPrefixMatcher := func(ipnet *net.IPNet, isSource bool) {
		var offset uint32
		var length uint32
		var mask []byte
		var networkAddress []byte

		if ipnet.IP.To4() != nil {
			// IPv4
			length = 4
			if isSource {
				offset = 12 // Source IPv4 address offset
			} else {
				offset = 16 // Destination IPv4 address offset
			}
			mask = net.IP(ipnet.Mask).To4()
			networkAddress = ipnet.IP.To4()
		} else {
			// IPv6
			length = 16
			if isSource {
				offset = 8 // Source IPv6 address offset
			} else {
				offset = 24 // Destination IPv6 address offset
			}
			mask = net.IP(ipnet.Mask).To16()
			networkAddress = ipnet.IP.To16()
		}

		// Load the address from the packet into register 1
		expressions = append(expressions, &expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        offset,
			Len:           length,
		})

		// Apply the network mask to the address in register 1
		expressions = append(expressions, &expr.Bitwise{
			DestRegister:   1,
			SourceRegister: 1,
			Len:            length,
			Mask:           mask,
			Xor:            make([]byte, length), // XOR with zero
		})

		// Compare the masked address with the network address
		expressions = append(expressions, &expr.Cmp{
			Register: 1,
			Data:     networkAddress,
			Op:       expr.CmpOpEq,
		})
	}

	addPortMatcher := func(port *uint16, isSource bool) {
		if port == nil {
			return
		}

		var offset uint32
		if isSource {
			offset = 0 // Source port offset in transport header
		} else {
			offset = 2 // Destination port offset in transport header
		}

		// Load the port from the transport header into register 1
		expressions = append(expressions, &expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        offset,
			Len:           2, // Length of the port number
		})

		// Compare the port with the specified port
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, *port)

		expressions = append(expressions, &expr.Cmp{
			Register: 1,
			Data:     portBytes,
			Op:       expr.CmpOpEq,
		})
	}

	// Add source and destination address matchers
	if flowSpecRoute.MatchAttrs.Source.IP != nil {
		addPrefixMatcher(&flowSpecRoute.MatchAttrs.Source, true)
	}
	if flowSpecRoute.MatchAttrs.Destination.IP != nil {
		addPrefixMatcher(&flowSpecRoute.MatchAttrs.Destination, false)
	}

	if flowSpecRoute.MatchAttrs.Protocol != 0 {
		// Match the protocol
		expressions = append(expressions, &expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		})
		expressions = append(expressions, &expr.Cmp{
			Register: 1,
			Data:     []byte{byte(flowSpecRoute.MatchAttrs.Protocol)},
			Op:       expr.CmpOpEq,
		})
	}

	// Add source and destination port matchers
	if flowSpecRoute.MatchAttrs.SourcePort != 0 {
		addPortMatcher(&flowSpecRoute.MatchAttrs.SourcePort, true)
	}
	if flowSpecRoute.MatchAttrs.DestinationPort != 0 {
		addPortMatcher(&flowSpecRoute.MatchAttrs.DestinationPort, false)
	}

	// Handle the action
	switch flowSpecRoute.Action {
	case route.ActionTrafficRateBytes, route.ActionTrafficRatePackets:
		if flowSpecRoute.Argument == 0x0 { // Drop traffic (rate limit to zero)
			expressions = append(expressions, actionDropExpressions(enableCounter)...)
		}
		if flowSpecRoute.Argument > 0x0 { // Rate limit traffic
			if enableCounter {
				expressions = append(expressions, []expr.Any{
					&expr.Objref{
						Type: int(nftables.ObjTypeCounter),
						Name: metrics.CounterFlowSpecLimitMatched,
					},
					&expr.Counter{},
				}...)
			}
			var limitType expr.LimitType
			switch flowSpecRoute.Action {
			case route.ActionTrafficRateBytes:
				limitType = expr.LimitTypePktBytes
			case route.ActionTrafficRatePackets:
				limitType = expr.LimitTypePkts
			}
			expressions = append(expressions, &expr.Limit{
				Type: limitType,
				Rate: uint64(flowSpecRoute.Argument),
				Over: true,
				Unit: expr.LimitTimeSecond,
			})

			expressions = append(expressions, actionDropExpressions(enableCounter)...)
		}
	default:
		return nil, errors.New("unsupported action type")
	}

	return expressions, nil
}
