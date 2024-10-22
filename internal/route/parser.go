package route

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
)

func ParseFlowSpecRoute(input string) (FlowspecRoute, error) {
	parts := strings.Split(input, "\n")

	header := "flow" + parts[0]
	localSessionAttrs, err := parseSessionAttrs(inclusiveMatch(header, "[", "]"))
	if err != nil {
		return FlowspecRoute{}, fmt.Errorf("invalid flowspec route: (%s): %v\n", header, err)
	}

	localMatchAttrs, err := parseMatchAttrs(inclusiveMatch(header, "{ ", " }"))
	if err != nil {
		return FlowspecRoute{}, fmt.Errorf("invalid flowspec route: (%s): %v\n", header, err)
	}

	action, arg, err := parseFlowCommunity(inclusiveMatch(input, "BGP.ext_community: (", ")"))
	if err != nil {
		return FlowspecRoute{}, fmt.Errorf("invalid flowspec route: (%s): %v\n", header, err)
	}

	route := FlowspecRoute{
		MatchAttrs:   localMatchAttrs,
		SessionAttrs: localSessionAttrs,
		Action:       action,
		Argument:     arg,
	}

	return route, nil // nil error
}

func inclusiveMatch(input string, leftDelimiter string, rightDelimiter string) string {
	leftSide := strings.Split(input, leftDelimiter)
	if len(leftSide) < 2 {
		return ""
	}

	return strings.Split(leftSide[1], rightDelimiter)[0]
}

// parseCommunity parses a BGP community string into a flowspec action and attribute
func parseFlowCommunity(input string) (int64, int64, error) {
	parts := strings.Split(input, ", ")
	if len(parts) != 3 {
		return -1, -1, errors.New("invalid community string")
	}

	// Parse action as int
	actionPart := strings.TrimSuffix(parts[1], "0000")
	action, err := strconv.ParseInt(actionPart, 0, 64)
	if err != nil {
		return -1, -1, errors.New("invalid community string: " + err.Error())
	}

	// Validate action
	if !(action == ActionTrafficRate || action == ActionTrafficAction || action == ActionRedirect || action == ActionTrafficMarking) {
		return -1, -1, errors.New("invalid flowspec action")
	}

	// Parse argument as int
	argPart := strings.TrimSuffix(parts[2], "0000")
	arg, err := strconv.ParseInt(argPart, 0, 64)
	if err != nil {
		return -1, -1, errors.New("invalid community string: " + err.Error())
	}

	return action, arg, nil // nil error
}

func parseMatchAttrs(input string) (matchAttrs, error) {
	var outputMatchAttrs = matchAttrs{}
	for _, kvPair := range strings.Split(input, ";") {
		parts := strings.Split(strings.TrimRight(strings.TrimLeft(kvPair, " "), " "), " ")
		if len(parts) > 1 {
			key := strings.TrimSpace(strings.Join(parts[:len(parts)-1], "_"))
			value := strings.TrimSpace(parts[len(parts)-1])
			switch key {
			case "src":
				_, localSource, err := net.ParseCIDR(value)
				if err != nil {
					return matchAttrs{}, errors.New("unable to parse source prefix")
				}
				outputMatchAttrs.Source = *localSource
			case "dst":
				_, localDestination, err := net.ParseCIDR(value)
				if err != nil {
					return matchAttrs{}, errors.New("unable to parse destination prefix")
				}
				outputMatchAttrs.Destination = *localDestination
			case "sport":
				localSPort, err := strconv.Atoi(value)
				if err != nil {
					return matchAttrs{}, errors.New("unable to parse source port")
				}
				outputMatchAttrs.SourcePort = uint16(localSPort)
			case "dport":
				localDPort, err := strconv.Atoi(value)
				if err != nil {
					return matchAttrs{}, errors.New("unable to parse destination port")
				}
				outputMatchAttrs.DestinationPort = uint16(localDPort)
			case "next_header":
				protocol, protocolParseError := strconv.ParseUint(value, 0, 8)
				if protocolParseError != nil {
					return matchAttrs{}, errors.New("unable to parse protocol")
				}
				outputMatchAttrs.Protocol = protocol
			default:
				slog.Warn("unknown match attribute", slog.String("key", key), slog.String("value", value))
			}
		}
	}

	return outputMatchAttrs, nil // nil error
}

// parseSessionAttrs parses the BIRD session attributes
func parseSessionAttrs(input string) (sessionAttrs, error) {
	var outputSessionAttrs = sessionAttrs{}

	parts := strings.Split(input, " ")
	if len(parts) != 4 {
		return sessionAttrs{}, errors.New("invalid token length")
	}

	// Set string values
	outputSessionAttrs.SessionName = parts[0]
	outputSessionAttrs.ImportTime = parts[1]

	ip := net.ParseIP(parts[3])
	if ip == nil {
		return sessionAttrs{}, errors.New("invalid neighbor IP address")
	}

	outputSessionAttrs.NeighborAddress = ip

	return outputSessionAttrs, nil // nil error
}
