package numorstring

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

var (
	allDigits = regexp.MustCompile(`^\d+$`)
	portRange = regexp.MustCompile(`^(\d+):(\d+)$`)
	nameRegex = regexp.MustCompile("^[a-zA-Z0-9_.-]{1,128}$")
)

// Port represents either a range of numeric ports or a named port.
//
//     - For a named port, set the PortName, leaving MinPort and MaxPort as 0.
//     - For a port range, set MinPort and MaxPort to the (inclusive) port numbers.  Set
//       PortName to "".
//     - For a single port, set MinPort = MaxPort and PortName = "".
type Port struct {
	MinPort  uint16 `json:"minPort,omitempty"`
	MaxPort  uint16 `json:"maxPort,omitempty"`
	PortName string `json:"portName" validate:"omitempty,portName"`
}

// PortFromString creates a Port struct from its string representation.  A port
// may either be single value "1234", a range of values "100:200" or a named port: "name".
func PortFromString(s string) (Port, error) {
	if allDigits.MatchString(s) {
		// Port is all digits, it should parse as a single port.
		num, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			msg := fmt.Sprintf("invalid port format (%s)", s)
			return Port{}, errors.New(msg)
		}
		return SinglePort(uint16(num)), nil
	}

	if groups := portRange.FindStringSubmatch(s); len(groups) > 0 {
		// Port matches <digits>:<digits>, it should parse as a range of ports.
		if pmin, err := strconv.ParseUint(groups[1], 10, 16); err != nil {
			msg := fmt.Sprintf("invalid minimum port number in range (%s)", s)
			return Port{}, errors.New(msg)
		} else if pmax, err := strconv.ParseUint(groups[2], 10, 16); err != nil {
			msg := fmt.Sprintf("invalid maximum port number in range (%s)", s)
			return Port{}, errors.New(msg)
		} else {
			return PortFromRange(uint16(pmin), uint16(pmax))
		}
	}

	if !nameRegex.MatchString(s) {
		msg := fmt.Sprintf("invalid name for named port (%s)", s)
		return Port{}, errors.New(msg)
	}

	return NamedPort(s), nil
}

// SinglePort creates a Port struct representing a single port.
func SinglePort(port uint16) Port {
	return Port{MinPort: port, MaxPort: port}
}

func NamedPort(name string) Port {
	return Port{PortName: name}
}

// PortFromRange creates a Port struct representing a range of ports.
func PortFromRange(minPort, maxPort uint16) (Port, error) {
	port := Port{MinPort: minPort, MaxPort: maxPort}
	if minPort > maxPort {
		msg := fmt.Sprintf("minimum port number (%d) is greater than maximum port number (%d) in port range", minPort, maxPort)
		return port, errors.New(msg)
	}
	return port, nil
}
