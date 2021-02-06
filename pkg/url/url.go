package url

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseEndpoint parses an endpoint of the form scheme://host:port and returns the components.
func ParseEndpoint(endpoint string) (string, string, string, error) {
	url, err := url.Parse(endpoint)
	if err != nil {
		return "", "", "", err
	}
	splits := strings.Split(url.Host, ":")
	if len(splits) != 2 {
		return "", "", "", fmt.Errorf("invalid host: %s", url.Host)
	}
	return url.Scheme, splits[0], splits[1], nil
}
