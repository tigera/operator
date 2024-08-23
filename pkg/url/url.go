package url

import (
	"fmt"
	"net"
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

func ParseHostPortFromHTTPProxyURL(proxyURL string) (string, error) {
	parsedProxyURL, err := url.ParseRequestURI(proxyURL)
	if err != nil {
		return "", err
	}

	parsedScheme := parsedProxyURL.Scheme
	if parsedScheme == "" || (parsedScheme != "http" && parsedScheme != "https") {
		return "", fmt.Errorf("unexpected scheme for HTTP proxy URL: %s", parsedScheme)
	}

	if parsedProxyURL.Port() != "" {
		// Host is already in host:port form.
		return parsedProxyURL.Host, nil
	}

	// Scheme is either http or https at this point.
	if parsedProxyURL.Scheme == "http" {
		return net.JoinHostPort(parsedProxyURL.Host, "80"), nil
	} else {
		return net.JoinHostPort(parsedProxyURL.Host, "443"), nil
	}
}
