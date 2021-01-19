package installation

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	v1 "k8s.io/api/core/v1"
)

const (
	// KubeadmConfigConfigMap is defined in k8s.io/kubernetes, which we can't import due to versioning issues.
	kubeadmConfigMap = "kubeadm-config"
)

// extractKubeadmCIDRs looks through the config map and parses lines starting with 'podSubnet'.
func extractKubeadmCIDRs(kubeadmConfig *v1.ConfigMap) ([]string, error) {
	var line []string
	var foundCIDRs []string

	// Look through the config map for a line starting with 'podSubnet', then assign the right variable
	// according to the IP family of the matching string.
	re := regexp.MustCompile(`podSubnet: (.*)`)
	for _, l := range kubeadmConfig.Data {
		if line = re.FindStringSubmatch(l); line != nil {
			break
		}
	}

	if len(line) == 0 {
		return foundCIDRs, fmt.Errorf("kubeadm configuration is missing required podSubnet field")
	}

	if len(line) != 0 {
		// IPv4 and IPv6 CIDRs will be separated by a comma in a dual stack setup.
		for _, cidr := range strings.Split(line[1], ",") {
			_, _, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, err
			}

			// Parsed successfully. Add it to the list.
			foundCIDRs = append(foundCIDRs, cidr)
		}
	}

	return foundCIDRs, nil
}
