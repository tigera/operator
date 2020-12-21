// Copyright (c) 2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dns

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	// Default location for the resolv.conf file.
	DefaultResolveConfPath = "/etc/resolv.conf"

	// Default cluster domain value for k8s clusters.
	DefaultClusterDomain = "cluster.local"
)

// GetClusterDomain parses the path to resolv.conf to find the cluster domain.
func GetClusterDomain(resolvConfPath string) (string, error) {
	var clusterDomain string
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	reg := regexp.MustCompile(`^search.*?\ssvc\.([^\s]*)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := reg.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			clusterDomain = match[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if clusterDomain == "" {
		return "", fmt.Errorf("failed to find cluster domain in resolv.conf")
	}

	return clusterDomain, nil
}

// GetServiceDNSNames parses the fully-qualified domain service name and
// returns a list of its qualified service names.
func GetServiceDNSNames(fqdnServiceName string, clusterDomain string) ([]string, error) {
	all := strings.Split(fqdnServiceName, ".")

	// The FQDN service name will be: <svc_name>.<ns>.svc.<cluster-domain>
	// There is no guarantee the cluster-domain will be dotted (kubelet does not
	// validate the cluster domain).
	if len(all) < 4 {
		return nil, fmt.Errorf("failed to split FQDN service name %q", fqdnServiceName)
	}

	// We return:
	// - <svc_name>
	// - <svc_name>.<ns>
	// - <svc_name>.<ns>.svc
	// - <svc_name>.<ns>.svc.<cluster-domain>
	name := all[0]
	nameWithNs := fmt.Sprintf("%s.%s", name, all[1])
	svcNameWithNs := fmt.Sprintf("%s.svc", nameWithNs)
	fqdnSvcName := fmt.Sprintf("%s.%s", svcNameWithNs, clusterDomain)

	return []string{name, nameWithNs, svcNameWithNs, fqdnSvcName}, nil
}
