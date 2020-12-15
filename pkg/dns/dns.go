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
)

const (
	// Default location for the resolv.conf file.
	DefaultResolveConfPath = "/etc/resolv.conf"

	// Default cluster domain value for k8s clusters.
	DefaultLocalDNS = "svc.cluster.local"
)

// GetLocalDNSName parses the path to resolv.conf to find the local DNS name.
func GetLocalDNSName(resolvConfPath string) (string, error) {
	var localDNSName string
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	reg := regexp.MustCompile(`^search.*?\s(svc\.[^\s]*)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := reg.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			localDNSName = match[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if localDNSName == "" {
		return "", fmt.Errorf("failed to find local DNS name in resolv.conf")
	}

	return localDNSName, nil
}
