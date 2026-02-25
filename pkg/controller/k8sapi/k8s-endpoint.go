// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
//
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

package k8sapi

import (
	"fmt"
	"net"
	"os"
	"strings"

	calicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	operator "github.com/tigera/operator/api/v1"
	v1 "k8s.io/api/core/v1"
)

const dockerEEProxyLocal = "proxy.local"

// Endpoint is the default ServiceEndpoint learned from environment variables.
var Endpoint ServiceEndpoint

func init() {
	// We read whatever is in the variable. We would read "" if they were not set.
	// We decide at the point of usage what to do with the values.
	Endpoint = ServiceEndpoint{
		HostNetworkHost: os.Getenv("KUBERNETES_SERVICE_HOST"),
		HostNetworkPort: os.Getenv("KUBERNETES_SERVICE_PORT"),
	}
}

// ServiceEndpoint is the Host/Port of the K8s endpoint.
// HostNetworkHost/HostNetworkPort are used for host-networked pods, while
// PodNetworkHost/PodNetworkPort are used for pod-networked pods.
type ServiceEndpoint struct {
	HostNetworkHost string
	HostNetworkPort string
	PodNetworkHost  string
	PodNetworkPort  string
}

// EnvVars returns a slice of v1.EnvVars with the K8s service endpoint if the Host and Port
// of the ServiceEndpoint were set. It returns a nil slice if either was empty as both
// need to be set. For host-networked pods, it returns KUBERNETES_SERVICE_HOST/PORT.
// For pod-networked pods, it returns KUBERNETES_SERVICE_HOST_POD_NETWORK/PORT_POD_NETWORK.
func (k8s ServiceEndpoint) EnvVars(hostNetworked bool, provider operator.Provider) []v1.EnvVar {
	if !hostNetworked {
		if k8s.PodNetworkHost == "" || k8s.PodNetworkPort == "" {
			return nil
		}
		return []v1.EnvVar{
			{Name: "KUBERNETES_SERVICE_HOST", Value: k8s.PodNetworkHost},
			{Name: "KUBERNETES_SERVICE_PORT", Value: k8s.PodNetworkPort},
		}
	}

	if k8s.HostNetworkHost == "" || k8s.HostNetworkPort == "" {
		return nil
	}
	return []v1.EnvVar{
		{Name: "KUBERNETES_SERVICE_HOST", Value: k8s.HostNetworkHost},
		{Name: "KUBERNETES_SERVICE_PORT", Value: k8s.HostNetworkPort},
	}
}

// DestinationEntityRule returns an EntityRule to match the HostNetworkHost and HostNetworkPort
// if the ServiceEndpoint was set. It returns nil if either was empty.
func (k8s ServiceEndpoint) DestinationEntityRule() (*calicov3.EntityRule, error) {
	if k8s.HostNetworkHost == "" || k8s.HostNetworkPort == "" {
		return nil, nil
	}

	p, err := numorstring.PortFromString(k8s.HostNetworkPort)
	if err != nil {
		return nil, err
	}

	rule := calicov3.EntityRule{
		Ports: []numorstring.Port{p},
	}

	ip := net.ParseIP(k8s.HostNetworkHost)
	if ip == nil {
		rule.Domains = []string{k8s.HostNetworkHost}
	} else {
		var netSuffix string
		if ip.To4() != nil {
			netSuffix = "/32"
		} else {
			netSuffix = "/128"
		}
		rule.Nets = []string{ip.String() + netSuffix}
	}

	return &rule, nil
}

func (k8s ServiceEndpoint) CNIAPIRoot() string {
	if k8s.HostNetworkHost == "" || k8s.HostNetworkPort == "" {
		return ""
	}
	host := k8s.HostNetworkHost
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("https://%s:%s", host, k8s.HostNetworkPort)
}
