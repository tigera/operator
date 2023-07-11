// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
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
	"errors"
	"fmt"
	"os"
	"strings"

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
		Host:        os.Getenv("KUBERNETES_SERVICE_HOST"),
		Port:        os.Getenv("KUBERNETES_SERVICE_PORT"),
		ServiceCIDR: os.Getenv("KUBERNETES_SERVICE_CIDR"),
		DNSServers:  os.Getenv("KUBERNETES_DNS_SERVERS"),
	}
}

// ServiceEndpoint is the Host/Port of the K8s endpoint.
type ServiceEndpoint struct {
	Host        string
	Port        string
	ServiceCIDR string
	DNSServers  string
}

// EnvVars returns a slice of v1.EnvVars KUBERNETES_SERVICE_HOST/PORT if the Host and Port
// of the ServiceEndpoint were set. It returns a nil slice if either was empty as both
// need to be set.
func (k8s ServiceEndpoint) EnvVars(hostNetworked bool, provider operator.Provider) []v1.EnvVar {
	if k8s.Host == "" || k8s.Port == "" {
		return nil
	}

	if provider == operator.ProviderDockerEE && !hostNetworked && k8s.Host == dockerEEProxyLocal {
		// Special case: Docker EE (now MKE) has a proxy on each host that is only accessible from the host
		// namespace.  Don't try to use it from non-host network pods.
		//
		// It's also possible for the user to configure a different route to the API server; we let those through.
		return nil
	}

	envVars := []v1.EnvVar{
		{Name: "KUBERNETES_SERVICE_HOST", Value: k8s.Host},
		{Name: "KUBERNETES_SERVICE_PORT", Value: k8s.Port},
	}

	if k8s.ServiceCIDR != "" {
		envVars = append(envVars, v1.EnvVar{Name: "KUBERNETES_SERVICE_CIDR", Value: k8s.ServiceCIDR})
	}
	if k8s.DNSServers != "" {
		envVars = append(envVars, v1.EnvVar{Name: "KUBERNETES_DNS_SERVERS", Value: k8s.DNSServers})
	}

	return envVars
}

func (k8s ServiceEndpoint) CNIAPIRoot() string {
	if k8s.Host == "" || k8s.Port == "" {
		return ""
	}
	host := k8s.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("https://%s:%s", host, k8s.Port)
}

func (k8s ServiceEndpoint) WindowsRequiredInfoPresent() error {
	if k8s.Host != "" && k8s.Port != "" && k8s.ServiceCIDR != "" && k8s.DNSServers != "" {
		return nil
	}

	return errors.New("missing required information for Windows on ServiceEndpoint configuration")
}
