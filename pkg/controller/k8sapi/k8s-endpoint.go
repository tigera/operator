// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"os"

	v1 "k8s.io/api/core/v1"
)

// Endpoint is the default ServiceEndpoint learned from environment variables.
var Endpoint ServiceEndpoint

func init() {
	// We read whatever is in the variable. We would read "" if they were not set.
	// We decide at the point of usage what to do with the values.
	Endpoint = ServiceEndpoint{
		Host: os.Getenv("KUBERNETES_SERVICE_HOST"),
		Port: os.Getenv("KUBERNETES_SERVICE_PORT"),
	}
}

// ServiceEndpoint is the Host/Port of the K8s endpoint.
type ServiceEndpoint struct {
	Host string
	Port string
}

// EnvVars returns a slice of v1.EnvVars KUBERNETES_SERVICE_HOST/PORT if the Host and Port
// of the ServiceEndpoint were set. It returns a nil slice if either was empty as both
// need to be set.
func (k8s ServiceEndpoint) EnvVars() []v1.EnvVar {
	if k8s.Host == "" || k8s.Port == "" {
		return nil
	}

	return []v1.EnvVar{
		{Name: "KUBERNETES_SERVICE_HOST", Value: k8s.Host},
		{Name: "KUBERNETES_SERVICE_PORT", Value: k8s.Port},
	}
}
