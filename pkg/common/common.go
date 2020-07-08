// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package common

import (
	"fmt"
	"os"
)

const (
	CalicoNamespace     = "calico-system"
	TyphaDeploymentName = "calico-typha"
	NodeDaemonSetName   = "calico-node"

	TigeraPrometheusNamespace = "tigera-prometheus"
)

// GetK8sEndpointOverride returns an ip:port override for the KUBERNETES_SERVICE_HOST/PORT
func GetK8sEndpointOverride() (string, string, error) {
	host := os.Getenv("TIGERA_OPERATOR_OVERRIDE_K8S_HOST")
	port := os.Getenv("TIGERA_OPERATOR_OVERRIDE_K8S_PORT")

	if host == "" || port == "" {
		return "", "", fmt.Errorf("k8s host and/or port override env vars empty")
	}

	return host, port, nil
}
