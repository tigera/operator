// Copyright (c) 2026 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

// UIGatewaySpec configures a Gateway API Gateway to expose a Calico UI
// component (Manager or Whisker) via Calico Ingress Gateway. Used as the
// type for spec.gateway on both ManagerSpec and WhiskerSpec.
type UIGatewaySpec struct {
	// Hostname for the Gateway listener. The operator generates a TLS
	// certificate with a SAN matching this hostname. For Enterprise Manager,
	// this must match the Authentication CR's managerDomain when OIDC is
	// configured.
	// +required
	// +kubebuilder:validation:MinLength=1
	Hostname string `json:"hostname"`

	// Port the Gateway listens on externally. Default: 443.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=443
	Port *int32 `json:"port,omitempty"`

	// GatewayNamespace is the namespace where the Gateway and Envoy Proxy
	// pods are created. When different from calico-system, the operator
	// creates a ReferenceGrant to permit cross-namespace routing.
	// Default: "calico-system".
	// +optional
	GatewayNamespace *string `json:"gatewayNamespace,omitempty"`
}

// GetPort returns the configured port or the default (443).
func (g *UIGatewaySpec) GetPort() int32 {
	if g.Port != nil {
		return *g.Port
	}
	return 443
}

// GetGatewayNamespace returns the configured namespace or the default ("calico-system").
func (g *UIGatewaySpec) GetGatewayNamespace() string {
	if g.GatewayNamespace != nil && *g.GatewayNamespace != "" {
		return *g.GatewayNamespace
	}
	return "calico-system"
}
