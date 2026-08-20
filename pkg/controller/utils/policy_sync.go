// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	operatorv1 "github.com/tigera/operator/api/v1"
)

// DefaultPolicySyncPrefix is where Felix opens the gRPC socket the Dikastes sidecar,
// the Istio waypoint l7-collector, and egress gateways dial.
const DefaultPolicySyncPrefix = "/var/run/nodeagent"

// ApplicationLayerRequiresPolicySync reports whether the given
// ApplicationLayer CR has any feature enabled that requires
// policySyncPathPrefix to be set on FelixConfiguration. A CR that is absent
// or being deleted returns false.
func ApplicationLayerRequiresPolicySync(al *operatorv1.ApplicationLayer) bool {
	if al == nil || !al.DeletionTimestamp.IsZero() {
		return false
	}
	spec := &al.Spec
	if spec.LogCollection != nil && spec.LogCollection.CollectLogs != nil &&
		*spec.LogCollection.CollectLogs == operatorv1.L7LogCollectionEnabled {
		return true
	}
	if spec.WebApplicationFirewall != nil &&
		*spec.WebApplicationFirewall == operatorv1.WAFEnabled {
		return true
	}
	if spec.ApplicationLayerPolicy != nil &&
		*spec.ApplicationLayerPolicy == operatorv1.ApplicationLayerPolicyEnabled {
		return true
	}
	if spec.SidecarInjection != nil &&
		*spec.SidecarInjection == operatorv1.SidecarEnabled {
		return true
	}
	return false
}

// IstioRequiresPolicySync reports whether an Istio CR is active in a way
// that requires policySyncPathPrefix to be set. The L7 ambient waypoint
// resources (l7-collector sidecar + EnvoyFilter) are rendered when the
// installation variant is Enterprise and waypoint logging is enabled; this
// predicate mirrors that gate (via the shared WaypointLoggingEnabled helper)
// so the FelixConfiguration field tracks the renderer — including when
// waypoint logging is explicitly Disabled.
func IstioRequiresPolicySync(istio *operatorv1.Istio, variant operatorv1.ProductVariant) bool {
	if istio == nil || !istio.DeletionTimestamp.IsZero() {
		return false
	}
	return variant.IsEnterprise() && istio.WaypointLoggingEnabled()
}

// GatewayAPIRequiresPolicySync reports whether a GatewayAPI CR is present, which is when
// the gateway data plane needs Felix's policy-sync socket.
func GatewayAPIRequiresPolicySync(gw *operatorv1.GatewayAPI) bool {
	return gw != nil && gw.DeletionTimestamp.IsZero()
}
