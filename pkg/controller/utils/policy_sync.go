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

// DefaultPolicySyncPrefix is the operator-managed value for
// FelixConfiguration.policySyncPathPrefix. The applicationlayer and istio
// controllers both write this value when their respective features need a
// running policy-sync gRPC server on the host (Dikastes sidecar, Istio
// ambient waypoint l7-collector, EGW).
const DefaultPolicySyncPrefix = "/var/run/nodeagent"

// ApplicationLayerRequiresPolicySync reports whether the given
// ApplicationLayer CR has any feature enabled that requires
// policySyncPathPrefix to be set on FelixConfiguration. A nil receiver
// returns false (the AL CR is absent or being deleted).
func ApplicationLayerRequiresPolicySync(al *operatorv1.ApplicationLayer) bool {
	if al == nil {
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
// installation variant is Enterprise; this predicate mirrors that gate so
// the FelixConfiguration field tracks the renderer.
func IstioRequiresPolicySync(istio *operatorv1.Istio, variant operatorv1.ProductVariant) bool {
	return istio != nil && variant.IsEnterprise()
}

// DesiredPolicySyncPathPrefix returns the value FelixConfiguration's
// policySyncPathPrefix should hold given the currently set value and
// whether either the applicationlayer or istio controllers need it.
//
//   - A non-empty existing value that does not match the operator-managed
//     default is treated as a customer override and preserved verbatim.
//   - If either controller needs the field, the operator-managed default
//     is returned.
//   - Otherwise the field is cleared.
//
// Both the applicationlayer and istio controllers call this from their
// set and cleanup paths to keep coordination explicit and symmetric.
func DesiredPolicySyncPathPrefix(existing string, alNeeds, istioNeeds bool) string {
	if existing != "" && existing != DefaultPolicySyncPrefix {
		return existing
	}
	if alNeeds || istioNeeds {
		return DefaultPolicySyncPrefix
	}
	return ""
}
