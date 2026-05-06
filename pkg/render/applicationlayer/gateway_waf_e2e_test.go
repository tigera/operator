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

package applicationlayer_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/render/applicationlayer"
)

// TestWAFRenderDeltaSet_LicensePresent_AllComponentsCoherent is a higher-level
// render-delta test that calls all three WAF render entry points, unions the results,
// and asserts the complete combined object set is coherent when the IngressGateway
// license is present:
//
//   - Expected total: 10 objects
//   - Kind counts: 1 ValidatingWebhookConfiguration + 2 Deployments + 2 Services +
//     2 ServiceAccounts + 1 ClusterRole + 1 ClusterRoleBinding + 1 ConfigMap
//   - No (Kind, Namespace, Name) collisions
//   - Namespace placement: webhook namespaced objects in calico-system, BFF namespaced
//     objects in tigera-ui-apis, frontend ConfigMap in calico-system
//
// This mirrors the object set the Installation reconciler will accumulate when the
// IngressGateway license is present (controller wiring in Tasks 4/5, pending in
// sibling subagent; this test validates the render layer in isolation).
func TestWAFRenderDeltaSet_LicensePresent_AllComponentsCoherent(t *testing.T) {
	const (
		webhookImage = "tigera/waf-admission-controller:v0.1.0"
		bffImage     = "tigera/waf-bff:v0.1.0"

		calicoNS = "calico-system"
		bffNS    = "tigera-ui-apis"
	)

	cert := &fakeCertPair{}
	install := &minimalInstallation

	var all []client.Object
	all = append(all, applicationlayer.WAFAdmissionWebhookComponents(install, webhookImage, cert)...)
	all = append(all, applicationlayer.WAFBFFComponents(install, bffImage, cert)...)
	all = append(all, applicationlayer.WAFFrontendModuleRegistration(install)...)

	// ---- total object count ----
	require.Len(t, all, 10, "expected 10 objects total across all three render functions")

	// ---- kind counts ----
	kindCount := map[string]int{}
	for _, o := range all {
		kindCount[o.GetObjectKind().GroupVersionKind().Kind]++
	}
	require.Equal(t, 1, kindCount["ValidatingWebhookConfiguration"], "expected 1 ValidatingWebhookConfiguration")
	require.Equal(t, 2, kindCount["Deployment"], "expected 2 Deployments (webhook + BFF)")
	require.Equal(t, 2, kindCount["Service"], "expected 2 Services (webhook + BFF)")
	require.Equal(t, 2, kindCount["ServiceAccount"], "expected 2 ServiceAccounts (webhook + BFF)")
	require.Equal(t, 1, kindCount["ClusterRole"], "expected 1 ClusterRole")
	require.Equal(t, 1, kindCount["ClusterRoleBinding"], "expected 1 ClusterRoleBinding")
	require.Equal(t, 1, kindCount["ConfigMap"], "expected 1 ConfigMap (frontend module)")

	// ---- no (Kind, Namespace, Name) collisions ----
	type objectKey struct{ kind, namespace, name string }
	seen := map[objectKey]bool{}
	for _, o := range all {
		k := objectKey{
			kind:      o.GetObjectKind().GroupVersionKind().Kind,
			namespace: o.GetNamespace(),
			name:      o.GetName(),
		}
		require.False(t, seen[k], "duplicate object: %s", fmt.Sprintf("%s/%s/%s", k.kind, k.namespace, k.name))
		seen[k] = true
	}

	// ---- namespace placement ----
	// Build a lookup from (Kind, Name) → Namespace for namespaced objects.
	type kindName struct{ kind, name string }
	nsMap := map[kindName]string{}
	for _, o := range all {
		kn := kindName{
			kind: o.GetObjectKind().GroupVersionKind().Kind,
			name: o.GetName(),
		}
		nsMap[kn] = o.GetNamespace()
	}

	// Webhook namespaced objects live in calico-system.
	require.Equal(t, calicoNS, nsMap[kindName{"Deployment", applicationlayer.WAFWebhookName}],
		"webhook Deployment must be in calico-system")
	require.Equal(t, calicoNS, nsMap[kindName{"Service", applicationlayer.WAFWebhookName}],
		"webhook Service must be in calico-system")
	require.Equal(t, calicoNS, nsMap[kindName{"ServiceAccount", applicationlayer.WAFWebhookName}],
		"webhook ServiceAccount must be in calico-system")

	// BFF namespaced objects live in tigera-ui-apis.
	require.Equal(t, bffNS, nsMap[kindName{"Deployment", applicationlayer.WAFBFFName}],
		"BFF Deployment must be in tigera-ui-apis")
	require.Equal(t, bffNS, nsMap[kindName{"Service", applicationlayer.WAFBFFName}],
		"BFF Service must be in tigera-ui-apis")
	require.Equal(t, bffNS, nsMap[kindName{"ServiceAccount", applicationlayer.WAFBFFName}],
		"BFF ServiceAccount must be in tigera-ui-apis")

	// Frontend ConfigMap lives in calico-system.
	require.Equal(t, calicoNS, nsMap[kindName{"ConfigMap", applicationlayer.WAFFrontendModuleConfigMapName}],
		"frontend module ConfigMap must be in calico-system")

	// Cluster-scoped objects must have no namespace.
	require.Empty(t, nsMap[kindName{"ClusterRole", applicationlayer.WAFWebhookName}],
		"ClusterRole must be cluster-scoped (no namespace)")
	require.Empty(t, nsMap[kindName{"ClusterRoleBinding", applicationlayer.WAFWebhookName}],
		"ClusterRoleBinding must be cluster-scoped (no namespace)")
}
