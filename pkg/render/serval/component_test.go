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

package serval_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/serval"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Serval rendering tests", func() {
	var cfg *serval.Configuration

	BeforeEach(func() {
		cfg = &serval.Configuration{
			Installation: &operatorv1.InstallationSpec{
				Variant: operatorv1.TigeraSecureEnterprise,
			},
			TrustedCertBundle: certificatemanagement.CreateTrustedBundle(nil),
			ServerKeyPair:     certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: serval.ServalKeyPairSecret}}, nil, ""),
			ClusterDomain:     dns.DefaultClusterDomain,
			Serval: &operatorv1.Serval{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec:       operatorv1.ServalSpec{Endpoint: "https://gateway.example.com:443"},
			},
		}
	})

	renderObjects := func() []client.Object {
		component := serval.Serval(cfg)
		Expect(component.ResolveImages(nil)).To(Succeed())
		toCreate, toDelete := component.Objects()
		Expect(toDelete).To(BeEmpty())
		return toCreate
	}

	It("should render the expected objects", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "serval", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "serval", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "serval", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "serval", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "serval", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: serval.ServalPolicyName, ns: "calico-system", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
		}

		toCreate := renderObjects()
		Expect(toCreate).To(HaveLen(len(expectedResources)))
		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(toCreate[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should grant the RBAC the gateway's auth stack needs", func() {
		toCreate := renderObjects()

		clusterRole := rtest.GetResource(toCreate, "serval", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get"},
			},
		))
	})

	It("should honor controlPlaneReplicas", func() {
		cfg.Installation.ControlPlaneReplicas = ptr.To(int32(3))
		toCreate := renderObjects()
		deployment := rtest.GetResource(toCreate, "serval", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(*deployment.Spec.Replicas).To(Equal(int32(3)))
		Expect(deployment.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("serval", []string{"calico-system"})))

		cfg.Installation.ControlPlaneReplicas = ptr.To(int32(1))
		toCreate = renderObjects()
		deployment = rtest.GetResource(toCreate, "serval", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(*deployment.Spec.Replicas).To(Equal(int32(1)))
		Expect(deployment.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should point the deployment at the in-cluster upstreams", func() {
		toCreate := renderObjects()

		deployment := rtest.GetResource(toCreate, "serval", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		container := deployment.Spec.Template.Spec.Containers[0]
		Expect(container.Command).To(Equal([]string{"/usr/bin/calico", "component", "serval"}))

		env := map[string]string{}
		for _, e := range container.Env {
			env[e.Name] = e.Value
		}
		Expect(env["SERVAL_TYPHA_ENDPOINT"]).To(Equal("calico-typha-noncluster-host.calico-system.svc.cluster.local:5473"))
		Expect(env["SERVAL_INGESTION_ENDPOINT"]).To(Equal("https://calico-fluent-bit-http-input.calico-system.svc.cluster.local:9880"))
		Expect(env["SERVAL_PORT"]).To(Equal("8449"))
	})

	It("should allow ingress to the gateway port and egress to typha and the log input", func() {
		toCreate := renderObjects()

		policy := rtest.GetResource(toCreate, serval.ServalPolicyName, "calico-system", "projectcalico.org", "v3", "NetworkPolicy").(*v3.NetworkPolicy)
		Expect(policy.Spec.Selector).To(Equal(networkpolicy.KubernetesAppSelector("serval")))

		Expect(policy.Spec.Ingress).To(HaveLen(1))
		Expect(policy.Spec.Ingress[0].Destination.Ports).To(Equal(networkpolicy.Ports(8449)))

		var egressSelectors []string
		for _, rule := range policy.Spec.Egress {
			egressSelectors = append(egressSelectors, rule.Destination.Selector)
		}
		Expect(egressSelectors).To(ContainElements(
			networkpolicy.KubernetesAppSelector("calico-typha-noncluster-host"),
			networkpolicy.KubernetesAppSelector("calico-fluent-bit"),
		))
	})
})
