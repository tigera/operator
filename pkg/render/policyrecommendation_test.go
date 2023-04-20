// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"

	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Policy recommendation rendering tests", func() {
	var cfg *render.PolicyRecommendationConfiguration
	var bundle certificatemanagement.TrustedBundle

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		bundle = certificateManager.CreateTrustedBundle()

		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		cfg = &render.PolicyRecommendationConfiguration{
			ClusterDomain:   dns.DefaultClusterDomain,
			ESClusterConfig: relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1),
			TrustedBundle:   bundle,
			Installation:    &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			ManagedCluster:  notManagedCluster,
			UsePSP:          true,
		}
	})

	It("should render all resources for a default configuration", func() {
		cfg.Openshift = notOpenshift
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-policy-recommendation", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-policy-recommendation", ns: "tigera-policy-recommendation", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-policy-recommendation", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-policy-recommendation", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "allow-tigera.tigera-policy-recommendation", ns: "tigera-policy-recommendation", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "tigera-policy-recommendation", ns: "tigera-policy-recommendation", group: "apps", version: "v1", kind: "Deployment"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// Should mount ManagerTLSSecret for non-managed clusters
		prc := rtest.GetResource(resources, render.PolicyRecommendationName, render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(prc.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(prc.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
		))
		Expect(prc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(prc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))

		Expect(prc.Spec.Template.Spec.Volumes[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(prc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))

		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*prc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))

		clusterRole := rtest.GetResource(resources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys", "managedclusters"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
					"policyrecommendationscopes",
					"policyrecommendationscopes/status",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"globalnetworksets",
				},
				Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
		))

		clusterRoleBinding := rtest.GetResource(resources, render.PolicyRecommendationName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef).To(Equal(
			rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     render.PolicyRecommendationName,
			}))
		Expect(clusterRoleBinding.Subjects).To(ConsistOf(
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      render.PolicyRecommendationName,
				Namespace: render.PolicyRecommendationNamespace,
			}))
	})

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component := render.PolicyRecommendation(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
		}
	})

	It("should apply controlPlaneNodeSelector correctly", func() {
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
		}
		cfg.ESClusterConfig = &relasticsearch.ClusterConfig{}
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
	})

	It("should apply controlPlaneTolerations correctly", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		cfg.ESClusterConfig = &relasticsearch.ClusterConfig{}
		component := render.PolicyRecommendation(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "tigera-policy-recommendation", render.PolicyRecommendationNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
	})
})
