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

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Typha rendering tests", func() {
	const defaultClusterDomain = "svc.cluster.local"
	var installation *operatorv1.InstallationSpec
	var registry string
	var typhaNodeTLS *render.TyphaNodeTLS
	k8sServiceEp := k8sapi.ServiceEndpoint{}
	var cfg render.TyphaConfiguration
	BeforeEach(func() {
		registry = "test.registry.com/org"
		// Initialize a default installation to use. Each test can override this to its
		// desired configuration.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
			//Variant ProductVariant `json:"variant,omitempty"`
			Registry: registry,
			CNI: &operatorv1.CNISpec{
				Type: operatorv1.PluginCalico,
			},
		}
		typhaNodeTLS = &render.TyphaNodeTLS{
			CAConfigMap: &corev1.ConfigMap{},
			TyphaSecret: &corev1.Secret{},
			NodeSecret:  &corev1.Secret{},
		}
		typhaNodeTLS.TyphaSecret.Name = "typha-certs"
		typhaNodeTLS.TyphaSecret.Namespace = "tigera-operator"
		typhaNodeTLS.TyphaSecret.Kind = "Secret"
		typhaNodeTLS.TyphaSecret.APIVersion = "v1"

		cfg = render.TyphaConfiguration{
			K8sServiceEp:  k8sServiceEp,
			TLS:           typhaNodeTLS,
			Installation:  installation,
			ClusterDomain: defaultClusterDomain,
		}
	})

	It("should render all resources for a default configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// Typha resources
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1beta1", kind: "PodDisruptionBudget"},
			{name: "typha-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "calico-typha", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
		}

		component := render.Typha(&cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())
		d := dResource.(*appsv1.Deployment)
		tc := d.Spec.Template.Spec.Containers[0]
		Expect(tc.Name).To(Equal("calico-typha"))
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(tc.Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(tc.Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))
	})

	It("should include updates needed for migration of core components from kube-system namespace", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// Typha resources
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1beta1", kind: "PodDisruptionBudget"},
			{name: "typha-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "calico-typha", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
		}

		cfg.MigrateNamespaces = true
		component := render.Typha(&cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		d := dResource.(*appsv1.Deployment)
		paa := d.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution
		Expect(paa).To(ContainElement(corev1.PodAffinityTerm{
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "calico-typha"},
			},
			Namespaces:  []string{"kube-system"},
			TopologyKey: "kubernetes.io/hostname",
		}))
	})
	It("should set TIGERA_*_SECURITY_GROUP variables when AmazonCloudIntegration is defined", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// Typha resources
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1beta1", kind: "PodDisruptionBudget"},
			{name: "typha-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "calico-typha", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
		}

		cfg.AmazonCloudIntegration = &operatorv1.AmazonCloudIntegration{
			Spec: operatorv1.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIDs: []string{"sg-nodeid", "sg-masterid"},
				PodSecurityGroupID:   "sg-podsgid",
			},
		}
		component := render.Typha(&cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		deploymentResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())
		d := deploymentResource.(*appsv1.Deployment)
		tc := d.Spec.Template.Spec.Containers[0]
		Expect(tc.Name).To(Equal("calico-typha"))

		// Assert on expected env vars.
		expectedEnvVars := []corev1.EnvVar{
			{Name: "TIGERA_DEFAULT_SECURITY_GROUPS", Value: "sg-nodeid,sg-masterid"},
			{Name: "TIGERA_POD_SECURITY_GROUP", Value: "sg-podsgid"},
		}
		for _, v := range expectedEnvVars {
			Expect(tc.Env).To(ContainElement(v))
		}
	})

	It("should render resourcerequirements", func() {
		rr := &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		installation.ComponentResources = []operatorv1.ComponentResource{
			{
				ComponentName:        operatorv1.ComponentNameTypha,
				ResourceRequirements: rr,
			},
		}

		component := render.Typha(&cfg)
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)

		passed := false
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == "calico-typha" {
				Expect(container.Resources).To(Equal(*rr))
				passed = true
			}
		}
		Expect(passed).To(Equal(true))
	})

	It("should render Preferred typha affinity when set by user", func() {
		pfts := []corev1.PreferredSchedulingTerm{{
			Weight: 100,
			Preference: corev1.NodeSelectorTerm{
				MatchFields: []corev1.NodeSelectorRequirement{{
					Key:      "foo",
					Operator: "in",
					Values:   []string{"foo", "bar"},
				}},
			},
		}}
		installation.TyphaAffinity = &operatorv1.TyphaAffinity{
			NodeAffinity: &operatorv1.NodeAffinity{
				PreferredDuringSchedulingIgnoredDuringExecution: pfts,
			},
		}
		component := render.Typha(&cfg)
		resources, _ := component.Objects()
		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())
		d := dResource.(*appsv1.Deployment)
		na := d.Spec.Template.Spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution
		Expect(na).To(Equal(pfts))
	})

	It("should render Required typha affinity when set by user", func() {
		rst := &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{{
					Key:      "test",
					Operator: corev1.NodeSelectorOpIn,
					Values:   []string{"myTestNode"},
				}},
			}},
		}
		installation.TyphaAffinity = &operatorv1.TyphaAffinity{
			NodeAffinity: &operatorv1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: rst,
			},
		}
		component := render.Typha(&cfg)
		resources, _ := component.Objects()
		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())
		d := dResource.(*appsv1.Deployment)
		na := d.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
		Expect(na).To(Equal(rst))
	})

	It("should render all resources when certificate management is enabled", func() {
		installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: []byte("<ca>"), SignerName: "a.b/c"}
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// Typha resources
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-typha", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-typha", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1beta1", kind: "PodDisruptionBudget"},
			{name: "typha-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "calico-typha:csr-creator", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-typha", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
		}

		component := render.Typha(&cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		dep := rtest.GetResource(resources, common.TyphaDeploymentName, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())
		deploy, ok := dep.(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].Name).To(Equal(render.CSRInitContainerName))
		rtest.ExpectEnv(deploy.Spec.Template.Spec.InitContainers[0].Env, "SIGNER", "a.b/c")
	})
	It("should not enable prometheus metrics if TyphaMetricsPort is nil", func() {
		installation.Variant = operatorv1.TigeraSecureEnterprise
		installation.TyphaMetricsPort = nil
		component := render.Typha(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())

		notExpectedEnvVar := corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSENABLED"}
		d := dResource.(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(notExpectedEnvVar))
	})

	It("should set TYPHA_PROMETHEUSMETRICSPORT with a custom value if TyphaMetricsPort is set", func() {
		var typhaMetricsPort int32 = 1234
		installation.Variant = operatorv1.TigeraSecureEnterprise
		installation.TyphaMetricsPort = &typhaMetricsPort
		component := render.Typha(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())

		d := dResource.(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
			corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSPORT", Value: "1234"}))
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
			corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSENABLED", Value: "true"}))

		// Assert we set annotations properly.
		Expect(d.Spec.Template.Annotations["prometheus.io/scrape"]).To(Equal("true"))
		Expect(d.Spec.Template.Annotations["prometheus.io/port"]).To(Equal("1234"))
	})
})
