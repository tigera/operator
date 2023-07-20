// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Typha rendering tests", func() {
	const defaultClusterDomain = "svc.cluster.local"
	var installation *operatorv1.InstallationSpec
	var registry string
	var typhaNodeTLS *render.TyphaNodeTLS
	var cli client.Client
	k8sServiceEp := k8sapi.ServiceEndpoint{}
	var cfg render.TyphaConfiguration
	BeforeEach(func() {
		registry = "test.registry.com/org"
		// Initialize a default installation to use. Each test can override this to its
		// desired configuration.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
			// Variant ProductVariant `json:"variant,omitempty"`
			Registry: registry,
			CNI: &operatorv1.CNISpec{
				Type: operatorv1.PluginCalico,
			},
		}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		typhaNodeTLS = getTyphaNodeTLS(cli, certificateManager)
		cfg = render.TyphaConfiguration{
			K8sServiceEp:    k8sServiceEp,
			TLS:             typhaNodeTLS,
			Installation:    installation,
			ClusterDomain:   defaultClusterDomain,
			FelixHealthPort: 9099,
			UsePSP:          true,
		}
	})

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component := render.Typha(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
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
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1", kind: "PodDisruptionBudget"},
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
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))

		tc := d.Spec.Template.Spec.Containers[0]
		Expect(tc.Name).To(Equal("calico-typha"))
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(tc.Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(tc.Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		Expect(*tc.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*tc.SecurityContext.Privileged).To(BeFalse())
		Expect(*tc.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*tc.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*tc.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(tc.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(tc.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
	})

	It("should render the correct env and/or images when FIPS mode is enabled (OSS)", func() {
		fipsEnabled := operatorv1.FIPSModeEnabled
		cfg.Installation.FIPSMode = &fipsEnabled
		cfg.Installation.Variant = operatorv1.Calico
		component := render.Typha(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())

		d := dResource.(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))

		tc := d.Spec.Template.Spec.Containers[0]
		Expect(tc.Image).To(ContainSubstring("-fips"))
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
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1", kind: "PodDisruptionBudget"},
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "calico-typha", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
		}

		cfg.MigrateNamespaces = true
		component := render.Typha(&cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())

		// The Deployment should have the correct configuration.
		d := dResource.(*appsv1.Deployment)
		paa := d.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution
		Expect(paa).To(ContainElement(corev1.PodAffinityTerm{
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "calico-typha"},
			},
			Namespaces:  []string{"kube-system"},
			TopologyKey: "kubernetes.io/hostname",
		}))

		Expect(*d.Spec.Template.Spec.TerminationGracePeriodSeconds).To(Equal(int64(300 /* our default*/)))
		Expect(*d.Spec.ProgressDeadlineSeconds).To(Equal(int32(600 /*k8s default*/)))
		Expect(d.Spec.Strategy).To(Equal(appsv1.DeploymentStrategy{
			Type: appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{
				MaxSurge:       ptr.IntOrStrPtr("100%"),
				MaxUnavailable: ptr.IntOrStrPtr("1"),
			},
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
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1", kind: "PodDisruptionBudget"},
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

	It("should properly configure a non-default typha health port", func() {
		// Set a non-default health port.
		cfg.FelixHealthPort = 7878

		component := render.Typha(&cfg)
		resources, _ := component.Objects()

		depResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(depResource).ToNot(BeNil())
		deployment := depResource.(*appsv1.Deployment)

		passed := false
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == "calico-typha" {
				Expect(container.LivenessProbe.HTTPGet.Port.IntVal).To(Equal(int32(7877)))
				for _, env := range container.Env {
					if env.Name == "TYPHA_HEALTHPORT" {
						Expect(env.Value).To(Equal("7877"))

						// Found both expected fields, and they match.
						passed = true
						break
					}
				}
				break
			}
		}
		Expect(passed).To(Equal(true), "Typha healthport configuration missing an expected field")
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

	It("should render zone affinity by default", func() {
		expected := corev1.WeightedPodAffinityTerm{
			Weight: 1,
			PodAffinityTerm: corev1.PodAffinityTerm{
				LabelSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "k8s-app",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"calico-typha"},
						},
					},
				},
				TopologyKey: "topology.kubernetes.io/zone",
			},
		}
		component := render.Typha(&cfg)
		resources, _ := component.Objects()
		dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
		Expect(dResource).ToNot(BeNil())
		d := dResource.(*appsv1.Deployment)
		paa := d.Spec.Template.Spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution
		Expect(paa).To(HaveLen(1))
		Expect(paa[0]).To(Equal(expected))
	})

	It("should render all resources when certificate management is enabled", func() {
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cfg.TLS.TyphaSecret.GetCertificatePEM()}
		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		cfg.TLS = getTyphaNodeTLS(cli, certificateManager)
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
			{name: "calico-typha", ns: "calico-system", group: "policy", version: "v1", kind: "PodDisruptionBudget"},
			{name: "calico-typha", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "calico-typha", ns: "calico-system", group: "apps", version: "v1", kind: "Deployment"},
		}

		component := render.Typha(&cfg)
		resources, _ := component.Objects()

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dep := rtest.GetResource(resources, common.TyphaDeploymentName, common.CalicoNamespace, "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())
		deploy, ok := dep.(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", render.TyphaTLSSecretName)))
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

	Context("With typha deployment overrides", func() {
		rr1 := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}
		rr2 := corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		It("should handle typhaDeployment overrides", func() {
			var minReadySeconds int32 = 20

			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			termGracePeriod := int64(700)

			installation.TyphaDeployment = &operatorv1.TyphaDeployment{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.TyphaDeploymentSpec{
					MinReadySeconds: &minReadySeconds,
					Strategy: &operatorv1.TyphaDeploymentStrategy{
						RollingUpdate: &appsv1.RollingUpdateDeployment{
							MaxSurge:       ptr.IntOrStrPtr("2"),
							MaxUnavailable: ptr.IntOrStrPtr("0"),
						},
					},
					Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.TyphaDeploymentPodSpec{
							TerminationGracePeriodSeconds: &termGracePeriod,
							Containers: []operatorv1.TyphaDeploymentContainer{
								{
									Name:      "calico-typha",
									Resources: &rr1,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
								{
									MaxSkew: 1,
								},
							},
							Affinity:    affinity,
							Tolerations: []corev1.Toleration{toleration},
						},
					},
				},
			}

			component := render.Typha(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
			Expect(dResource).ToNot(BeNil())

			d := dResource.(*appsv1.Deployment)

			Expect(d.Labels).To(HaveLen(1))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(1))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))
			Expect(d.Spec.Strategy).To(Equal(appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       ptr.IntOrStrPtr("2"),
					MaxUnavailable: ptr.IntOrStrPtr("0"),
				},
			}))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-typha". But the deployment object
			// produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(1))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 3 template-level annotations
			// - 2 added by the default typha render
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(3))
			Expect(d.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/tigera-ca-private"))
			Expect(d.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/typha-certs"))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-typha"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.TopologySpreadConstraints).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.TopologySpreadConstraints[0].MaxSkew).To(Equal(int32(1)))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))

			Expect(*d.Spec.Template.Spec.TerminationGracePeriodSeconds).To(Equal(termGracePeriod))
			expProgDeadline := int32(700 * 120 / 100)
			Expect(*d.Spec.ProgressDeadlineSeconds).To(Equal(expProgDeadline))
			found := false
			for _, ev := range d.Spec.Template.Spec.Containers[0].Env {
				if ev.Name == "TYPHA_SHUTDOWNTIMEOUTSECS" {
					Expect(found).To(BeFalse(), "Typha deployment had duplicate TYPHA_SHUTDOWNTIMEOUTSECS env var")
					Expect(ev.Value).To(Equal("700"))
					found = true
				}
			}
			Expect(found).To(BeTrue(), "Typha deployment was missing TYPHA_SHUTDOWNTIMEOUTSECS env var")
		})

		It("should override ComponentResources", func() {
			installation.ComponentResources = []operatorv1.ComponentResource{
				{
					ComponentName:        operatorv1.ComponentNameTypha,
					ResourceRequirements: &rr1,
				},
			}

			installation.TyphaDeployment = &operatorv1.TyphaDeployment{
				Spec: &operatorv1.TyphaDeploymentSpec{
					Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
						Spec: &operatorv1.TyphaDeploymentPodSpec{
							Containers: []operatorv1.TyphaDeploymentContainer{
								{
									Name:      "calico-typha",
									Resources: &rr2,
								},
							},
						},
					},
				},
			}

			component := render.Typha(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
			Expect(dResource).ToNot(BeNil())

			d := dResource.(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-typha"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr2))
		})

		It("should override ControlPlaneNodeSelector when specified", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

			installation.TyphaDeployment = &operatorv1.TyphaDeployment{
				Spec: &operatorv1.TyphaDeploymentSpec{
					Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
						Spec: &operatorv1.TyphaDeploymentPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
						},
					},
				},
			}
			component := render.Typha(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
			Expect(dResource).ToNot(BeNil())

			d := dResource.(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))
		})

		It("should override ControlPlaneTolerations when specified", func() {
			cfg.Installation.ControlPlaneTolerations = rmeta.TolerateControlPlane

			tol := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}

			installation.TyphaDeployment = &operatorv1.TyphaDeployment{
				Spec: &operatorv1.TyphaDeploymentSpec{
					Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
						Spec: &operatorv1.TyphaDeploymentPodSpec{
							Tolerations: []corev1.Toleration{tol},
						},
					},
				},
			}
			component := render.Typha(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			dResource := rtest.GetResource(resources, "calico-typha", "calico-system", "apps", "v1", "Deployment")
			Expect(dResource).ToNot(BeNil())

			d := dResource.(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(tol))
		})
	})
})
