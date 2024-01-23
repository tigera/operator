// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package dashboards

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/google/go-cmp/cmp"
	"github.com/tigera/operator/pkg/render/logstorage"
	batchv1 "k8s.io/api/batch/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

type resourceTestObj struct {
	name string
	ns   string
	typ  runtime.Object
	f    func(resource runtime.Object)
}

var _ = Describe("Dashboards rendering tests", func() {
	Context("zero-tenant rendering", func() {
		var installation *operatorv1.InstallationSpec
		var replicas int32
		var cfg *Config
		expectedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dashboards.json")
		expectedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dashboards_ocp.json")

		expectedResources := []resourceTestObj{
			{PolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
			{Name, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
			{Name, render.ElasticsearchNamespace, &batchv1.Job{}, nil},
			{Name, "", &rbacv1.ClusterRole{}, nil},
			{Name, "", &rbacv1.ClusterRoleBinding{}, nil},
			{Name, "", &policyv1beta1.PodSecurityPolicy{}, nil},
		}

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}

			replicas = 2
			bundle := getBundle(installation)

			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				TrustedBundle: bundle,
				UsePSP:        true,
				Namespace:     render.ElasticsearchNamespace,
				KibanaHost:    "tigera-secure-kb-http.tigera-kibana.svc",
				KibanaScheme:  "https",
				KibanaPort:    "5601",
			}
		})

		It("should render a Dashboards Jobs and all supporting resources", func() {
			component := Dashboards(cfg)
			createResources, _ := component.Objects()
			compareResources(createResources, expectedResources)
		})

		It("should render properly when PSP is not supported by the cluster", func() {
			cfg.UsePSP = false
			component := Dashboards(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			// Should not contain any PodSecurityPolicies
			for _, r := range resources {
				Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
				Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("ClusterRole"))
				Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("ClusterRoleBinding"))
			}
		})

		It("should apply controlPlaneNodeSelector correctly", func() {
			installation.ControlPlaneNodeSelector = map[string]string{"foo": "bar"}

			component := Dashboards(cfg)

			resources, _ := component.Objects()
			job, ok := rtest.GetResource(resources, Name, render.ElasticsearchNamespace, "batch", "v1", "Job").(*batchv1.Job)
			Expect(ok).To(BeTrue(), "Job not found")
			Expect(job.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
		})

		It("should apply controlPlaneTolerations correctly", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			installation.ControlPlaneTolerations = []corev1.Toleration{t}
			component := Dashboards(cfg)

			resources, _ := component.Objects()
			job, ok := rtest.GetResource(resources, Name, render.ElasticsearchNamespace, "batch", "v1", "Job").(*batchv1.Job)
			Expect(ok).To(BeTrue(), "Job not found")
			Expect(job.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
		})

		Context("allow-tigera rendering", func() {
			policyName := types.NamespacedName{Name: "allow-tigera.dashboards-installer", Namespace: "tigera-elasticsearch"}

			getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
				if scenario.ManagedCluster {
					return nil
				}

				return testutils.SelectPolicyByProvider(scenario, expectedPolicy, expectedPolicyForOpenshift)
			}

			DescribeTable("should render allow-tigera policy",
				func(scenario testutils.AllowTigeraScenario) {
					if scenario.Openshift {
						cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
					} else {
						cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
					}
					component := Dashboards(cfg)
					resources, _ := component.Objects()

					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(scenario)
					if !cmp.Equal(policy, expectedPolicy) {
						cmp.Diff(policy, expectedPolicy)
					}
					Expect(policy).To(Equal(expectedPolicy))
				},
				// Dashboards only renders in the presence of an LogStorage CR and absence of a ManagementClusterConnection CR, therefore
				// does not have a config option for managed clusters.
				Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
				Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			)
		})

		It("should not render when FIPS mode is enabled", func() {
			bundle := getBundle(installation)
			enabled := operatorv1.FIPSModeEnabled
			installation.FIPSMode = &enabled
			component := Dashboards(&Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				TrustedBundle: bundle,
				Namespace:     render.ElasticsearchNamespace,
				KibanaHost:    "tigera-secure-kb-http.tigera-kibana.tigera-kibana.svc",
				KibanaScheme:  "htpps",
				KibanaPort:    "5601",
			})

			resources, _ := component.Objects()
			_, ok := rtest.GetResource(resources, Name, render.ElasticsearchNamespace, "batch", "v1", "Job").(*batchv1.Job)
			Expect(ok).To(BeFalse(), "Jobs not found")
		})
	})

	Context("multi-tenant rendering", func() {
		var installation *operatorv1.InstallationSpec
		var tenant *operatorv1.Tenant
		var replicas int32
		var cfg *Config

		BeforeEach(func() {
			replicas = 2
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-tenant",
					Namespace: "test-tenant-ns",
				},
				Spec: operatorv1.TenantSpec{
					ID: "test-tenant",
					Elastic: &operatorv1.TenantElasticSpec{
						KibanaURL: "https://external-kibana:443",
						MutualTLS: true,
					},
				},
			}
			bundle := getBundle(installation)
			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				TrustedBundle: bundle,
				Namespace:     "tenant-test-tenant",
				Tenant:        tenant,
				KibanaHost:    "external-kibana",
				KibanaScheme:  "https",
				KibanaPort:    "443",
			}
		})

		It("should support an external kibana endpoint", func() {
			cfg.ExternalKibanaClientSecret = &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      logstorage.ExternalCertsSecret,
					Namespace: cfg.Namespace,
				},
				Data: map[string][]byte{
					"client.crt": {1, 2, 3},
					"client.key": {4, 5, 6},
				},
			}
			component := Dashboards(cfg)
			createResources, _ := component.Objects()
			d, ok := rtest.GetResource(createResources, Name, cfg.Namespace, "batch", "v1", "Job").(*batchv1.Job)
			Expect(ok).To(BeTrue(), "Job not found")

			// The deployment should have the hash annotation set, as well as a volume and volume mount for the client secret.
			Expect(d.Spec.Template.Annotations["hash.operator.tigera.io/kibana-client-secret"]).To(Equal("ae1a6776a81bf1fc0ee4aac936a90bd61a07aea7"))
			Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(corev1.Volume{
				Name: logstorage.ExternalCertsVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: logstorage.ExternalCertsSecret,
					},
				},
			}))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
				Name:      logstorage.ExternalCertsVolumeName,
				MountPath: "/certs/kibana/mtls",
				ReadOnly:  true,
			}))

			// Should expect mTLS env vars set.
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: "KIBANA_CLIENT_KEY", Value: "/certs/kibana/mtls/client.key",
			}))
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: "KIBANA_CLIENT_CERT", Value: "/certs/kibana/mtls/client.crt",
			}))
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: "KIBANA_MTLS_ENABLED", Value: "true",
			}))
		})

		It("should render resources in the tenant namespace", func() {
			component := Dashboards(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			job := rtest.GetResource(resources, Name, cfg.Namespace, batchv1.GroupName, "v1", "Job").(*batchv1.Job)
			Expect(job).NotTo(BeNil())
			sa := rtest.GetResource(resources, Name, cfg.Namespace, corev1.GroupName, "v1", "ServiceAccount").(*corev1.ServiceAccount)
			Expect(sa).NotTo(BeNil())
			netPol := rtest.GetResource(resources, fmt.Sprintf("allow-tigera.%s", Name), cfg.Namespace, "projectcalico.org", "v3", "NetworkPolicy").(*v3.NetworkPolicy)
			Expect(netPol).NotTo(BeNil())
		})

		It("should render multi-tenant environment variables", func() {
			component := Dashboards(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			job := rtest.GetResource(resources, Name, cfg.Namespace, batchv1.GroupName, "v1", "Job").(*batchv1.Job)
			envs := job.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_SPACE_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_SCHEME", Value: "https"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_HOST", Value: "external-kibana"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_PORT", Value: "443"}))
		})

		It("should override resource request with the value from TenantSpec's dashboardsJob when available", func() {
			dashboardsJobResources := corev1.ResourceRequirements{
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
			dashboardJob := &operatorv1.DashboardsJob{
				Spec: &operatorv1.DashboardsJobSpec{
					Template: &operatorv1.DashboardsJobPodTemplateSpec{
						Spec: &operatorv1.DashboardsJobPodSpec{
							Containers: []operatorv1.DashboardsJobContainer{{
								Name:      Name,
								Resources: &dashboardsJobResources,
							}},
						},
					},
				},
			}
			cfg.Tenant.Spec.DashboardsJob = dashboardJob
			component := Dashboards(cfg)

			resources, _ := component.Objects()
			job := rtest.GetResource(resources, Name, cfg.Namespace, batchv1.GroupName, "v1", "Job").(*batchv1.Job)
			Expect(job.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(job.Spec.Template.Spec.Containers[0].Name).To(Equal(Name))
			Expect(job.Spec.Template.Spec.Containers[0].Resources).To(Equal(dashboardsJobResources))
		})

	})

	Context("single-tenant with external elastic rendering", func() {
		var installation *operatorv1.InstallationSpec
		var tenant *operatorv1.Tenant
		var replicas int32
		var cfg *Config

		BeforeEach(func() {
			replicas = 2
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-tenant",
				},
				Spec: operatorv1.TenantSpec{
					ID: "test-tenant",
				},
			}
			bundle := getBundle(installation)
			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				TrustedBundle: bundle,
				Namespace:     render.ElasticsearchNamespace,
				Tenant:        tenant,
				KibanaHost:    "external-kibana",
				KibanaScheme:  "https",
				KibanaPort:    "443",
			}
		})

		It("should support an external kibana endpoint", func() {
			cfg.ExternalKibanaClientSecret = &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      logstorage.ExternalCertsSecret,
					Namespace: render.ElasticsearchNamespace,
				},
				Data: map[string][]byte{
					"client.crt": {1, 2, 3},
					"client.key": {4, 5, 6},
				},
			}
			component := Dashboards(cfg)
			createResources, _ := component.Objects()
			d, ok := rtest.GetResource(createResources, Name, render.ElasticsearchNamespace, "batch", "v1", "Job").(*batchv1.Job)
			Expect(ok).To(BeTrue(), "Job not found")

			// The deployment should have the hash annotation set, as well as a volume and volume mount for the client secret.
			Expect(d.Spec.Template.Annotations["hash.operator.tigera.io/kibana-client-secret"]).To(Equal("ae1a6776a81bf1fc0ee4aac936a90bd61a07aea7"))
			Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(corev1.Volume{
				Name: logstorage.ExternalCertsVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: logstorage.ExternalCertsSecret,
					},
				},
			}))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
				Name:      logstorage.ExternalCertsVolumeName,
				MountPath: "/certs/kibana/mtls",
				ReadOnly:  true,
			}))

			// Should expect mTLS env vars set.
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: "KIBANA_CLIENT_KEY", Value: "/certs/kibana/mtls/client.key",
			}))
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: "KIBANA_CLIENT_CERT", Value: "/certs/kibana/mtls/client.crt",
			}))
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name: "KIBANA_MTLS_ENABLED", Value: "true",
			}))
		})

		It("should render resources in the elasticsearch namespace", func() {
			component := Dashboards(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			job := rtest.GetResource(resources, Name, render.ElasticsearchNamespace, batchv1.GroupName, "v1", "Job").(*batchv1.Job)
			Expect(job).NotTo(BeNil())
			sa := rtest.GetResource(resources, Name, render.ElasticsearchNamespace, corev1.GroupName, "v1", "ServiceAccount").(*corev1.ServiceAccount)
			Expect(sa).NotTo(BeNil())
			netPol := rtest.GetResource(resources, fmt.Sprintf("allow-tigera.%s", Name), render.ElasticsearchNamespace, "projectcalico.org", "v3", "NetworkPolicy").(*v3.NetworkPolicy)
			Expect(netPol).NotTo(BeNil())
		})

		It("should render single-tenant environment variables", func() {
			component := Dashboards(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, Name, cfg.Namespace, batchv1.GroupName, "v1", "Job").(*batchv1.Job)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_SPACE_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_SCHEME", Value: "https"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_HOST", Value: "external-kibana"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_PORT", Value: "443"}))
		})
	})

	Context("single-tenant with internal elastic rendering", func() {
		var installation *operatorv1.InstallationSpec
		var tenant *operatorv1.Tenant
		var replicas int32
		var cfg *Config

		BeforeEach(func() {
			replicas = 2
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-tenant",
				},
				Spec: operatorv1.TenantSpec{
					ID: "test-tenant",
				},
			}
			bundle := getBundle(installation)
			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				TrustedBundle: bundle,
				Namespace:     render.ElasticsearchNamespace,
				Tenant:        tenant,
				KibanaHost:    "tigera-secure-kb-http.tigera-kibana.svc",
				KibanaScheme:  "https",
				KibanaPort:    "5601",
			}
		})

		It("should render resources in the elasticsearch namespace", func() {
			component := Dashboards(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			job := rtest.GetResource(resources, Name, render.ElasticsearchNamespace, batchv1.GroupName, "v1", "Job").(*batchv1.Job)
			Expect(job).NotTo(BeNil())
			sa := rtest.GetResource(resources, Name, render.ElasticsearchNamespace, corev1.GroupName, "v1", "ServiceAccount").(*corev1.ServiceAccount)
			Expect(sa).NotTo(BeNil())
			netPol := rtest.GetResource(resources, fmt.Sprintf("allow-tigera.%s", Name), render.ElasticsearchNamespace, "projectcalico.org", "v3", "NetworkPolicy").(*v3.NetworkPolicy)
			Expect(netPol).NotTo(BeNil())
		})

		It("should render single-tenant environment variables", func() {
			component := Dashboards(cfg)
			Expect(component).NotTo(BeNil())
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, Name, cfg.Namespace, batchv1.GroupName, "v1", "Job").(*batchv1.Job)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_SPACE_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_SCHEME", Value: "https"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_HOST", Value: "tigera-secure-kb-http.tigera-kibana.svc"}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "KIBANA_PORT", Value: "5601"}))
		})
	})
})

func getBundle(installation *operatorv1.InstallationSpec) certificatemanagement.TrustedBundle {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	trustedBundle := certificateManager.CreateTrustedBundle()
	Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

	return trustedBundle
}

func compareResources(resources []client.Object, expectedResources []resourceTestObj) {
	Expect(resources).To(HaveLen(len(expectedResources)))
	for i, expectedResource := range expectedResources {
		resource := resources[i]
		actualName := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
		actualNS := resource.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()

		Expect(actualName).To(Equal(expectedResource.name), fmt.Sprintf("Rendered resource has wrong name (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(actualNS).To(Equal(expectedResource.ns), fmt.Sprintf("Rendered resource has wrong namespace (position %d, name %s, namespace %s)", i, actualName, actualNS))
		Expect(resource).Should(BeAssignableToTypeOf(expectedResource.typ))
		if expectedResource.f != nil {
			expectedResource.f(resource)
		}
	}

	// Check job
	job := rtest.GetResource(resources, Name, render.ElasticsearchNamespace, "batch", "v1", "Job").(*batchv1.Job)
	ExpectWithOffset(1, job).NotTo(BeNil())

	// Check containers
	expected := expectedContainers()
	actual := job.Spec.Template.Spec.Containers
	ExpectWithOffset(1, len(actual)).To(Equal(len(expected)))
	ExpectWithOffset(1, actual[0].Env).To(ConsistOf(expected[0].Env))
	ExpectWithOffset(1, actual[0].EnvFrom).To(ConsistOf(expected[0].EnvFrom))
	ExpectWithOffset(1, actual[0].VolumeMounts).To(ConsistOf(expected[0].VolumeMounts))
	ExpectWithOffset(1, actual[0].ReadinessProbe).To(Equal(expected[0].ReadinessProbe))
	ExpectWithOffset(1, actual[0].LivenessProbe).To(Equal(expected[0].LivenessProbe))
	ExpectWithOffset(1, actual[0].SecurityContext).To(Equal(expected[0].SecurityContext))
	ExpectWithOffset(1, actual[0].Name).To(Equal(expected[0].Name))
	ExpectWithOffset(1, actual[0].Resources).To(Equal(expected[0].Resources))
	ExpectWithOffset(1, actual[0].Image).To(Equal(expected[0].Image))
	ExpectWithOffset(1, actual[0].Ports).To(Equal(expected[0].Ports))
	ExpectWithOffset(1, actual).To(ConsistOf(expected))

	// Check volumeMounts
	ExpectWithOffset(1, job.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVolumes()))

	// Check annotations
	ExpectWithOffset(1, job.Spec.Template.Annotations).To(HaveKeyWithValue("tigera-operator.hash.operator.tigera.io/tigera-ca-private", Not(BeEmpty())))
	ExpectWithOffset(1, job.Spec.Template.Annotations).To(HaveKeyWithValue("hash.operator.tigera.io/elasticsearch-secrets", Not(BeEmpty())))

	// Check permissions
	clusterRole := rtest.GetResource(resources, Name, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
	Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{

		{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			ResourceNames: []string{Name},
			Verbs:         []string{"use"},
		},
	}))
	clusterRoleBinding := rtest.GetResource(resources, Name, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
	Expect(clusterRoleBinding.RoleRef.Name).To(Equal(Name))
	Expect(clusterRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      Name,
			Namespace: render.ElasticsearchNamespace,
		},
	}))
}

func expectedVolumes() []corev1.Volume {
	return []corev1.Volume{
		{
			Name: "tigera-ca-bundle",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ca-bundle",
					},
				},
			},
		},
	}
}

func expectedContainers() []corev1.Container {
	return []corev1.Container{
		{
			Name:            Name,
			ImagePullPolicy: render.ImagePullPolicy(),
			SecurityContext: &corev1.SecurityContext{
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				AllowPrivilegeEscalation: ptr.BoolToPtr(false),
				Privileged:               ptr.BoolToPtr(false),
				RunAsNonRoot:             ptr.BoolToPtr(true),
				RunAsGroup:               ptr.Int64ToPtr(10001),
				RunAsUser:                ptr.Int64ToPtr(10001),
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Env: []corev1.EnvVar{
				{
					Name:  "KIBANA_HOST",
					Value: "tigera-secure-kb-http.tigera-kibana.svc",
				},
				{
					Name:  "KIBANA_PORT",
					Value: "5601",
				},
				{
					Name:  "KIBANA_SCHEME",
					Value: "https",
				},
				{
					Name:  "START_XPACK_TRIAL",
					Value: "false",
				},
				{
					Name:  "USER",
					Value: "",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: ElasticCredentialsSecret,
							},
							Key: "username",
						},
					},
				},
				{
					Name:  "PASSWORD",
					Value: "",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: ElasticCredentialsSecret,
							},
							Key: "password",
						},
					},
				},
				{
					Name:  "KB_CA_CERT",
					Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt",
				},
				{
					Name:  "FIPS_MODE_ENABLED",
					Value: "false",
				},
				{
					Name:  "ELASTIC_USER",
					Value: "",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: ElasticCredentialsSecret,
							},
							Key: "username",
						},
					},
				},
				{
					Name:  "ELASTIC_PASSWORD",
					Value: "",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: ElasticCredentialsSecret,
							},
							Key: "password",
						},
					},
				}},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "tigera-ca-bundle",
					MountPath: "/etc/pki/tls/certs",
					ReadOnly:  true,
				},
			},
		},
	}
}
