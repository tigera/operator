// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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

package linseed

import (
	"context"
	"fmt"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	"github.com/tigera/operator/pkg/render/common/podaffinity"
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

var _ = Describe("Linseed rendering tests", func() {
	Context("Linseed deployment", func() {
		var installation *operatorv1.InstallationSpec
		var replicas int32
		var cfg *Config
		clusterDomain := "cluster.local"
		expectedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/linseed.json")
		expectedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/linseed_ocp.json")
		esClusterConfig := relasticsearch.NewClusterConfig("", 1, 1, 1)

		expectedResources := []resourceTestObj{
			{PolicyName, render.ElasticsearchNamespace, &v3.NetworkPolicy{}, nil},
			{render.LinseedServiceName, render.ElasticsearchNamespace, &corev1.Service{}, nil},
			{ClusterRoleName, "", &rbacv1.ClusterRole{}, nil},
			{ClusterRoleName, "", &rbacv1.ClusterRoleBinding{}, nil},
			{ServiceAccountName, render.ElasticsearchNamespace, &corev1.ServiceAccount{}, nil},
			{DeploymentName, render.ElasticsearchNamespace, &appsv1.Deployment{}, nil},
			{"tigera-linseed", "", &policyv1beta1.PodSecurityPolicy{}, nil},
		}

		BeforeEach(func() {
			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}
			replicas = 2
			kp, bundle := getTLS(installation)
			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				KeyPair:         kp,
				TrustedBundle:   bundle,
				ClusterDomain:   clusterDomain,
				UsePSP:          true,
				ESClusterConfig: esClusterConfig,
			}
		})

		It("should render an Linseed deployment and all supporting resources", func() {
			component := Linseed(cfg)

			createResources, _ := component.Objects()
			compareResources(createResources, expectedResources, false)
		})

		It("should render properly when PSP is not supported by the cluster", func() {
			cfg.UsePSP = false
			component := Linseed(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			// Should not contain any PodSecurityPolicies
			for _, r := range resources {
				Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
			}
		})

		It("should render an Linseed deployment and all supporting resources when CertificateManagement is enabled", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret("", "", "", nil)
			Expect(err).NotTo(HaveOccurred())
			installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: secret.Data[corev1.TLSCertKey]}
			kp, bundle := getTLS(installation)
			cfg = &Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				KeyPair:         kp,
				TrustedBundle:   bundle,
				ClusterDomain:   clusterDomain,
				UsePSP:          true,
				ESClusterConfig: esClusterConfig,
			}

			component := Linseed(cfg)

			createResources, _ := component.Objects()
			compareResources(createResources, expectedResources, true)
		})

		It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
			var replicas int32 = 1
			installation.ControlPlaneReplicas = &replicas

			component := Linseed(cfg)

			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
		})

		It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
			var replicas int32 = 2
			installation.ControlPlaneReplicas = &replicas

			component := Linseed(cfg)

			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
			Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity(DeploymentName, render.ElasticsearchNamespace)))
		})

		It("should apply controlPlaneNodeSelector correctly", func() {
			installation.ControlPlaneNodeSelector = map[string]string{"foo": "bar"}

			component := Linseed(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
		})

		It("should apply controlPlaneTolerations correctly", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			installation.ControlPlaneTolerations = []corev1.Toleration{t}
			component := Linseed(cfg)

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
		})

		Context("allow-tigera rendering", func() {
			policyName := types.NamespacedName{Name: "allow-tigera.linseed-access", Namespace: "tigera-elasticsearch"}

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
					component := Linseed(cfg)
					resources, _ := component.Objects()

					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(scenario)
					Expect(policy).To(Equal(expectedPolicy))
				},
				// Linseed only renders in the presence of an LogStorage CR and absence of a ManagementClusterConnection CR, therefore
				// does not have a config option for managed clusters.
				Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
				Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			)
		})
		It("should set the right env when FIPS mode is enabled", func() {
			kp, bundle := getTLS(installation)
			enabled := operatorv1.FIPSModeEnabled
			installation.FIPSMode = &enabled
			component := Linseed(&Config{
				Installation: installation,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				KeyPair:         kp,
				TrustedBundle:   bundle,
				ClusterDomain:   clusterDomain,
				ESClusterConfig: esClusterConfig,
			})

			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "LINSEED_FIPS_MODE_ENABLED", Value: "true"}))
		})
	})
})

func getTLS(installation *operatorv1.InstallationSpec) (certificatemanagement.KeyPairInterface, certificatemanagement.TrustedBundle) {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	certificateManager, err := certificatemanager.Create(cli, installation, dns.DefaultClusterDomain)
	Expect(err).NotTo(HaveOccurred())
	esDNSNames := dns.GetServiceDNSNames(render.TigeraLinseedSecret, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	gwKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraLinseedSecret, render.ElasticsearchNamespace, esDNSNames)
	Expect(err).NotTo(HaveOccurred())
	trustedBundle := certificateManager.CreateTrustedBundle(gwKeyPair)
	Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
	return gwKeyPair, trustedBundle
}

func compareResources(resources []client.Object, expectedResources []resourceTestObj, useCSR bool) {
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

	// Check deployment
	deployment := rtest.GetResource(resources, DeploymentName, render.ElasticsearchNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
	ExpectWithOffset(1, deployment).NotTo(BeNil())
	ExpectWithOffset(1, deployment.Spec.Strategy.Type).To(Equal(appsv1.RollingUpdateDeploymentStrategyType))
	ExpectWithOffset(1, deployment.Spec.Strategy.RollingUpdate.MaxSurge).To(Equal(ptr.IntOrStrPtr("100%")))
	ExpectWithOffset(1, deployment.Spec.Strategy.RollingUpdate.MaxUnavailable).To(Equal(ptr.IntOrStrPtr("0")))

	// Check containers
	expected := expectedContainers()
	actual := deployment.Spec.Template.Spec.Containers
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

	// Check init containers
	if useCSR {
		ExpectWithOffset(1, len(deployment.Spec.Template.Spec.InitContainers)).To(Equal(1))
		ExpectWithOffset(1, deployment.Spec.Template.Spec.InitContainers[0].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", render.TigeraLinseedSecret)))
	}

	// Check volumeMounts
	ExpectWithOffset(1, deployment.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVolumes(useCSR)))

	// Check annotations
	if !useCSR {
		ExpectWithOffset(1, deployment.Spec.Template.Annotations).To(HaveKeyWithValue("hash.operator.tigera.io/tigera-secure-linseed-cert", Not(BeEmpty())))
	}
	ExpectWithOffset(1, deployment.Spec.Template.Annotations).To(HaveKeyWithValue("hash.operator.tigera.io/tigera-ca-private", Not(BeEmpty())))

	// Check permissions
	clusterRole := rtest.GetResource(resources, ClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
	Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
		{
			APIGroups:     []string{"authorization.k8s.io"},
			Resources:     []string{"subjectaccessreviews"},
			ResourceNames: []string{},
			Verbs:         []string{"create"},
		},
		{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			ResourceNames: []string{"tigera-linseed"},
			Verbs:         []string{"use"},
		},
		{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"managedclusters"},
			Verbs:     []string{"list", "watch"},
		},
	}))
	clusterRoleBinding := rtest.GetResource(resources, ClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
	Expect(clusterRoleBinding.RoleRef.Name).To(Equal(ClusterRoleName))
	Expect(clusterRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      ServiceAccountName,
			Namespace: render.ElasticsearchNamespace,
		},
	}))

	// Check service
	service := rtest.GetResource(resources, render.LinseedServiceName, render.ElasticsearchNamespace, "", "v1", "Service").(*corev1.Service)
	Expect(service.Spec.Ports).To(ConsistOf([]corev1.ServicePort{
		{
			Name:       PortName,
			Port:       443,
			TargetPort: intstr.FromInt(TargetPort),
			Protocol:   corev1.ProtocolTCP,
		},
	}))
}

func expectedVolumes(useCSR bool) []corev1.Volume {
	var volumes []corev1.Volume
	if useCSR {
		volumes = append(volumes, corev1.Volume{
			Name: render.TigeraLinseedSecret,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	} else {
		volumes = append(volumes, corev1.Volume{
			Name: render.TigeraLinseedSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  render.TigeraLinseedSecret,
					DefaultMode: ptr.Int32ToPtr(420),
				},
			},
		})
	}

	volumes = append(volumes, corev1.Volume{
		Name: "tigera-ca-bundle",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "tigera-ca-bundle",
				},
			},
		},
	})
	return volumes
}

func expectedContainers() []corev1.Container {
	return []corev1.Container{
		{
			Name:            DeploymentName,
			ImagePullPolicy: corev1.PullIfNotPresent,
			SecurityContext: &corev1.SecurityContext{
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				AllowPrivilegeEscalation: ptr.BoolToPtr(false),
				Privileged:               ptr.BoolToPtr(false),
				RunAsNonRoot:             ptr.BoolToPtr(true),
				RunAsGroup:               ptr.Int64ToPtr(10001),
				RunAsUser:                ptr.Int64ToPtr(10001),
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"/linseed", "-ready"},
					},
				},
				InitialDelaySeconds: 10,
				PeriodSeconds:       5,
			},
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"/linseed", "-live"},
					},
				},
				InitialDelaySeconds: 10,
				PeriodSeconds:       5,
			},
			Env: []corev1.EnvVar{
				{
					Name:  "LINSEED_LOG_LEVEL",
					Value: "INFO",
				},
				{
					Name:  "LINSEED_FIPS_MODE_ENABLED",
					Value: "false",
				},
				{
					Name:  "LINSEED_HTTPS_CERT",
					Value: "/tigera-secure-linseed-cert/tls.crt",
				},
				{
					Name:  "LINSEED_HTTPS_KEY",
					Value: "/tigera-secure-linseed-cert/tls.key",
				},
				{
					Name:  "LINSEED_CA_CERT",
					Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt",
				},
				{
					Name:  "ELASTIC_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_FLOWS_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_DNS_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_AUDIT_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_BGP_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_WAF_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_L7_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_RUNTIME_INDEX_REPLICAS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_FLOWS_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_DNS_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_AUDIT_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_BGP_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_WAF_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_L7_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_RUNTIME_INDEX_SHARDS",
					Value: "1",
				},
				{
					Name:  "ELASTIC_SCHEME",
					Value: "https",
				},
				{
					Name:  "ELASTIC_HOST",
					Value: "tigera-secure-es-http.tigera-elasticsearch.svc",
				},
				{
					Name:  "ELASTIC_PORT",
					Value: "9200",
				},
				{
					Name: "ELASTIC_USERNAME",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tigera-ee-linseed-elasticsearch-user-secret",
							},
							Key: "username",
						},
					},
				},
				{
					Name: "ELASTIC_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tigera-ee-linseed-elasticsearch-user-secret",
							},
							Key: "password",
						},
					},
				},
				{
					Name:  "ELASTIC_CA",
					Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt",
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "tigera-ca-bundle",
					MountPath: "/etc/pki/tls/certs",
					ReadOnly:  true,
				},
				{
					Name:      render.TigeraLinseedSecret,
					MountPath: "/tigera-secure-linseed-cert",
					ReadOnly:  true,
				},
			},
		},
	}
}
