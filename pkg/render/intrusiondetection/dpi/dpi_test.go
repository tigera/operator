// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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

package dpi_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	"github.com/tigera/operator/pkg/render/testutils"
)

var (
	defaultMode int32 = 420
	dirOrCreate       = corev1.HostPathDirectoryOrCreate

	ids = &operatorv1.IntrusionDetection{
		TypeMeta:   metav1.TypeMeta{Kind: "IntrusionDetection", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		Spec: operatorv1.IntrusionDetectionSpec{
			ComponentResources: []operatorv1.IntrusionDetectionComponentResource{
				{
					ComponentName: operatorv1.ComponentNameDeepPacketInspection,
					ResourceRequirements: &corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse(dpi.DefaultMemoryLimit),
							corev1.ResourceCPU:    resource.MustParse(dpi.DefaultCPULimit),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse(dpi.DefaultMemoryRequest),
							corev1.ResourceCPU:    resource.MustParse(dpi.DefaultCPURequest),
						},
					},
				},
			},
		},
	}

	expectedClusterRoleRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"endpoints", "services"},
			Verbs:     []string{"watch", "list", "get"},
		},
	}

	expectedCRB = rbacv1.RoleBinding{
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      dpi.DeepPacketInspectionName,
				Namespace: dpi.DeepPacketInspectionNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     dpi.DeepPacketInspectionName,
		},
	}

	expectedVolumes = []corev1.Volume{
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
		{
			Name: "node-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  render.NodeTLSSecretName,
					DefaultMode: &defaultMode,
				},
			},
		},
		{
			Name: "log-snort-alters",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/snort-alerts",
					Type: &dirOrCreate,
				},
			},
		},
	}

	expectedVolumeMounts = []corev1.VolumeMount{
		{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
		{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
		{
			MountPath: "/var/log/calico/snort-alerts", Name: "log-snort-alters",
		},
	}

	esConfigMap = relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)

	pullSecrets = []*corev1.Secret{{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: common.OperatorNamespace()},
	}}
)

type resourceTestObj struct {
	name    string
	ns      string
	group   string
	version string
	kind    string
}

var _ = Describe("DPI rendering tests", func() {
	var (
		clusterDomain = "cluster.local"
		installation  *operatorv1.InstallationSpec
		typhaNodeTLS  *render.TyphaNodeTLS
		dpiCertSecret certificatemanagement.KeyPairInterface
		cfg           *dpi.DPIConfig
	)

	// Fetch expectations from utilities that require Ginkgo context.
	expectedUnmanagedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dpi_unmanaged.json")
	expectedUnmanagedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dpi_unmanaged_ocp.json")
	expectedManagedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dpi_managed.json")
	expectedManagedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dpi_managed_ocp.json")

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		nodeKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())
		typhaKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())
		dpiCertSecret, err = certificateManager.GetOrCreateKeyPair(cli, render.DPITLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		trustedBundle := certificateManager.CreateTrustedBundle(nodeKeyPair, typhaKeyPair, dpiCertSecret)
		typhaNodeTLS = &render.TyphaNodeTLS{
			TyphaSecret:   typhaKeyPair,
			NodeSecret:    nodeKeyPair,
			TrustedBundle: trustedBundle,
		}
		installation = &operatorv1.InstallationSpec{Registry: "testregistry.com/"}
		cfg = &dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       installation,
			TyphaNodeTLS:       typhaNodeTLS,
			PullSecrets:        pullSecrets,
			Openshift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   false,
			ESClusterConfig:    esConfigMap,
			ClusterDomain:      dns.DefaultClusterDomain,
			DPICertSecret:      dpiCertSecret,
		}
	})

	It("should render all resources for deep packet inspection with default resource requirements", func() {
		component := dpi.DPI(cfg)

		resources, _ := component.Objects()

		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: dpi.DeepPacketInspectionPolicyName, ns: dpi.DeepPacketInspectionNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "pull-secret", ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "CLUSTER_NAME", Value: "clusterTestName"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: "/deep-packet-inspection-tls/tls.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: "/deep-packet-inspection-tls/tls.key"},
			corev1.EnvVar{Name: "FIPS_MODE_ENABLED", Value: "false"},
		))
		Expect(len(ds.Spec.Template.Spec.Containers)).Should(Equal(1))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPURequest)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPULimit)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryRequest)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryLimit)))

		validateDPIComponents(resources, false)
	})

	It("should render all resources for deep packet inspection with custom resource requirements", func() {
		memoryLimit := resource.MustParse("2Gi")
		cpuLimit := resource.MustParse("2")
		ids2 := &operatorv1.IntrusionDetection{
			TypeMeta:   metav1.TypeMeta{Kind: "IntrusionDetection", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.IntrusionDetectionSpec{ComponentResources: []operatorv1.IntrusionDetectionComponentResource{
				{
					ComponentName: "DeepPacketInspection",
					ResourceRequirements: &corev1.ResourceRequirements{
						Limits: corev1.ResourceList{"memory": memoryLimit, "cpu": cpuLimit},
					},
				},
			}},
		}

		cfg.IntrusionDetection = ids2
		cfg.Openshift = true
		component := dpi.DPI(cfg)

		resources, _ := component.Objects()

		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: dpi.DeepPacketInspectionPolicyName, ns: dpi.DeepPacketInspectionNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "pull-secret", ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(len(ds.Spec.Template.Spec.Containers)).Should(Equal(1))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Cpu()).Should(Equal(cpuLimit))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Memory()).Should(Equal(memoryLimit))
		Expect(ds.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu().IsZero()).Should(BeTrue())
		Expect(ds.Spec.Template.Spec.Containers[0].Resources.Requests.Memory().IsZero()).Should(BeTrue())

		validateDPIComponents(resources, true)
	})

	It("should delete resources for deep packet inspection if there is no valid product license", func() {
		cfg.HasNoLicense = true
		component := dpi.DPI(cfg)

		createResources, deleteResource := component.Objects()
		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: dpi.DeepPacketInspectionPolicyName, ns: dpi.DeepPacketInspectionNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: relasticsearch.PublicCertSecret, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "pull-secret", ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: "tigera-linseed", ns: "tigera-dpi", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
		}

		Expect(len(deleteResource)).To(Equal(len(expectedResources)))
		Expect(len(createResources)).To(Equal(0))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(deleteResource[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should delete resources for deep packet inspection if there is no DPI resource", func() {
		cfg.HasNoDPIResource = true
		component := dpi.DPI(cfg)
		createResources, deleteResource := component.Objects()
		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionPolicyName, ns: dpi.DeepPacketInspectionNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: relasticsearch.PublicCertSecret, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "pull-secret", ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: "tigera-linseed", ns: "tigera-dpi", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
		}

		expectedCreateResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
		}
		Expect(len(deleteResource)).To(Equal(len(expectedResources)))
		Expect(len(createResources)).To(Equal(len(expectedCreateResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(deleteResource[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
		for i, expectedRes := range expectedCreateResources {
			rtest.ExpectResource(createResources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	Context("allow-tigera rendering", func() {
		policyName := types.NamespacedName{Name: "allow-tigera.tigera-dpi", Namespace: "tigera-dpi"}

		getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			return testutils.SelectPolicyByClusterTypeAndProvider(
				scenario,
				expectedUnmanagedPolicy,
				expectedUnmanagedPolicyForOpenshift,
				expectedManagedPolicy,
				expectedManagedPolicyForOpenshift,
			)
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.ManagedCluster = scenario.ManagedCluster
				cfg.Openshift = scenario.Openshift
				component := dpi.DPI(cfg)
				resources, _ := component.Objects()

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}),
		)
	})
})

func validateDPIComponents(resources []client.Object, openshift bool) {
	dpiNs := rtest.GetResource(resources, dpi.DeepPacketInspectionNamespace, "", "", "v1", "Namespace").(*corev1.Namespace)
	Expect(dpiNs).ShouldNot(BeNil())

	dpiServiceAccount := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
	Expect(dpiServiceAccount).ShouldNot(BeNil())

	dpiClusterRole := rtest.GetResource(resources, dpi.DeepPacketInspectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
	Expect(dpiClusterRole.Rules).Should(ContainElements(expectedClusterRoleRules))

	dpiClusterRoleBinding := rtest.GetResource(resources, dpi.DeepPacketInspectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
	Expect(dpiClusterRoleBinding.RoleRef).Should(Equal(expectedCRB.RoleRef))
	Expect(dpiClusterRoleBinding.Subjects).Should(BeEquivalentTo(expectedCRB.Subjects))

	dpiDaemonSet := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
	Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/tigera-ca-private"))
	Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/node-certs"))

	Expect(dpiDaemonSet.Spec.Template.Spec.Volumes).To(ContainElements(expectedVolumes))
	Expect(dpiDaemonSet.Spec.Template.Spec.HostNetwork).Should(BeTrue())
	Expect(dpiDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())

	Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].VolumeMounts).Should(ContainElements(expectedVolumeMounts))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(Equal(openshift))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(Equal(openshift))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(Equal(false))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
	Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
		&corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
			Add:  []corev1.Capability{"NET_ADMIN", "NET_RAW"},
		},
	))
	Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
		&corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		}))
}
