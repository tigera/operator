// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
			Name: "typha-ca",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaCAConfigMapName,
					}}},
		},
		{
			Name: "node-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  render.NodeTLSSecretName,
					DefaultMode: &defaultMode,
				}},
		},
		{
			Name: "elastic-ca-cert-volume",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: relasticsearch.PublicCertSecret,
					Items: []corev1.KeyToPath{
						{Key: "tls.crt", Path: "ca.pem"},
					},
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
		{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
		{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
		{
			MountPath: "/etc/ssl/elastic/", Name: "elastic-ca-cert-volume",
		},
		{
			MountPath: "/var/log/calico/snort-alerts", Name: "log-snort-alters",
		},
	}

	typhaCAConfigMap = &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.TyphaCAConfigMapName}}

	typhaTLSSecret = &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.TyphaTLSSecretName}}

	nodeTLSSecret = &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.NodeTLSSecretName}}

	esConfigMap = relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)

	pullSecrets = []*corev1.Secret{{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: common.OperatorNamespace()}}}
)

type resourceTestObj struct {
	name    string
	ns      string
	group   string
	version string
	kind    string
}

var _ = Describe("DPI rendering tests", func() {

	It("should render all resources for deep packet inspection with default resource requirements", func() {
		component := dpi.DPI(&dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			NodeTLSSecret:      nodeTLSSecret,
			TyphaTLSSecret:     typhaTLSSecret,
			TyphaCAConfigMap:   typhaCAConfigMap,
			PullSecrets:        pullSecrets,
			Openshift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   false,
			ESClusterConfig:    esConfigMap,
			ESSecrets:          nil,
			ClusterDomain:      dns.DefaultClusterDomain,
		})

		resources, _ := component.Objects()

		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.NodeTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaCAConfigMapName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ConfigMap"},
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
					}},
			}},
		}

		component := dpi.DPI(&dpi.DPIConfig{
			IntrusionDetection: ids2,
			Installation:       &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			NodeTLSSecret:      nodeTLSSecret,
			TyphaTLSSecret:     typhaTLSSecret,
			TyphaCAConfigMap:   typhaCAConfigMap,
			PullSecrets:        pullSecrets,
			Openshift:          true,
			HasNoLicense:       false,
			HasNoDPIResource:   false,
			ESClusterConfig:    esConfigMap,
			ESSecrets:          nil,
			ClusterDomain:      dns.DefaultClusterDomain,
		})

		resources, _ := component.Objects()

		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.NodeTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaCAConfigMapName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ConfigMap"},
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
		component := dpi.DPI(&dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			NodeTLSSecret:      nodeTLSSecret,
			TyphaTLSSecret:     typhaTLSSecret,
			TyphaCAConfigMap:   typhaCAConfigMap,
			PullSecrets:        pullSecrets,
			Openshift:          false,
			HasNoLicense:       true,
			HasNoDPIResource:   false,
			ESClusterConfig:    esConfigMap,
			ESSecrets:          nil,
			ClusterDomain:      dns.DefaultClusterDomain,
		})

		createResources, deleteResource := component.Objects()
		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.NodeTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: relasticsearch.PublicCertSecret, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaCAConfigMapName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: "pull-secret", ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		Expect(len(deleteResource)).To(Equal(len(expectedResources)))
		Expect(len(createResources)).To(Equal(0))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(deleteResource[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should delete resources for deep packet inspection if there is no DPI resource", func() {
		component := dpi.DPI(&dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			NodeTLSSecret:      nil,
			TyphaTLSSecret:     nil,
			TyphaCAConfigMap:   nil,
			PullSecrets:        pullSecrets,
			Openshift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   true,
			ESClusterConfig:    esConfigMap,
			ESSecrets:          nil,
			ClusterDomain:      dns.DefaultClusterDomain,
		})
		createResources, deleteResource := component.Objects()
		expectedResources := []resourceTestObj{
			{name: render.NodeTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: relasticsearch.PublicCertSecret, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaCAConfigMapName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: "pull-secret", ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
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
	Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/typha-ca"))
	Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/node-cert"))
	Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/typha-cert"))

	Expect(dpiDaemonSet.Spec.Template.Spec.Volumes).To(ContainElements(expectedVolumes))
	Expect(dpiDaemonSet.Spec.Template.Spec.HostNetwork).Should(BeTrue())
	Expect(dpiDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())

	Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].VolumeMounts).Should(ContainElements(expectedVolumeMounts))
	if !openshift {
		privileged := false
		Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext).Should(Equal(&corev1.SecurityContext{
			Privileged: &privileged,
		}))
	} else {
		privileged := true
		Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext).Should(Equal(&corev1.SecurityContext{
			Privileged: &privileged,
		}))
	}
}
