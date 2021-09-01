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
	"github.com/tigera/operator/pkg/render"
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

	ids = &operatorv1.IntrusionDetection{TypeMeta: metav1.TypeMeta{Kind: "IntrusionDetection", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}

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
	}

	expectedVolumeMounts = []corev1.VolumeMount{
		{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
		{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
	}

	typhaCAConfigMap = &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.TyphaCAConfigMapName}}

	typhaTLSSecret = &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.TyphaTLSSecretName}}

	nodeTLSSecret = &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.NodeTLSSecretName}}
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
		component := dpi.DPI(
			ids,
			&operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			nodeTLSSecret,
			typhaTLSSecret,
			typhaCAConfigMap,
			nil,
			false,
			false,
		)
		resources, _ := component.Objects()

		expectedResources := []resourceTestObj{
			{name: "tigera-secure", ns: "", group: "", version: "v1", kind: "IntrusionDetection"},
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.NodeTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaCAConfigMapName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// IDS resource should be updated with default resource values for DPI
		idsResp := rtest.GetResource(resources, "tigera-secure", "", "", "v1", "IntrusionDetection").(*operatorv1.IntrusionDetection)
		Expect(len(idsResp.Spec.ComponentResources)).Should(Equal(1))
		Expect(idsResp.Spec.ComponentResources[0].ComponentName).Should(Equal(operatorv1.ComponentNameDeepPacketInspection))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Requests.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPURequestDPI)))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Limits.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPULimitDPI)))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Requests.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryRequestDPI)))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Limits.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryLimitDPI)))

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

		component := dpi.DPI(
			ids2,
			&operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			nodeTLSSecret,
			typhaTLSSecret,
			typhaCAConfigMap,
			nil,
			true,
			false,
		)
		resources, _ := component.Objects()

		expectedResources := []resourceTestObj{
			{name: "tigera-secure", ns: "", group: "", version: "v1", kind: "IntrusionDetection"},
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.NodeTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaTLSSecretName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaCAConfigMapName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// IDS resource should be updated with default resource values for DPI
		idsResp := rtest.GetResource(resources, "tigera-secure", "", "", "v1", "IntrusionDetection").(*operatorv1.IntrusionDetection)
		Expect(len(idsResp.Spec.ComponentResources)).Should(Equal(1))
		Expect(idsResp.Spec.ComponentResources[0].ComponentName).Should(Equal(operatorv1.ComponentNameDeepPacketInspection))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Limits.Cpu()).Should(Equal(cpuLimit))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Limits.Memory()).Should(Equal(memoryLimit))
		Expect(idsResp.Spec.ComponentResources[0].ResourceRequirements.Requests.Cpu().IsZero()).Should(BeTrue())
		Expect(idsResp.Spec.ComponentResources[0].ResourceRequirements.Requests.Memory().IsZero()).Should(BeTrue())

		validateDPIComponents(resources, true)
	})

	It("Should delete resources for deep packet inspection if there is no valid product license", func() {
		component := dpi.DPI(
			ids,
			&operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			nodeTLSSecret,
			typhaTLSSecret,
			typhaCAConfigMap,
			nil,
			false,
			true,
		)
		createResources, deleteResource := component.Objects()
		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
		}

		Expect(len(deleteResource)).To(Equal(len(expectedResources)))
		Expect(len(createResources)).To(Equal(0))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(deleteResource[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("Should delete resources for deep packet inspection if TLS configs are not set", func() {
		component := dpi.DPI(
			ids,
			&operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			nil,
			nil,
			nil,
			nil,
			false,
			false,
		)
		createResources, deleteResource := component.Objects()
		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
		}

		Expect(len(deleteResource)).To(Equal(len(expectedResources)))
		Expect(len(createResources)).To(Equal(0))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(deleteResource[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
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
