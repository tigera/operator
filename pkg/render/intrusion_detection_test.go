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
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	managedCluster          = true
	notManagedCluster       = false
	defaultMode       int32 = 420
)

var _ = Describe("Intrusion Detection rendering tests", func() {
	It("should render all resources for a default configuration", func() {
		esConfigMap := relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)

		component := render.IntrusionDetection(
			nil,
			nil,
			nil,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			&operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			esConfigMap, nil, notOpenshift, dns.DefaultClusterDomain, render.ElasticsearchLicenseTypeUnknown, notManagedCluster,
			false,
			&internalManagerTLSSecret,
			nil,
			nil,
			nil)
		resources, _ := component.Objects()

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-intrusion-detection", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.TigeraKibanaCertSecret, ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{render.ManagerInternalTLSSecretName, "tigera-intrusion-detection", "", "v1", "Secret"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "policy.pod", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkpolicy", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkset", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.serviceaccount", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.cloudapi", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.ssh", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.access", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.originate", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.servfail", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.dos", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			if expectedRes.kind == "GlobalAlertTemplate" {
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		// Should mount ManagerTLSSecret for non-managed clusters
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))
		Expect(idc.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(idc.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))

		clusterRole := rtest.GetResource(resources, "intrusion-detection-controller", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)

		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"managedclusters"},
			Verbs:     []string{"watch", "list", "get"},
		}))

		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authenticationreviews"},
			Verbs:     []string{"create"},
		}))
	})

	It("should render all resources for a configuration that includes event forwarding turned on (Syslog)", func() {
		esConfigMap := relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)

		// Initialize a default LogCollector instance to use.
		lc := &operatorv1.LogCollector{}
		lc.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}

		component := render.IntrusionDetection(
			nil,
			lc,
			nil,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			&operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			esConfigMap,
			nil,
			notOpenshift,
			dns.DefaultClusterDomain,
			render.ElasticsearchLicenseTypeUnknown,
			notManagedCluster,
			false,
			nil,
			nil,
			nil,
			nil)
		resources, _ := component.Objects()

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-intrusion-detection", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.TigeraKibanaCertSecret, ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "policy.pod", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkpolicy", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkset", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.serviceaccount", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.cloudapi", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.ssh", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.access", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.originate", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.servfail", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.dos", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			if expectedRes.kind == "GlobalAlertTemplate" {
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		dp := rtest.GetResource(resources, "intrusion-detection-controller", "tigera-intrusion-detection", "apps", "v1", "Deployment").(*appsv1.Deployment)
		envs := dp.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"IDS_ENABLE_EVENT_FORWARDING", "true", "", ""},
		}
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						}},
				}))
			}
		}
	})

	It("should render all resources for deep packet inspection with default resource requirements", func() {
		ids := &operatorv1.IntrusionDetection{TypeMeta: metav1.TypeMeta{Kind: "IntrusionDetection", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
		esConfigMap := relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)
		typhaCAConfigMap := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.TyphaCAConfigMapName}}
		typhaTLSSecret := &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.TyphaTLSSecretName}}
		nodeTLSSecret := &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.NodeTLSSecretName}}

		component := render.IntrusionDetection(
			ids,
			nil,
			nil,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			&operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			esConfigMap,
			nil,
			notOpenshift,
			dns.DefaultClusterDomain,
			render.ElasticsearchLicenseTypeUnknown,
			notManagedCluster,
			false,
			&internalManagerTLSSecret,
			nodeTLSSecret,
			typhaTLSSecret,
			typhaCAConfigMap)
		resources, _ := component.Objects()

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-intrusion-detection", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.TigeraKibanaCertSecret, ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{render.ManagerInternalTLSSecretName, "tigera-intrusion-detection", "", "v1", "Secret"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "policy.pod", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkpolicy", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkset", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.serviceaccount", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.cloudapi", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.ssh", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.access", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.originate", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.servfail", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.dos", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.NodeTLSSecretName, ns: render.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaTLSSecretName, ns: render.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaCAConfigMapName, ns: render.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: render.DeepPacketInspectionName, ns: render.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.DeepPacketInspectionName, ns: render.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: "tigera-secure", ns: "", group: "", version: "v1", kind: "IntrusionDetection"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// IDS resource should be updated with default resource values for DPI
		idsResp := rtest.GetResource(resources, "tigera-secure", "", "", "v1", "IntrusionDetection").(*operatorv1.IntrusionDetection)
		Expect(len(idsResp.Spec.ComponentResources)).Should(Equal(1))
		Expect(idsResp.Spec.ComponentResources[0].ComponentName).Should(Equal(operatorv1.ComponentNameDeepPacketInspection))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Requests.Cpu()).Should(Equal(resource.MustParse(render.DefaultCPURequestDPI)))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Limits.Cpu()).Should(Equal(resource.MustParse(render.DefaultCPULimitDPI)))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Requests.Memory()).Should(Equal(resource.MustParse(render.DefaultMemoryRequestDPI)))
		Expect(*idsResp.Spec.ComponentResources[0].ResourceRequirements.Limits.Memory()).Should(Equal(resource.MustParse(render.DefaultMemoryLimitDPI)))

		dpiNs := rtest.GetResource(resources, render.DeepPacketInspectionNamespace, "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(dpiNs).ShouldNot(BeNil())

		dpiServiceAccount := rtest.GetResource(resources, render.DeepPacketInspectionName, render.DeepPacketInspectionNamespace, "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
		Expect(dpiServiceAccount).ShouldNot(BeNil())

		dpiClusterRole := rtest.GetResource(resources, render.DeepPacketInspectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(dpiClusterRole.Rules).Should(ContainElements([]rbacv1.PolicyRule{
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
		}))

		dpiClusterRoleBinding := rtest.GetResource(resources, render.DeepPacketInspectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(dpiClusterRoleBinding.RoleRef).Should(Equal(rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.DeepPacketInspectionName,
		}))
		Expect(dpiClusterRoleBinding.Subjects).Should(BeEquivalentTo([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.DeepPacketInspectionName,
				Namespace: render.DeepPacketInspectionNamespace,
			},
		}))

		dpiDaemonSet := rtest.GetResource(resources, render.DeepPacketInspectionName, render.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/typha-ca"))
		Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/node-cert"))
		Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/typha-cert"))

		Expect(dpiDaemonSet.Spec.Template.Spec.Volumes).To(ContainElements([]corev1.Volume{
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
		}))

		Expect(dpiDaemonSet.Spec.Template.Spec.HostNetwork).Should(BeTrue())

		Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].VolumeMounts).Should(ContainElements([]corev1.VolumeMount{
			{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
			{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
		}))

	})

	It("should render all resources for deep packet inspection with custom resource requirements", func() {
		memoryLimit := resource.MustParse("2Gi")
		cpuLimit := resource.MustParse("2")
		ids := &operatorv1.IntrusionDetection{
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

		esConfigMap := relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)
		typhaCAConfigMap := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.TyphaCAConfigMapName}}
		typhaTLSSecret := &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.TyphaTLSSecretName}}
		nodeTLSSecret := &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: render.NodeTLSSecretName}}

		component := render.IntrusionDetection(
			ids,
			nil,
			nil,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			&operatorv1.InstallationSpec{Registry: "testregistry.com/", ControlPlaneNodeSelector: map[string]string{"foo": "bar"}},
			esConfigMap,
			nil,
			notOpenshift,
			dns.DefaultClusterDomain,
			render.ElasticsearchLicenseTypeUnknown,
			notManagedCluster,
			false,
			&internalManagerTLSSecret,
			nodeTLSSecret,
			typhaTLSSecret,
			typhaCAConfigMap)
		resources, _ := component.Objects()

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-intrusion-detection", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.TigeraKibanaCertSecret, ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{render.ManagerInternalTLSSecretName, "tigera-intrusion-detection", "", "v1", "Secret"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "policy.pod", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkpolicy", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkset", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.serviceaccount", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.cloudapi", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.ssh", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.access", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.originate", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.servfail", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.dos", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.NodeTLSSecretName, ns: render.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaTLSSecretName, ns: render.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.TyphaCAConfigMapName, ns: render.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: render.DeepPacketInspectionName, ns: render.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.DeepPacketInspectionName, ns: render.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: "tigera-secure", ns: "", group: "", version: "v1", kind: "IntrusionDetection"},
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

		dpiNs := rtest.GetResource(resources, render.DeepPacketInspectionNamespace, "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(dpiNs).ShouldNot(BeNil())

		dpiServiceAccount := rtest.GetResource(resources, render.DeepPacketInspectionName, render.DeepPacketInspectionNamespace, "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
		Expect(dpiServiceAccount).ShouldNot(BeNil())

		dpiClusterRole := rtest.GetResource(resources, render.DeepPacketInspectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(dpiClusterRole.Rules).Should(ContainElements([]rbacv1.PolicyRule{
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
		}))

		dpiClusterRoleBinding := rtest.GetResource(resources, render.DeepPacketInspectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(dpiClusterRoleBinding.RoleRef).Should(Equal(rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.DeepPacketInspectionName,
		}))
		Expect(dpiClusterRoleBinding.Subjects).Should(BeEquivalentTo([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.DeepPacketInspectionName,
				Namespace: render.DeepPacketInspectionNamespace,
			},
		}))

		dpiDaemonSet := rtest.GetResource(resources, render.DeepPacketInspectionName, render.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/typha-ca"))
		Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/node-cert"))
		Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/typha-cert"))

		Expect(dpiDaemonSet.Spec.Template.Spec.Volumes).To(ContainElements([]corev1.Volume{
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
		}))

		Expect(dpiDaemonSet.Spec.Template.Spec.HostNetwork).Should(BeTrue())

		Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].VolumeMounts).Should(ContainElements([]corev1.VolumeMount{
			{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
			{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
		}))

		Expect(dpiDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())
	})

	It("should not render intrusion-detection-es-job-installer and should disable GlobalAlert controller when cluster is managed", func() {
		esConfigMap := relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)

		component := render.IntrusionDetection(
			nil,
			nil,
			nil,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			&operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			esConfigMap,
			nil,
			notOpenshift,
			dns.DefaultClusterDomain,
			render.ElasticsearchLicenseTypeUnknown,
			managedCluster,
			false,
			nil,
			nil,
			nil,
			nil)
		resources, _ := component.Objects()

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-intrusion-detection", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.TigeraKibanaCertSecret, ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-controller", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "policy.pod", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkpolicy", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.globalnetworkset", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "policy.serviceaccount", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.cloudapi", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.ssh", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.access", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "network.lateral.originate", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.servfail", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "dns.dos", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			if expectedRes.kind == "GlobalAlertTemplate" {
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "DISABLE_ALERTS", Value: "yes"}))

		clusterRole := rtest.GetResource(resources, "intrusion-detection-controller", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).NotTo(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		}))
	})

	It("should apply controlPlaneNodeSelector correctly", func() {
		component := render.IntrusionDetection(
			nil,
			nil,
			nil,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			&operatorv1.InstallationSpec{ControlPlaneNodeSelector: map[string]string{"foo": "bar"}},
			&relasticsearch.ClusterConfig{},
			nil,
			false,
			dns.DefaultClusterDomain,
			render.ElasticsearchLicenseTypeUnknown,
			notManagedCluster,
			false,
			nil,
			nil,
			nil,
			nil)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		job := rtest.GetResource(resources, render.IntrusionDetectionInstallerJobName, render.IntrusionDetectionNamespace, "batch", "v1", "Job").(*batchv1.Job)
		Expect(idc.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
		Expect(job.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
	})

	It("should apply controlPlaneTolerations correctly", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		component := render.IntrusionDetection(
			nil,
			nil,
			nil,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			&operatorv1.InstallationSpec{ControlPlaneTolerations: []corev1.Toleration{t}},
			&relasticsearch.ClusterConfig{},
			nil,
			false,
			dns.DefaultClusterDomain,
			render.ElasticsearchLicenseTypeUnknown,
			notManagedCluster,
			false,
			nil,
			nil,
			nil,
			nil)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		job := rtest.GetResource(resources, render.IntrusionDetectionInstallerJobName, render.IntrusionDetectionNamespace, "batch", "v1", "Job").(*batchv1.Job)
		Expect(idc.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
		Expect(job.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
	})
})
