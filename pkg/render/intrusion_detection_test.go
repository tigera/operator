// Copyright (c) 2019,2022 Tigera, Inc. All rights reserved.

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
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	managedCluster    = true
	notManagedCluster = false
)

var _ = Describe("Intrusion Detection rendering tests", func() {

	var cfg *render.IntrusionDetectionConfiguration
	var bundle certificatemanagement.TrustedBundle
	var adAPIKeyPair certificatemanagement.KeyPairInterface
	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		adAPIKeyPair, err = certificatemanagement.NewKeyPair(rtest.CreateCertSecret(render.ADAPITLSSecretName, common.OperatorNamespace(), render.ADAPITLSSecretName), []string{""}, "")
		Expect(err).NotTo(HaveOccurred())
		bundle = certificateManager.CreateTrustedBundle()
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		cfg = &render.IntrusionDetectionConfiguration{
			TrustedCertBundle:     bundle,
			ADAPIServerCertSecret: adAPIKeyPair,
			Installation:          &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			ESClusterConfig:       relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1),
			ClusterDomain:         dns.DefaultClusterDomain,
			ESLicenseType:         render.ElasticsearchLicenseTypeUnknown,
			ManagedCluster:        notManagedCluster,
		}
	})

	It("should render all resources for a default configuration", func() {
		cfg.Openshift = notOpenshift
		component := render.IntrusionDetection(cfg)
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
			{name: "tigera.io.detector.dga", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-connection-spike", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-response-codes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-verbs", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.ip-sweep", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.port-scan", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-dns", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.time-series-dns", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-flows", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.time-series-flows", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-l7", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.dns-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.l7-bytes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.l7-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.process-restarts", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ADAPIObjectName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ADAPIObjectName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Service"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Secret"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: render.ADJobPodTemplateBaseName + ".training", ns: render.IntrusionDetectionNamespace, group: "", version: "v1", kind: "PodTemplate"},
			{name: render.ADJobPodTemplateBaseName + ".detection", ns: render.IntrusionDetectionNamespace, group: "", version: "v1", kind: "PodTemplate"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
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
		idji := rtest.GetResource(resources, "intrusion-detection-es-job-installer", render.IntrusionDetectionNamespace, "batch", "v1", "Job").(*batchv1.Job)
		Expect(idc.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
		))
		Expect(idji.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
		))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal(certificatemanagement.TrustedCertVolumeMountPath))
		Expect(idc.Spec.Template.Spec.Volumes[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(idc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))

		clusterRole := rtest.GetResource(resources, "intrusion-detection-controller", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)

		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"managedclusters"},
			Verbs:     []string{"watch", "list", "get"},
		}))

		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		}))

		// secrets are mounted
		adAPIDeployment := rtest.GetResource(resources, render.ADAPIObjectName, render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(adAPIDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(bundle.VolumeMount().Name))
		Expect(adAPIDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal(bundle.VolumeMount().MountPath))
		Expect(adAPIDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal(adAPIKeyPair.VolumeMount().Name))
		Expect(adAPIDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal(adAPIKeyPair.VolumeMount().MountPath))

		// Check all Role for respective AD API SAs
		detectorsSecret := rtest.GetResource(resources, "anomaly-detectors", render.IntrusionDetectionNamespace, "", "v1", "Secret").(*corev1.Secret)
		Expect(detectorsSecret.Type).To(Equal(corev1.SecretTypeServiceAccountToken))
		Expect(detectorsSecret.GetObjectMeta().GetAnnotations()[corev1.ServiceAccountNameKey]).To(Equal("anomaly-detectors"))

		detectorsRole := rtest.GetResource(resources, "anomaly-detectors", render.IntrusionDetectionNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(len(detectorsRole.Rules)).To(Equal(1))
		Expect(detectorsRole.Rules[0].APIGroups).To(ConsistOf(render.ADResourceGroup))
		Expect(detectorsRole.Rules[0].Resources).To(ConsistOf(render.ADDetectorsModelResourceName))
		Expect(detectorsRole.Rules[0].Verbs).To(ConsistOf("get", "create", "update"))

		detectorsRoleBinding := rtest.GetResource(resources, "anomaly-detectors", render.IntrusionDetectionNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(detectorsRoleBinding.RoleRef).To(Equal(rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "anomaly-detectors",
		}))
		Expect(detectorsRoleBinding.Subjects).To(ConsistOf(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      "anomaly-detectors",
			Namespace: render.IntrusionDetectionNamespace,
		}))

		adAPIClusterRole := rtest.GetResource(resources, render.ADAPIObjectName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(adAPIClusterRole.Rules)).To(Equal(2))
		Expect(adAPIClusterRole.Rules[0].APIGroups).To(ConsistOf("authorization.k8s.io"))
		Expect(adAPIClusterRole.Rules[0].Resources).To(ConsistOf("subjectaccessreviews"))
		Expect(adAPIClusterRole.Rules[0].Verbs).To(ConsistOf("create"))
		Expect(adAPIClusterRole.Rules[1].APIGroups).To(ConsistOf("authentication.k8s.io"))
		Expect(adAPIClusterRole.Rules[1].Resources).To(ConsistOf("tokenreviews"))
		Expect(adAPIClusterRole.Rules[1].Verbs).To(ConsistOf("create"))

		adAPIClusterRoleBinding := rtest.GetResource(resources, render.ADAPIObjectName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(adAPIClusterRoleBinding.RoleRef).To(Equal(rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.ADAPIObjectName,
		}))
		Expect(adAPIClusterRoleBinding.Subjects).To(ConsistOf(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      render.ADAPIObjectName,
			Namespace: render.IntrusionDetectionNamespace,
		}))
	})

	It("should render all resources for a configuration that includes event forwarding turned on (Syslog)", func() {
		// Initialize a default LogCollector instance to use.
		cfg.LogCollector = &operatorv1.LogCollector{}
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		cfg.Openshift = notOpenshift

		component := render.IntrusionDetection(cfg)
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
			{name: "tigera.io.detector.dga", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-connection-spike", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-response-codes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-verbs", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.ip-sweep", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.port-scan", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-dns", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.time-series-dns", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-flows", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.time-series-flows", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-l7", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.dns-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.l7-bytes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.l7-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.process-restarts", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ADAPIObjectName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ADAPIObjectName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Service"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Secret"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: render.ADJobPodTemplateBaseName + ".training", ns: render.IntrusionDetectionNamespace, group: "", version: "v1", kind: "PodTemplate"},
			{name: render.ADJobPodTemplateBaseName + ".detection", ns: render.IntrusionDetectionNamespace, group: "", version: "v1", kind: "PodTemplate"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
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
			{"CLUSTER_NAME", cfg.ESClusterConfig.ClusterName(), "", ""},
			{"MULTI_CLUSTER_FORWARDING_CA", cfg.TrustedCertBundle.MountPath(), "", ""},
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

	It("should not render intrusion-detection-es-job-installer and should disable GlobalAlert controller when cluster is managed", func() {
		cfg.Openshift = notOpenshift
		cfg.ManagedCluster = managedCluster

		component := render.IntrusionDetection(cfg)
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
			{name: "tigera.io.detector.dga", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-connection-spike", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-response-codes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-verbs", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.ip-sweep", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.port-scan", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-dns", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.time-series-dns", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-flows", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.time-series-flows", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-l7", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.dns-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.l7-bytes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.l7-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.process-restarts", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
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
		Expect(idc.Spec.Template.Spec.Containers[0].Env).To(ContainElements(
			corev1.EnvVar{Name: "CLUSTER_NAME", Value: cfg.ESClusterConfig.ClusterName()},
			corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: cfg.TrustedCertBundle.MountPath()},
			corev1.EnvVar{Name: "DISABLE_ALERTS", Value: "yes"},
			corev1.EnvVar{Name: "DISABLE_ANOMALY_DETECTION", Value: "yes"},
		))

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
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
		}
		cfg.ESClusterConfig = &relasticsearch.ClusterConfig{}
		component := render.IntrusionDetection(cfg)
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
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		cfg.ESClusterConfig = &relasticsearch.ClusterConfig{}
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		job := rtest.GetResource(resources, render.IntrusionDetectionInstallerJobName, render.IntrusionDetectionNamespace, "batch", "v1", "Job").(*batchv1.Job)
		Expect(idc.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
		Expect(job.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
	})
})
