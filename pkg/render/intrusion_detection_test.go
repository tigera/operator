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
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	managedCluster    = true
	notManagedCluster = false
)

type expectedEnvVar struct {
	name       string
	val        string
	secretName string
	secretKey  string
}

var _ = Describe("Intrusion Detection rendering tests", func() {
	var cfg *render.IntrusionDetectionConfiguration
	var bundle certificatemanagement.TrustedBundle
	var adAPIKeyPair certificatemanagement.KeyPairInterface

	expectedIDPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_unmanaged.json")
	expectedIDPolicyForManaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_managed.json")
	expectedIDPolicyForUnmanagedOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_unmanaged_ocp.json")
	expectedIDPolicyForManagedOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_managed_ocp.json")
	expectedIDInstallerPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-elastic.json")
	expectedIDInstallerPolicyForOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-elastic_ocp.json")
	expectedAnomalyDetectionAPIPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/ad-api.json")
	expectedAnomalyDetectionAPIPolicyForOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/ad-api_ocp.json")
	expectedAnomalyDetectorsPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/ad-detectors.json")
	expectedAnomalyDetectorsPolicyForOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/ad-detectors_ocp.json")

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		secret, err := certificatemanagement.CreateSelfSignedSecret("", "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		adAPIKeyPair = certificatemanagement.NewKeyPair(secret, []string{""}, "")
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
			UsePSP:                true,
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
			{name: "allow-tigera.intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "allow-tigera.default-deny", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
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
			{name: "allow-tigera.anomaly-detection-api", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ADAPIObjectName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ADAPIObjectName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Service"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "allow-tigera.anomaly-detectors", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Secret"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: render.ADJobPodTemplateBaseName + ".training", ns: render.IntrusionDetectionNamespace, group: "", version: "v1", kind: "PodTemplate"},
			{name: render.ADJobPodTemplateBaseName + ".detection", ns: render.IntrusionDetectionNamespace, group: "", version: "v1", kind: "PodTemplate"},
			{name: "allow-tigera.intrusion-detection-elastic", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
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
		Expect(idc.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(idc.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
		))
		Expect(idji.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(idji.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
		))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal(certificatemanagement.TrustedCertVolumeMountPath))

		Expect(idc.Spec.Template.Spec.Volumes[0].Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))
		Expect(idc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal(certificatemanagement.TrustedCertConfigMapName))

		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))

		clusterRole := rtest.GetResource(resources, "intrusion-detection-controller", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)

		Expect(clusterRole.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"watch", "list", "get"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs", "jobs"},
				Verbs: []string{
					"get", "list", "watch", "create", "update", "patch", "delete",
				},
			}))

		// secrets are mounted
		adAPIDeployment := rtest.GetResource(resources, render.ADAPIObjectName, render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(adAPIDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal(bundle.VolumeMount(rmeta.OSTypeLinux).Name))
		Expect(adAPIDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal(bundle.VolumeMount(rmeta.OSTypeLinux).MountPath))
		Expect(adAPIDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal(adAPIKeyPair.VolumeMount(rmeta.OSTypeLinux).Name))
		Expect(adAPIDeployment.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal(adAPIKeyPair.VolumeMount(rmeta.OSTypeLinux).MountPath))

		// Check all Role for respective AD API SAs
		detectorsSecret := rtest.GetResource(resources, "anomaly-detectors", render.IntrusionDetectionNamespace, "", "v1", "Secret").(*corev1.Secret)
		Expect(detectorsSecret.Type).To(Equal(corev1.SecretTypeServiceAccountToken))
		Expect(detectorsSecret.GetObjectMeta().GetAnnotations()[corev1.ServiceAccountNameKey]).To(Equal("anomaly-detectors"))

		detectorsRole := rtest.GetResource(resources, "anomaly-detectors", render.IntrusionDetectionNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(len(detectorsRole.Rules)).To(Equal(1))
		Expect(detectorsRole.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{
					render.ADResourceGroup,
				},
				Resources: []string{
					render.ADDetectorsModelResourceName, render.ADLogTypeMetaDataResourceName,
				},
				Verbs: []string{
					"get",
					"create",
					"update",
				},
			},
		))

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

	It("should render finalizers rbac resources in the IDS ClusterRole for an Openshift management/standalone cluster", func() {
		cfg.Openshift = openshift
		cfg.ManagedCluster = false
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		idsControllerRole := rtest.GetResource(resources, render.IntrusionDetectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)

		Expect(idsControllerRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments/finalizers"},
			Verbs:     []string{"update"},
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
			{name: "allow-tigera.intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "allow-tigera.default-deny", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
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
			{name: "allow-tigera.anomaly-detection-api", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ADAPIObjectName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ADAPIObjectName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Service"},
			{name: render.ADAPIObjectName, ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "allow-tigera.anomaly-detectors", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Secret"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: render.ADJobPodTemplateBaseName + ".training", ns: render.IntrusionDetectionNamespace, group: "", version: "v1", kind: "PodTemplate"},
			{name: render.ADJobPodTemplateBaseName + ".detection", ns: render.IntrusionDetectionNamespace, group: "", version: "v1", kind: "PodTemplate"},
			{name: "allow-tigera.intrusion-detection-elastic", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
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

		expectedEnvs := []expectedEnvVar{
			{"CLUSTER_NAME", cfg.ESClusterConfig.ClusterName(), "", ""},
			{"MULTI_CLUSTER_FORWARDING_CA", cfg.TrustedCertBundle.MountPath(), "", ""},
			{"IDS_ENABLE_EVENT_FORWARDING", "true", "", ""},
		}

		assertEnvVarlistMatch(envs, expectedEnvs)

		// expect AD PodTemplate EnvVars
		expectedADEnvs := []expectedEnvVar{
			{"ELASTIC_HOST", dns.GetServiceDNSNames(render.ESGatewayServiceName, render.ElasticsearchNamespace, cfg.ClusterDomain)[2], "", ""},
			{"ELASTIC_PORT", strconv.Itoa(render.ElasticsearchDefaultPort), "", ""},
			{"ELASTIC_CA", certificatemanagement.TrustedCertBundleMountPath, "", ""},
			{"ELASTIC_USERNAME", "", render.ElasticsearchADJobUserSecret, "username"},
			{"ELASTIC_PASSWORD", "", render.ElasticsearchADJobUserSecret, "password"},
			{"MODEL_STORAGE_API_HOST", render.ADAPIExpectedServiceName, "", ""},
			{"MODEL_STORAGE_API_PORT", strconv.Itoa(8080), "", ""},
			{"MODEL_STORAGE_CLIENT_CERT", cfg.ADAPIServerCertSecret.VolumeMountCertificateFilePath(), "", ""},
			{"MODEL_STORAGE_API_TOKEN", "", "anomaly-detectors", "token"},
		}

		adDetectionPodtemplate := rtest.GetResource(resources, render.ADJobPodTemplateBaseName+".detection", "tigera-intrusion-detection", "", "v1", "PodTemplate").(*corev1.PodTemplate)
		adDetectionEnvs := adDetectionPodtemplate.Template.Spec.Containers[0].Env

		adTrainingPodtemplate := rtest.GetResource(resources, render.ADJobPodTemplateBaseName+".training", "tigera-intrusion-detection", "", "v1", "PodTemplate").(*corev1.PodTemplate)
		adTrainingEnvs := adTrainingPodtemplate.Template.Spec.Containers[0].Env

		assertEnvVarlistMatch(adDetectionEnvs, expectedADEnvs)
		assertEnvVarlistMatch(adTrainingEnvs, expectedADEnvs)
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
			{name: "allow-tigera.intrusion-detection-controller", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "allow-tigera.default-deny", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
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
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
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
		Expect(clusterRole.Rules).NotTo(ContainElements([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs", "jobs"},
				Verbs: []string{
					"get", "list", "watch", "create", "update", "patch", "delete",
				},
			},
		}))
	})

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component := render.IntrusionDetection(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind()).NotTo(Equal("PodSecurityPolicy"))
		}
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

	Context("allow-tigera rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "allow-tigera.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"},
			{Name: "allow-tigera.intrusion-detection-elastic", Namespace: "tigera-intrusion-detection"},
			{Name: "allow-tigera.anomaly-detection-api", Namespace: "tigera-intrusion-detection"},
			{Name: "allow-tigera.anomaly-detectors", Namespace: "tigera-intrusion-detection"},
		}

		getExpectedPolicy := func(policyName types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if policyName.Name == "allow-tigera.intrusion-detection-controller" {
				return testutils.SelectPolicyByClusterTypeAndProvider(scenario,
					expectedIDPolicyForUnmanaged,
					expectedIDPolicyForUnmanagedOCP,
					expectedIDPolicyForManaged,
					expectedIDPolicyForManagedOCP,
				)
			} else if !scenario.ManagedCluster && policyName.Name == "allow-tigera.intrusion-detection-elastic" {
				return testutils.SelectPolicyByProvider(scenario, expectedIDInstallerPolicy, expectedIDInstallerPolicyForOCP)
			} else if !scenario.ManagedCluster && policyName.Name == "allow-tigera.anomaly-detection-api" {
				return testutils.SelectPolicyByProvider(scenario, expectedAnomalyDetectionAPIPolicy, expectedAnomalyDetectionAPIPolicyForOCP)
			} else if !scenario.ManagedCluster && policyName.Name == "allow-tigera.anomaly-detectors" {
				return testutils.SelectPolicyByProvider(scenario, expectedAnomalyDetectorsPolicy, expectedAnomalyDetectorsPolicyForOCP)
			}

			return nil
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.Openshift = scenario.Openshift
				cfg.ManagedCluster = scenario.ManagedCluster
				component := render.IntrusionDetection(cfg)
				resources, _ := component.Objects()

				for _, policyName := range policyNames {
					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}),
		)
	})
})

func assertEnvVarlistMatch(envVars []corev1.EnvVar, expectedEnvVars []expectedEnvVar) {
	for _, expected := range expectedEnvVars {
		if expected.val != "" {
			Expect(envVars).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
		} else {
			Expect(envVars).To(ContainElement(corev1.EnvVar{
				Name: expected.name,
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
						Key:                  expected.secretKey,
					},
				},
			}))
		}
	}
}
