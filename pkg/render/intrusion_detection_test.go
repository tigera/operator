// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/secret"

	"github.com/tigera/operator/pkg/common"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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
	var (
		cfg     *render.IntrusionDetectionConfiguration
		bundle  certificatemanagement.TrustedBundle
		keyPair certificatemanagement.KeyPairInterface
		cli     client.Client
	)

	expectedIDPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_unmanaged.json")
	expectedIDPolicyForManaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_managed.json")
	expectedIDPolicyForUnmanagedOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_unmanaged_ocp.json")
	expectedIDPolicyForManagedOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-controller_managed_ocp.json")
	expectedIDInstallerPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-elastic.json")
	expectedIDInstallerPolicyForOCP := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/intrusion-detection-elastic_ocp.json")

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		secretTLS, err := certificatemanagement.CreateSelfSignedSecret(render.IntrusionDetectionTLSSecretName, "", "", nil)
		Expect(err).NotTo(HaveOccurred())
		keyPair = certificatemanagement.NewKeyPair(secretTLS, []string{""}, "")

		bundle = certificateManager.CreateTrustedBundle()

		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		cfg = &render.IntrusionDetectionConfiguration{
			TrustedCertBundle:            bundle,
			IntrusionDetectionCertSecret: keyPair,
			Installation:                 &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			ESClusterConfig:              relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1),
			ClusterDomain:                dns.DefaultClusterDomain,
			ESLicenseType:                render.ElasticsearchLicenseTypeUnknown,
			ManagedCluster:               notManagedCluster,
			UsePSP:                       true,
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
			{name: "allow-tigera.intrusion-detection-elastic", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		Expect(resources).To(HaveLen(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)

			if expectedRes.kind == "GlobalAlertTemplate" {
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		// Should mount ManagerTLSSecret for non-managed clusters
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		idji := rtest.GetResource(resources, "intrusion-detection-es-job-installer", render.IntrusionDetectionNamespace, "batch", "v1", "Job").(*batchv1.Job)
		Expect(idc.Spec.Template.Spec.Containers).To(HaveLen(2))
		idcExpectedEnvVars := []corev1.EnvVar{
			{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "FIPS_MODE_ENABLED", Value: "false"},
			{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			{Name: "LINSEED_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "LINSEED_CLIENT_CERT", Value: "/intrusion-detection-tls/tls.crt"},
			{Name: "LINSEED_CLIENT_KEY", Value: "/intrusion-detection-tls/tls.key"},
			{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
			{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
			{Name: "ELASTIC_USER", ValueFrom: secret.GetEnvVarSource(render.ElasticsearchIntrusionDetectionUserSecret, "username", false)},
			{Name: "ELASTIC_PASSWORD", ValueFrom: secret.GetEnvVarSource(render.ElasticsearchIntrusionDetectionUserSecret, "password", false)},
			{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
			{Name: "ELASTIC_PORT", Value: "9200"},
			{Name: "ELASTIC_SCHEME", Value: "https"},
			{Name: "ELASTIC_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		}
		Expect(idc.Spec.Template.Spec.Containers[0].Env).To(Equal(idcExpectedEnvVars))

		Expect(idji.Spec.Template.Spec.Containers).To(HaveLen(1))
		idjiExpectedEnvVars := []corev1.EnvVar{
			{Name: "KIBANA_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
			{Name: "KIBANA_PORT", Value: "5601", ValueFrom: nil},
			{Name: "KIBANA_SCHEME", Value: "https"},
			{Name: "START_XPACK_TRIAL", Value: "false"},
			{
				Name: "USER", ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-ee-installer-elasticsearch-access",
						},
						Key: "username",
					},
				},
			},
			{
				Name: "PASSWORD", ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-ee-installer-elasticsearch-access",
						},
						Key: "password",
					},
				},
			},
			{Name: "KB_CA_CERT", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "FIPS_MODE_ENABLED", Value: "false"},
			{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
			{Name: "ELASTIC_USER", ValueFrom: secret.GetEnvVarSource(render.ElasticsearchIntrusionDetectionJobUserSecret, "username", false)},
			{Name: "ELASTIC_PASSWORD", ValueFrom: secret.GetEnvVarSource(render.ElasticsearchIntrusionDetectionJobUserSecret, "password", false)},
		}
		Expect(idji.Spec.Template.Spec.Containers[0].Env).To(Equal(idjiExpectedEnvVars))

		Expect(*idji.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*idji.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*idji.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*idji.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*idji.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(idji.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(idji.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(2))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("intrusion-detection-tls"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/intrusion-detection-tls"))

		Expect(idc.Spec.Template.Spec.Volumes).To(HaveLen(2))
		Expect(idc.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.IntrusionDetectionTLSSecretName))
		Expect(idc.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.IntrusionDetectionTLSSecretName))

		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(idc.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(idc.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.Privileged).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*idc.Spec.Template.Spec.Containers[1].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(idc.Spec.Template.Spec.Containers[1].SecurityContext.Capabilities).To(Equal(&corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}))
		Expect(idc.Spec.Template.Spec.Containers[1].SecurityContext.SeccompProfile).To(Equal(&corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}))

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
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets", "configmaps"},
				Verbs:     []string{"get", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"securityeventwebhooks"},
				Verbs:     []string{"get", "watch", "update"},
			},
		))

		role := rtest.GetResource(resources, render.IntrusionDetectionName, render.IntrusionDetectionNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(role.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get"},
			},
			rbacv1.PolicyRule{
				// Intrusion detection forwarder snapshots its state to a specific ConfigMap.
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "create", "update"},
			},
		))

		roleBinding := rtest.GetResource(resources, render.IntrusionDetectionName, render.IntrusionDetectionNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(roleBinding.RoleRef.Name).To(Equal(render.IntrusionDetectionName))
		Expect(roleBinding.RoleRef.Kind).To(Equal("Role"))
		Expect(roleBinding.RoleRef.APIGroup).To(Equal("rbac.authorization.k8s.io"))
		Expect(roleBinding.Subjects).To(ContainElements(
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      render.IntrusionDetectionName,
				Namespace: render.IntrusionDetectionNamespace,
			},
		))
	})

	It("should render finalizers rbac resources in the IDS ClusterRole for an Openshift management/standalone cluster", func() {
		cfg.Openshift = openshift
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
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
			{name: "allow-tigera.intrusion-detection-elastic", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		Expect(resources).To(HaveLen(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			if expectedRes.kind == "GlobalAlertTemplate" {
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		dp := rtest.GetResource(resources, "intrusion-detection-controller", "tigera-intrusion-detection", "apps", "v1", "Deployment").(*appsv1.Deployment)
		envs := dp.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []expectedEnvVar{
			{"MULTI_CLUSTER_FORWARDING_CA", cfg.TrustedCertBundle.MountPath(), "", ""},
			{"IDS_ENABLE_EVENT_FORWARDING", "true", "", ""},
		}

		assertEnvVarlistMatch(envs, expectedEnvs)

		// Validate that even with syslog configured we still have the CA configmap Volume
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Volumes).To(HaveLen(3))
		Expect(idc.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Volumes[0].ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(idc.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.IntrusionDetectionTLSSecretName))
		Expect(idc.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.IntrusionDetectionTLSSecretName))
		Expect(idc.Spec.Template.Spec.Volumes[2].Name).To(Equal("var-log-calico"))
		Expect(idc.Spec.Template.Spec.Volumes[2].VolumeSource.HostPath.Path).To(Equal("/var/log/calico"))

		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*idc.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(idc.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(idc.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
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
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "tigera-linseed", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
		}

		Expect(resources).To(HaveLen(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			if expectedRes.kind == "GlobalAlertTemplate" {
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Containers[0].Env).To(ContainElements(
			corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: cfg.TrustedCertBundle.MountPath()},
			corev1.EnvVar{Name: "DISABLE_ALERTS", Value: "yes"},
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
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
		}
	})

	It("should apply controlPlaneNodeSelector correctly", func() {
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
		}
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

	It("should not render es-job installer when FIPS mode is enabled", func() {
		fipsEnabled := operatorv1.FIPSModeEnabled
		testADStorageClassName := "test-storage-class-name"
		cfg.Installation.FIPSMode = &fipsEnabled
		cfg.IntrusionDetection = operatorv1.IntrusionDetection{
			Spec: operatorv1.IntrusionDetectionSpec{
				AnomalyDetection: operatorv1.AnomalyDetectionSpec{
					StorageClassName: testADStorageClassName,
				},
			},
		}
		component := render.IntrusionDetection(cfg)
		toCreate, toRemove := component.Objects()

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
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "intrusion-detection-psp", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "intrusion-detection", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		Expect(toCreate).To(HaveLen(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(toCreate[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)

			if expectedRes.kind == "GlobalAlertTemplate" {
				rtest.ExpectGlobalAlertTemplateToBePopulated(toCreate[i])
			}
		}

		expectedResourcesToRemove := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera.io.detector.dga", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.dga", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.http-connection-spike", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-connection-spike", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.http-response-codes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-response-codes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.http-verbs", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.http-verbs", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.port-scan", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.port-scan", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.generic-dns", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-dns", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.generic-flows", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-flows", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.multivariable-flow", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.multivariable-flow", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.generic-l7", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.generic-l7", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.dns-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.dns-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.dns-tunnel", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.dns-tunnel", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.l7-bytes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.l7-bytes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.l7-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.l7-latency", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.bytes-in", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.bytes-in", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.bytes-out", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.bytes-out", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.process-bytes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.process-bytes", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "tigera.io.detector.process-restarts", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlertTemplate"},
			{name: "tigera.io.detector.process-restarts", ns: "", group: "projectcalico.org", version: "v3", kind: "GlobalAlert"},
			{name: "allow-tigera.anomaly-detection-api", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "anomaly-detection-api", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "anomaly-detection-api", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "anomaly-detection-api", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-anomaly-detection", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "PersistentVolumeClaim"},
			{name: "anomaly-detection-api", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Service"},
			{name: "anomaly-detection-api", ns: "tigera-intrusion-detection", group: "apps", version: "v1", kind: "Deployment"},
			{name: "allow-tigera.anomaly-detectors", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Secret"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "anomaly-detectors", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "anomaly-detectors", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "anomaly-detectors", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera.io.detectors.training", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "PodTemplate"},
			{name: "tigera.io.detectors.detection", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "PodTemplate"},
			{name: "anomaly-detection-api", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "allow-tigera.intrusion-detection-elastic", ns: "tigera-intrusion-detection", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "intrusion-detection-es-job-installer", ns: "tigera-intrusion-detection", group: "batch", version: "v1", kind: "Job"},
			{name: "tigera-linseed", ns: "tigera-intrusion-detection", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
		}

		Expect(toRemove).To(HaveLen(len(expectedResourcesToRemove)))

		for i, expectedRes := range expectedResourcesToRemove {
			rtest.ExpectResourceTypeAndObjectMetadata(toRemove[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render an init container for pods when certificate management is enabled", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		intrusionDetectionCertSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.IntrusionDetectionTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg.IntrusionDetectionCertSecret = intrusionDetectionCertSecret

		component := render.IntrusionDetection(cfg)
		toCreate, _ := component.Objects()

		intrusionDetectionDeploy := rtest.GetResource(toCreate, "intrusion-detection-controller", "tigera-intrusion-detection", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(intrusionDetectionDeploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := intrusionDetectionDeploy.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.IntrusionDetectionTLSSecretName)))
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
