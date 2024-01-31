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

	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	"github.com/tigera/operator/pkg/common"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			ClusterDomain:                dns.DefaultClusterDomain,
			ESLicenseType:                render.ElasticsearchLicenseTypeUnknown,
			ManagedCluster:               notManagedCluster,
			Namespace:                    render.IntrusionDetectionNamespace,
			BindNamespaces:               []string{"tigera-intrusion-detection"},
			Tenant:                       nil,
		}
	})

	It("should render all resources for a default configuration", func() {
		cfg.Openshift = notOpenshift
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		expected := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.pod"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkpolicy"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkset"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.serviceaccount"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.cloudapi"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.ssh"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.access"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.originate"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.servfail"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.dos"}},
		}
		rtest.ExpectResources(resources, expected)

		// Check that GlobalAlertTemplates are populated
		for i, res := range resources {
			switch res.(type) {
			case *v3.GlobalAlertTemplate:
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		// Should mount ManagerTLSSecret for non-managed clusters
		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(idc.Spec.Template.Spec.Containers).To(HaveLen(2))
		idcExpectedEnvVars := []corev1.EnvVar{
			{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "FIPS_MODE_ENABLED", Value: "false"},
			{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			{Name: "LINSEED_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "LINSEED_CLIENT_CERT", Value: "/intrusion-detection-tls/tls.crt"},
			{Name: "LINSEED_CLIENT_KEY", Value: "/intrusion-detection-tls/tls.key"},
			{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		}
		Expect(idc.Spec.Template.Spec.Containers[0].Env).To(Equal(idcExpectedEnvVars))
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

		expected := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.pod"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkpolicy"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkset"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.serviceaccount"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.cloudapi"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.ssh"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.access"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.originate"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.servfail"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.dos"}},
		}
		rtest.ExpectResources(resources, expected)

		// Check that GlobalAlertTemplates are populated
		for i, res := range resources {
			switch res.(type) {
			case *v3.GlobalAlertTemplate:
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

	It("should disable GlobalAlert controller when cluster is managed", func() {
		cfg.Openshift = notOpenshift
		cfg.ManagedCluster = managedCluster

		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		expected := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.pod"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkpolicy"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkset"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.serviceaccount"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.cloudapi"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.ssh"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.access"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.originate"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.servfail"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.dos"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: "tigera-intrusion-detection"}},
		}
		rtest.ExpectResources(resources, expected)

		// Check that GlobalAlertTemplates are populated
		for i, res := range resources {
			switch res.(type) {
			case *v3.GlobalAlertTemplate:
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
		Expect(idc.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
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
		Expect(idc.Spec.Template.Spec.Tolerations).To(ConsistOf(t))
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

		expected := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: "tigera-intrusion-detection"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.pod"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkpolicy"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.globalnetworkset"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "policy.serviceaccount"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.cloudapi"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.ssh"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.access"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "network.lateral.originate"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.servfail"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "dns.dos"}},
		}
		rtest.ExpectResources(toCreate, expected)

		// Check that GlobalAlertTemplates are populated
		for i, res := range toCreate {
			switch res.(type) {
			case *v3.GlobalAlertTemplate:
				rtest.ExpectGlobalAlertTemplateToBePopulated(toCreate[i])
			}
		}

		expectedDeletes := []client.Object{
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.dga"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.dga"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.http-connection-spike"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.http-connection-spike"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.http-response-codes"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.http-response-codes"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.http-verbs"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.http-verbs"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.port-scan"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.port-scan"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.generic-dns"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.generic-dns"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.generic-flows"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.generic-flows"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.multivariable-flow"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.multivariable-flow"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.generic-l7"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.generic-l7"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.dns-latency"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.dns-latency"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.dns-tunnel"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.dns-tunnel"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.l7-bytes"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.l7-bytes"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.l7-latency"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.l7-latency"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.bytes-in"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.bytes-in"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.bytes-out"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.bytes-out"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.process-bytes"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.process-bytes"}},
			&v3.GlobalAlertTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.process-restarts"}},
			&v3.GlobalAlert{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detector.process-restarts"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.anomaly-detection-api", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detection-api", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detection-api"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detection-api"}},
			&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "tigera-anomaly-detection", Namespace: "tigera-intrusion-detection"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detection-api", Namespace: "tigera-intrusion-detection"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detection-api", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.anomaly-detectors", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detectors", Namespace: "tigera-intrusion-detection"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detectors", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detectors", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detectors"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detectors", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "anomaly-detectors"}},
			&corev1.PodTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detectors.training", Namespace: "tigera-intrusion-detection"}},
			&corev1.PodTemplate{ObjectMeta: metav1.ObjectMeta{Name: "tigera.io.detectors.detection", Namespace: "tigera-intrusion-detection"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.intrusion-detection-elastic", Namespace: "tigera-intrusion-detection"}},
			&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-es-job-installer", Namespace: "tigera-intrusion-detection"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-es-job-installer", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: "tigera-intrusion-detection"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-psp"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-psp"}},
		}

		rtest.ExpectResources(toRemove, expectedDeletes)
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

	Context("multi-tenant rendering", func() {
		tenantANamespace := "tenant-a-ns"
		tenantBNamespace := "tenant-b-ns"
		var tenantA *operatorv1.Tenant

		BeforeEach(func() {
			// Configure a tenant.
			tenantA = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: tenantANamespace},
				Spec:       operatorv1.TenantSpec{},
			}
			cfg.Namespace = tenantANamespace
			cfg.BindNamespaces = []string{tenantANamespace, tenantBNamespace}
			cfg.Tenant = tenantA
		})

		It("should render multi-tenant resources", func() {
			component := render.IntrusionDetection(cfg)
			toCreate, _ := component.Objects()

			expected := []client.Object{
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.intrusion-detection-controller", Namespace: tenantANamespace}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: tenantANamespace}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: tenantANamespace}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller"}},
				&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: tenantANamespace}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: tenantANamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-controller", Namespace: tenantANamespace}},
			}
			rtest.ExpectResources(toCreate, expected)

			netpol, err := rtest.GetResourceOfType[*v3.NetworkPolicy](toCreate, render.IntrusionDetectionControllerPolicyName, tenantANamespace)
			Expect(err).NotTo(HaveOccurred())

			Expect(netpol.Spec.Ingress).To(ConsistOf(v3.Rule{Action: v3.Deny}))

			expectedEgressRules := []v3.Rule{
				{
					Action:   v3.Deny,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Nets: []string{"169.254.0.0/16"},
					},
				},
				{
					Action:   v3.Deny,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Nets: []string{"fe80::/10"},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.UDPProtocol,
					Destination: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'kube-system'",
						Selector:          "k8s-app == 'kube-dns'",
						Ports:             networkpolicy.Ports(53),
					},
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Destination: networkpolicy.CreateEntityRule(tenantANamespace, "tigera-linseed", 8444),
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Destination: networkpolicy.KubeAPIServerEntityRule,
				},
				{
					Action: v3.Pass,
				},
			}
			Expect(netpol.Spec.Egress).To(ConsistOf(expectedEgressRules))
		})
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
