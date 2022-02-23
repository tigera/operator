// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
)

var _ = Describe("Tigera Secure Manager rendering tests", func() {
	oidcEnvVar := corev1.EnvVar{
		Name:      "CNX_WEB_OIDC_AUTHORITY",
		Value:     "",
		ValueFrom: nil,
	}
	var replicas int32 = 2
	installation := &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas}
	const expectedResourcesNumber = 12

	expectedDNSNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, dns.DefaultClusterDomain)
	expectedDNSNames = append(expectedDNSNames, "localhost")

	It("should render all resources for a default configuration", func() {
		resources := renderObjects(false, nil, installation, true)

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: render.ManagerNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.ManagerServiceAccount, ns: render.ManagerNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ManagerClusterRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ManagerClusterRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ManagerUserSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerTLSSecretName, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-manager", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: render.ComplianceServerCertSecret, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.PacketCaptureCertSecret, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.PrometheusTLSSecretName, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "apps", version: "v1", kind: "Deployment"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
		Expect(len(resources)).To(Equal(expectedResourcesNumber))

		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(len(deployment.Spec.Template.Spec.Containers)).Should(Equal(3))
		var manager = deployment.Spec.Template.Spec.Containers[0]
		var esProxy = deployment.Spec.Template.Spec.Containers[1]
		var voltron = deployment.Spec.Template.Spec.Containers[2]

		Expect(manager.Image).Should(Equal(components.TigeraRegistry + "tigera/cnx-manager:" + components.ComponentManager.Version))
		Expect(esProxy.Image).Should(Equal(components.TigeraRegistry + "tigera/es-proxy:" + components.ComponentEsProxy.Version))
		Expect(voltron.Image).Should(Equal(components.TigeraRegistry + "tigera/voltron:" + components.ComponentManagerProxy.Version))

		Expect(esProxy.Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
		))
		Expect(len(esProxy.VolumeMounts)).To(Equal(1))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/etc/ssl/elastic/"))

		Expect(len(voltron.VolumeMounts)).To(Equal(5))
		Expect(voltron.VolumeMounts[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/certs/https"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/certs/kibana"))
		Expect(voltron.VolumeMounts[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(voltron.VolumeMounts[2].MountPath).To(Equal("/certs/compliance"))
		Expect(voltron.VolumeMounts[3].Name).To(Equal(render.PacketCaptureCertSecret))
		Expect(voltron.VolumeMounts[3].MountPath).To(Equal("/certs/packetcapture"))
		Expect(voltron.VolumeMounts[4].Name).To(Equal(render.PrometheusTLSSecretName))
		Expect(voltron.VolumeMounts[4].MountPath).To(Equal("/certs/prometheus"))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(6))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.KibanaPublicCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ComplianceServerCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Name).To(Equal(render.PacketCaptureCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Secret.SecretName).To(Equal(render.PacketCaptureCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Name).To(Equal(render.PrometheusTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Secret.SecretName).To(Equal(render.PrometheusTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[5].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(deployment.Spec.Template.Spec.Volumes[5].Secret.SecretName).To(Equal(relasticsearch.PublicCertSecret))
	})

	It("should ensure cnx policy recommendation support is always set to true", func() {
		resources := renderObjects(false, nil, installation, true)
		Expect(len(resources)).To(Equal(expectedResourcesNumber))

		// Should render the correct resource based on test case.
		Expect(rtest.GetResource(resources, "tigera-manager", "tigera-manager", "apps", "v1", "Deployment")).ToNot(BeNil())

		d := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("tigera-manager"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[8].Name).To(Equal("CNX_POLICY_RECOMMENDATION_SUPPORT"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[8].Value).To(Equal("true"))

		clusterRole := rtest.GetResource(resources, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"networksets",
					"globalnetworksets",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"hostendpoints",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"felixconfigurations",
				},
				ResourceNames: []string{
					"default",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces", "nodes", "events", "services", "pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch", "update"},
			},
			{
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"tigera-manager"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		}))
	})

	It("should set OIDC Authority environment when auth-type is OIDC", func() {
		const authority = "https://127.0.0.1/dex"
		oidcEnvVar.Value = authority

		// Should render the correct resource based on test case.
		resources := renderObjects(true, nil, installation, true)
		Expect(len(resources)).To(Equal(expectedResourcesNumber + 1)) //Extra tls secret was added.
		d := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		// tigera-manager volumes/volumeMounts checks.
		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(7))
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(oidcEnvVar))
		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(2))
	})

	It("should render multicluster settings properly", func() {
		resources := renderObjects(false, &operatorv1.ManagementCluster{}, installation, true)

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-manager", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-manager-role", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-manager-binding", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ManagerUserSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: "manager-tls", ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: render.VoltronTunnelSecretName, ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: render.ManagerInternalTLSSecretName, ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "Service"},
			{name: "tigera-manager", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: render.ComplianceServerCertSecret, ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: render.PacketCaptureCertSecret, ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: render.PrometheusTLSSecretName, ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: "tigera-manager", group: "apps", version: "v1", kind: "Deployment"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		By("configuring the manager deployment")
		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		manager := deployment.Spec.Template.Spec.Containers[0]
		Expect(manager.Name).To(Equal("tigera-manager"))
		rtest.ExpectEnv(manager.Env, "ENABLE_MULTI_CLUSTER_MANAGEMENT", "true")

		voltron := deployment.Spec.Template.Spec.Containers[2]
		esProxy := deployment.Spec.Template.Spec.Containers[1]
		Expect(voltron.Name).To(Equal("tigera-voltron"))
		rtest.ExpectEnv(voltron.Env, "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", "true")

		Expect(len(esProxy.VolumeMounts)).To(Equal(2))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretCertName))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/manager-tls"))
		Expect(esProxy.VolumeMounts[1].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(esProxy.VolumeMounts[1].MountPath).To(Equal("/etc/ssl/elastic/"))

		Expect(len(voltron.VolumeMounts)).To(Equal(7))
		Expect(voltron.VolumeMounts[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/certs/https"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/certs/kibana"))
		Expect(voltron.VolumeMounts[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(voltron.VolumeMounts[2].MountPath).To(Equal("/certs/compliance"))
		Expect(voltron.VolumeMounts[3].Name).To(Equal(render.PacketCaptureCertSecret))
		Expect(voltron.VolumeMounts[3].MountPath).To(Equal("/certs/packetcapture"))
		Expect(voltron.VolumeMounts[4].Name).To(Equal(render.PrometheusTLSSecretName))
		Expect(voltron.VolumeMounts[4].MountPath).To(Equal("/certs/prometheus"))
		Expect(voltron.VolumeMounts[5].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(voltron.VolumeMounts[5].MountPath).To(Equal("/certs/internal"))
		Expect(voltron.VolumeMounts[6].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(voltron.VolumeMounts[6].MountPath).To(Equal("/certs/tunnel"))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(9))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.KibanaPublicCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ComplianceServerCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Name).To(Equal(render.PacketCaptureCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Secret.SecretName).To(Equal(render.PacketCaptureCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Name).To(Equal(render.PrometheusTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Secret.SecretName).To(Equal(render.PrometheusTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[5].Name).To(Equal(render.ManagerInternalTLSSecretCertName))
		Expect(deployment.Spec.Template.Spec.Volumes[5].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[6].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[6].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[7].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[7].Secret.SecretName).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[8].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(deployment.Spec.Template.Spec.Volumes[8].Secret.SecretName).To(Equal(relasticsearch.PublicCertSecret))

		clusterRole := rtest.GetResource(resources, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"networksets",
					"globalnetworksets",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"hostendpoints",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"felixconfigurations",
				},
				ResourceNames: []string{
					"default",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces", "nodes", "events", "services", "pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch", "update"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"tigera-manager"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		}))
	})

	// renderManager passes in as few parameters as possible to render.Manager without it
	// panicing. It accepts variations on the installspec for testing purposes.
	renderManager := func(i *operatorv1.InstallationSpec) *appsv1.Deployment {
		cfg := &render.ManagerConfiguration{
			ComplianceServerCertSecret:    rtest.CreateCertSecret(render.ComplianceServerCertSecret, common.OperatorNamespace()),
			PacketCaptureServerCertSecret: rtest.CreateCertSecret(render.PacketCaptureCertSecret, common.OperatorNamespace()),
			PrometheusCertSecret:          rtest.CreateCertSecret(render.PrometheusTLSSecretName, common.OperatorNamespace()),
			ESClusterConfig:               &relasticsearch.ClusterConfig{},
			TLSKeyPair:                    rtest.CreateCertSecret(render.ManagerTLSSecretName, common.OperatorNamespace()),
			Installation:                  i,
			ESLicenseType:                 render.ElasticsearchLicenseTypeUnknown,
			Replicas:                      &replicas,
		}
		component, err := render.Manager(cfg)
		Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
		resources, _ := component.Objects()
		return rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
	}

	It("should apply controlPlaneNodeSelectors", func() {
		deployment := renderManager(&operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{
				"foo": "bar",
			},
			ControlPlaneReplicas: &replicas,
		})
		Expect(deployment.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
	})

	It("should apply controlPlaneTolerations", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		deployment := renderManager(&operatorv1.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
			ControlPlaneReplicas:    &replicas,
		})
		Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElements(t, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly))
	})

	It("should render all resources for certificate management", func() {
		resources := renderObjects(false, nil, &operatorv1.InstallationSpec{
			CertificateManagement: &operatorv1.CertificateManagement{},
			ControlPlaneReplicas:  &replicas,
		}, false)

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: render.ManagerNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.ManagerServiceAccount, ns: render.ManagerNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ManagerClusterRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ManagerClusterRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ManagerUserSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-manager", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: render.ComplianceServerCertSecret, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.PacketCaptureCertSecret, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.PrometheusTLSSecretName, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{"tigera-manager:csr-creator", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"},
		}

		Expect(resources).To(HaveLen(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(deployment.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := deployment.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(render.CSRInitContainerName))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(6))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret).To(BeNil())
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		installation.ControlPlaneReplicas = &replicas

		resources := renderObjects(false, nil, &operatorv1.InstallationSpec{
			CertificateManagement: &operatorv1.CertificateManagement{},
			ControlPlaneReplicas:  &replicas,
		}, false)
		deploy, ok := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		installation.ControlPlaneReplicas = &replicas

		resources := renderObjects(false, nil, &operatorv1.InstallationSpec{
			CertificateManagement: &operatorv1.CertificateManagement{},
			ControlPlaneReplicas:  &replicas,
		}, false)
		deploy, ok := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-manager", render.ManagerNamespace)))
	})

	It("should not render an user supplied manager TLS certificate", func() {

		resources := renderObjects(false, nil, &operatorv1.InstallationSpec{}, true)
		secret, ok := rtest.GetResource(resources, render.ManagerTLSSecretName, common.OperatorNamespace(), "", "v1", "Secret").(*corev1.Secret)
		Expect(secret).To(BeNil())

		secret, ok = rtest.GetResource(resources, render.ManagerTLSSecretName, render.ManagerNamespace, "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue())
		Expect(secret).ToNot(BeNil())
	})
})

func renderObjects(oidc bool, managementCluster *operatorv1.ManagementCluster, installation *operatorv1.InstallationSpec, includeManagerTLSSecret bool) []client.Object {
	var dexCfg authentication.KeyValidatorConfig
	if oidc {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"}}}

		dexCfg = render.NewDexKeyValidatorConfig(authentication, nil, render.CreateDexTLSSecret("cn"), dns.DefaultClusterDomain)
	}

	var tunnelSecret *corev1.Secret
	var internalTraffic *corev1.Secret
	if managementCluster != nil {
		tunnelSecret = &testutils.VoltronTunnelSecret
		internalTraffic = &testutils.InternalManagerTLSSecret
	}
	var managerTLS *corev1.Secret
	if includeManagerTLSSecret {
		managerTLS = rtest.CreateCertSecret(render.ManagerTLSSecretName, common.OperatorNamespace())
	}

	esConfigMap := relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)

	cfg := &render.ManagerConfiguration{
		KeyValidatorConfig:            dexCfg,
		ComplianceServerCertSecret:    rtest.CreateCertSecret(render.ComplianceServerCertSecret, common.OperatorNamespace()),
		PacketCaptureServerCertSecret: rtest.CreateCertSecret(render.PacketCaptureCertSecret, common.OperatorNamespace()),
		PrometheusCertSecret:          rtest.CreateCertSecret(render.PrometheusTLSSecretName, common.OperatorNamespace()),
		ESClusterConfig:               esConfigMap,
		TLSKeyPair:                    managerTLS,
		Installation:                  installation,
		ManagementCluster:             managementCluster,
		TunnelSecret:                  tunnelSecret,
		InternalTrafficSecret:         internalTraffic,
		ClusterDomain:                 dns.DefaultClusterDomain,
		ESLicenseType:                 render.ElasticsearchLicenseTypeEnterpriseTrial,
		Replicas:                      installation.ControlPlaneReplicas,
	}
	component, err := render.Manager(cfg)
	Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
	Expect(component.ResolveImages(nil)).To(BeNil())
	resources, _ := component.Objects()
	return resources
}
