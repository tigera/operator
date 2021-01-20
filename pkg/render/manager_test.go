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
	"github.com/tigera/operator/pkg/components"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Tigera Secure Manager rendering tests", func() {
	oidcEnvVar := corev1.EnvVar{
		Name:      "CNX_WEB_OIDC_AUTHORITY",
		Value:     "",
		ValueFrom: nil,
	}

	const expectedResourcesNumber = 10
	It("should render all resources for a default configuration", func() {
		resources := renderObjects(false, nil, nil)
		Expect(len(resources)).To(Equal(expectedResourcesNumber))

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
			{name: render.ManagerTLSSecretName, ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: render.ManagerTLSSecretName, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-manager", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: render.ComplianceServerCertSecret, ns: render.ManagerNamespace, group: "", version: "", kind: ""},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "", version: "v1", kind: "Deployment"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		deployment := GetResource(resources, "tigera-manager", render.ManagerNamespace, "", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment.Spec.Template.Spec.Containers[0].Image).Should(Equal(components.TigeraRegistry + "tigera/cnx-manager:" + components.ComponentManager.Version))
		Expect(deployment.Spec.Template.Spec.Containers[1].Image).Should(Equal(components.TigeraRegistry + "tigera/es-proxy:" + components.ComponentEsProxy.Version))
		Expect(deployment.Spec.Template.Spec.Containers[2].Image).Should(Equal(components.TigeraRegistry + "tigera/voltron:" + components.ComponentManagerProxy.Version))

		// Expect 1 volume mounts for es proxy
		var esProxy = deployment.Spec.Template.Spec.Containers[1]
		Expect(len(esProxy.VolumeMounts)).To(Equal(1))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/etc/ssl/elastic/"))

		// Expect 3 volume mounts for voltron
		var voltron = deployment.Spec.Template.Spec.Containers[2]
		Expect(len(voltron.VolumeMounts)).To(Equal(3))
		Expect(voltron.VolumeMounts[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/certs/https"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/certs/kibana"))
		Expect(voltron.VolumeMounts[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(voltron.VolumeMounts[2].MountPath).To(Equal("/certs/compliance"))

		//Expect 4 volumes mapped to 4 secrets
		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(4))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.KibanaPublicCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ComplianceServerCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Secret.SecretName).To(Equal(render.ElasticsearchPublicCertSecret))
	})

	It("should ensure cnx policy recommendation support is always set to true", func() {
		resources := renderObjects(false, nil, nil)
		Expect(len(resources)).To(Equal(expectedResourcesNumber))

		// Should render the correct resource based on test case.
		Expect(GetResource(resources, "tigera-manager", "tigera-manager", "", "v1", "Deployment")).ToNot(BeNil())

		d := GetResource(resources, "tigera-manager", render.ManagerNamespace, "", "v1", "Deployment").(*appsv1.Deployment)

		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("tigera-manager"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[8].Name).To(Equal("CNX_POLICY_RECOMMENDATION_SUPPORT"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[8].Value).To(Equal("true"))

		clusterRole := GetResource(resources, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
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
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces"},
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
		resources := renderObjects(true, nil, nil)
		Expect(len(resources)).To(Equal(expectedResourcesNumber + 1)) //Extra tls secret was added.
		d := GetResource(resources, "tigera-manager", render.ManagerNamespace, "", "v1", "Deployment").(*appsv1.Deployment)
		// tigera-manager volumes/volumeMounts checks.
		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(5))
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(oidcEnvVar))
		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
	})

	It("should render multicluster settings properly", func() {
		resources := renderObjects(false, &operator.ManagementCluster{}, nil)

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
			{name: "manager-tls", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "manager-tls", ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: render.VoltronTunnelSecretName, ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: render.ManagerInternalTLSSecretName, ns: "tigera-manager", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "Service"},
			{name: "tigera-manager", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: render.ComplianceServerCertSecret, ns: "tigera-manager", group: "", version: "", kind: ""},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "Deployment"},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		By("configuring the manager deployment")
		deployment := GetResource(resources, "tigera-manager", render.ManagerNamespace, "", "v1", "Deployment").(*appsv1.Deployment)
		manager := deployment.Spec.Template.Spec.Containers[0]
		Expect(manager.Name).To(Equal("tigera-manager"))
		ExpectEnv(manager.Env, "ENABLE_MULTI_CLUSTER_MANAGEMENT", "true")

		voltron := deployment.Spec.Template.Spec.Containers[2]
		esProxy := deployment.Spec.Template.Spec.Containers[1]
		Expect(voltron.Name).To(Equal("tigera-voltron"))
		ExpectEnv(voltron.Env, "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", "true")

		// Expect 2 volume mounts for es proxy
		Expect(len(esProxy.VolumeMounts)).To(Equal(2))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal(render.ManagerInternalTLSSecretCertName))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/manager-tls"))
		Expect(esProxy.VolumeMounts[1].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(esProxy.VolumeMounts[1].MountPath).To(Equal("/etc/ssl/elastic/"))

		// Expect 5 volume mounts for voltron
		Expect(len(voltron.VolumeMounts)).To(Equal(5))
		Expect(voltron.VolumeMounts[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/certs/https"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/certs/kibana"))
		Expect(voltron.VolumeMounts[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(voltron.VolumeMounts[2].MountPath).To(Equal("/certs/compliance"))
		Expect(voltron.VolumeMounts[3].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(voltron.VolumeMounts[3].MountPath).To(Equal("/certs/internal"))
		Expect(voltron.VolumeMounts[4].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(voltron.VolumeMounts[4].MountPath).To(Equal("/certs/tunnel"))

		// Expect 7 volumes mapped to 6 secrets
		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(7))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.KibanaPublicCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ComplianceServerCertSecret))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Name).To(Equal(render.ManagerInternalTLSSecretCertName))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[5].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[5].Secret.SecretName).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[6].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(deployment.Spec.Template.Spec.Volumes[6].Secret.SecretName).To(Equal(render.ElasticsearchPublicCertSecret))

		clusterRole := GetResource(resources, render.ManagerClusterRole, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
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
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch", "update"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"authenticationreviews"},
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
})

func renderObjects(oidc bool, managementCluster *operator.ManagementCluster,
	tlsSecret *corev1.Secret) []runtime.Object {
	var dexCfg render.DexKeyValidatorConfig
	if oidc {
		var authentication *operator.Authentication
		authentication = &operator.Authentication{
			Spec: operator.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operator.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"}}}

		dexCfg = render.NewDexKeyValidatorConfig(authentication, render.CreateDexTLSSecret())
	}

	var tunnelSecret *corev1.Secret
	var internalTraffic *corev1.Secret
	if managementCluster != nil {
		tunnelSecret = &voltronTunnelSecret
		internalTraffic = &internalManagerTLSSecret
	}
	esConfigMap := render.NewElasticsearchClusterConfig("clusterTestName", 1, 1, 1)
	component, err := render.Manager(dexCfg,
		nil,
		nil,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ComplianceServerCertSecret,
				Namespace: render.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"tls.crt": []byte("crt"),
				"tls.key": []byte("crt"),
			},
		},
		esConfigMap,
		tlsSecret,
		nil,
		false,
		&operator.InstallationSpec{},
		managementCluster,
		tunnelSecret,
		internalTraffic)
	Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
	resources, _ := component.Objects()
	return resources
}
