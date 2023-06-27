// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	networkpolicy "github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Tigera Secure Manager rendering tests", func() {
	oidcEnvVar := corev1.EnvVar{
		Name:      "CNX_WEB_OIDC_AUTHORITY",
		Value:     "",
		ValueFrom: nil,
	}
	var replicas int32 = 2
	installation := &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas}
	compliance := &operatorv1.Compliance{}
	const expectedResourcesNumber = 13

	expectedManagerPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/manager.json")
	expectedManagerOpenshiftPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/manager_ocp.json")

	It("should render all resources for a default configuration", func() {
		resources := renderObjects(renderConfig{oidc: false, managementCluster: nil, installation: installation, compliance: compliance, complianceFeatureActive: true})

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: render.ManagerNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.ManagerPolicyName, ns: "tigera-manager", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: networkpolicy.TigeraComponentDefaultDenyPolicyName, ns: "tigera-manager", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.ManagerServiceAccount, ns: render.ManagerNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ManagerClusterRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ManagerClusterRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ManagerClusterSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerUserSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerClusterSettingsLayerTigera, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettings"},
			{name: render.ManagerClusterSettingsViewDefault, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettings"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-manager", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "apps", version: "v1", kind: "Deployment"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
		Expect(resources).To(HaveLen(expectedResourcesNumber))

		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		// deployment
		Expect(deployment.Spec.Template.Spec.Volumes).To(HaveLen(2))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[1].VolumeSource.ConfigMap.Name).To(Equal("tigera-ca-bundle"))

		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(3))
		manager := deployment.Spec.Template.Spec.Containers[0]
		esProxy := deployment.Spec.Template.Spec.Containers[1]
		voltron := deployment.Spec.Template.Spec.Containers[2]

		Expect(manager.Image).Should(Equal(components.TigeraRegistry + "tigera/cnx-manager:" + components.ComponentManager.Version))
		Expect(esProxy.Image).Should(Equal(components.TigeraRegistry + "tigera/es-proxy:" + components.ComponentEsProxy.Version))
		Expect(voltron.Image).Should(Equal(components.TigeraRegistry + "tigera/voltron:" + components.ComponentManagerProxy.Version))

		// manager container
		Expect(*manager.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*manager.SecurityContext.Privileged).To(BeFalse())
		Expect(*manager.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*manager.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*manager.SecurityContext.RunAsUser).To(BeEquivalentTo(999))
		Expect(manager.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(manager.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		Expect(manager.Env).Should(ContainElements(
			corev1.EnvVar{Name: "ENABLE_COMPLIANCE_REPORTS", Value: "true"},
		))

		// es-proxy container
		Expect(esProxy.Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
		))

		Expect(esProxy.VolumeMounts).To(HaveLen(2))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(esProxy.VolumeMounts[1].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(esProxy.VolumeMounts[1].MountPath).To(Equal("/manager-tls"))

		Expect(*esProxy.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*esProxy.SecurityContext.Privileged).To(BeFalse())
		Expect(*esProxy.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*esProxy.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*esProxy.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(esProxy.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(esProxy.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// voltron container
		Expect(voltron.Env).To(ContainElements([]corev1.EnvVar{
			{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: "true"},
			{Name: "VOLTRON_QUERYSERVER_ENDPOINT", Value: "https://tigera-api.tigera-system.svc:8080"},
			{Name: "VOLTRON_QUERYSERVER_BASE_PATH", Value: "/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy/"},
			{Name: "VOLTRON_QUERYSERVER_CA_BUNDLE_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		}))

		Expect(voltron.VolumeMounts).To(HaveLen(2))
		Expect(voltron.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/manager-tls"))

		Expect(*voltron.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*voltron.SecurityContext.Privileged).To(BeFalse())
		Expect(*voltron.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*voltron.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*voltron.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(voltron.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(voltron.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		// Check the namespace.
		ns := rtest.GetResource(resources, "tigera-manager", "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(ns.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("restricted"))
		Expect(ns.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))
	})

	type managerComplianceExpectation struct {
		managerFlag bool
		voltronFlag bool
	}
	DescribeTable("should set container env appropriately when compliance is not fully available",
		func(crPresent bool, licenseFeatureActive bool, scenario managerComplianceExpectation) {
			var complianceCR *operatorv1.Compliance
			if crPresent {
				complianceCR = &operatorv1.Compliance{}
			}

			resources := renderObjects(renderConfig{
				oidc:                    false,
				managementCluster:       nil,
				installation:            installation,
				compliance:              complianceCR,
				complianceFeatureActive: licenseFeatureActive,
			})

			deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			manager := deployment.Spec.Template.Spec.Containers[0]
			voltron := deployment.Spec.Template.Spec.Containers[2]
			Expect(manager.Env).To(ContainElement(corev1.EnvVar{Name: "ENABLE_COMPLIANCE_REPORTS", Value: strconv.FormatBool(scenario.managerFlag)}))
			Expect(voltron.Env).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: strconv.FormatBool(scenario.voltronFlag)}))
		},
		Entry("Both CR and license feature not present/active", false, false, managerComplianceExpectation{managerFlag: false, voltronFlag: false}),
		Entry("CR not present, license feature active", false, true, managerComplianceExpectation{managerFlag: false, voltronFlag: false}),

		// We expect the manager feature flag to be true in this case, since the CR is present. The manager will render an insufficient license state.
		Entry("CR present, license feature not active", true, false, managerComplianceExpectation{managerFlag: true, voltronFlag: false}),
	)

	It("should ensure cnx policy recommendation support is always set to true", func() {
		resources := renderObjects(renderConfig{oidc: false, managementCluster: nil, installation: installation, compliance: compliance, complianceFeatureActive: true})
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
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
				},
				Verbs: []string{"patch"},
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
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"alertexceptions",
				},
				Verbs: []string{"get", "list", "update"},
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
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flows",
					"flowlogs",
					"bgplogs",
					"auditlogs",
					"dnsflows",
					"dnslogs",
					"l7flows",
					"l7logs",
					"events",
					"processes",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
			},
		}))
	})

	It("should set OIDC Authority environment when auth-type is OIDC", func() {
		const authority = "https://127.0.0.1/dex"
		oidcEnvVar.Value = authority

		// Should render the correct resource based on test case.
		resources := renderObjects(renderConfig{oidc: true, managementCluster: nil, installation: installation, compliance: compliance, complianceFeatureActive: true})
		Expect(resources).To(HaveLen(expectedResourcesNumber))
		d := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		// tigera-manager volumes/volumeMounts checks.
		Expect(d.Spec.Template.Spec.Volumes).To(HaveLen(2))
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(3))
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(oidcEnvVar))
	})

	Describe("public ca bundle", func() {
		var cfg *render.ManagerConfiguration
		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			cli := fake.NewClientBuilder().WithScheme(scheme).Build()

			certificateManager, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			tunnelSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.VoltronTunnelSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			internalTraffic, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			managerTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerTLSSecretName, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())

			voltronLinseedCert, err := certificateManager.GetOrCreateKeyPair(cli, render.VoltronLinseedTLS, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
			Expect(err).NotTo(HaveOccurred())

			cfg = &render.ManagerConfiguration{
				TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(certificateManager.KeyPair()),
				TLSKeyPair:            managerTLS,
				ManagementCluster:     &operatorv1.ManagementCluster{},
				TunnelSecret:          tunnelSecret,
				VoltronLinseedKeyPair: voltronLinseedCert,
				InternalTrafficSecret: internalTraffic,
				Installation:          installation,
				ClusterConfig:         &relasticsearch.ClusterConfig{},
			}
		})

		It("should render when disabled", func() {
			resources, err := render.Manager(cfg)
			Expect(err).ToNot(HaveOccurred())
			rs, _ := resources.Objects()

			managerDeployment := rtest.GetResource(rs, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			voltronContainer := rtest.GetContainer(managerDeployment.Spec.Template.Spec.Containers, "tigera-voltron")

			rtest.ExpectEnv(voltronContainer.Env, "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", "false")
		})

		It("should render when enabled", func() {
			cfg.ManagementCluster.Spec.TLS = &operatorv1.TLS{SecretName: render.ManagerTLSSecretName}

			resources, err := render.Manager(cfg)
			Expect(err).ToNot(HaveOccurred())
			rs, _ := resources.Objects()

			managerDeployment := rtest.GetResource(rs, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			voltronContainer := rtest.GetContainer(managerDeployment.Spec.Template.Spec.Containers, "tigera-voltron")

			rtest.ExpectEnv(voltronContainer.Env, "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", "true")
		})
	})

	It("should render multicluster settings properly", func() {
		resources := renderObjects(renderConfig{oidc: false, managementCluster: &operatorv1.ManagementCluster{}, installation: installation, compliance: compliance, complianceFeatureActive: true})

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-manager", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.ManagerPolicyName, ns: "tigera-manager", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: networkpolicy.TigeraComponentDefaultDenyPolicyName, ns: "tigera-manager", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-manager-role", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-manager-binding", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ManagerClusterSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerUserSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerClusterSettingsLayerTigera, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettings"},
			{name: render.ManagerClusterSettingsViewDefault, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettings"},
			{name: "tigera-manager", ns: "tigera-manager", group: "", version: "v1", kind: "Service"},
			{name: "tigera-manager", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "tigera-manager", ns: "tigera-manager", group: "apps", version: "v1", kind: "Deployment"},
			{name: render.VoltronLinseedPublicCert, ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
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

		Expect(esProxy.VolumeMounts).To(HaveLen(2))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(esProxy.VolumeMounts[1].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(esProxy.VolumeMounts[1].MountPath).To(Equal("/manager-tls"))

		Expect(len(voltron.VolumeMounts)).To(Equal(5))
		Expect(voltron.VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
		Expect(voltron.VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(voltron.VolumeMounts[1].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(voltron.VolumeMounts[1].MountPath).To(Equal("/manager-tls"))
		Expect(voltron.VolumeMounts[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(voltron.VolumeMounts[2].MountPath).To(Equal("/internal-manager-tls"))
		Expect(voltron.VolumeMounts[3].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(voltron.VolumeMounts[3].MountPath).To(Equal("/tigera-management-cluster-connection"))
		Expect(voltron.VolumeMounts[4].Name).To(Equal(render.VoltronLinseedTLS))
		Expect(voltron.VolumeMounts[4].MountPath).To(Equal("/tigera-voltron-linseed-tls"))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(5))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[1].VolumeSource.ConfigMap.Name).To(Equal("tigera-ca-bundle"))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Name).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Name).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[3].Secret.SecretName).To(Equal(render.VoltronTunnelSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Name).To(Equal(render.VoltronLinseedTLS))
		Expect(deployment.Spec.Template.Spec.Volumes[4].Secret.SecretName).To(Equal(render.VoltronLinseedTLS))

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
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
				},
				Verbs: []string{"patch"},
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
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"alertexceptions",
				},
				Verbs: []string{"get", "list", "update"},
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
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flows",
					"flowlogs",
					"bgplogs",
					"auditlogs",
					"dnsflows",
					"dnslogs",
					"l7flows",
					"l7logs",
					"events",
					"processes",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
			},
		}))
	})

	var kp certificatemanagement.KeyPairInterface
	var voltronLinseedKP certificatemanagement.KeyPairInterface
	var bundle certificatemanagement.TrustedBundle

	BeforeEach(func() {
		var err error
		secret, err := certificatemanagement.CreateSelfSignedSecret(render.ManagerTLSSecretName, common.OperatorNamespace(), render.ManagerTLSSecretName, nil)
		Expect(err).NotTo(HaveOccurred())
		kp = certificatemanagement.NewKeyPair(secret, []string{""}, "")
		Expect(err).NotTo(HaveOccurred())
		voltronLinseedKP = certificatemanagement.NewKeyPair(secret, []string{""}, "")
		Expect(err).NotTo(HaveOccurred())
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		bundle = certificateManager.CreateTrustedBundle()
	})

	// renderManager passes in as few parameters as possible to render.Manager without it
	// panicing. It accepts variations on the installspec for testing purposes.
	renderManager := func(i *operatorv1.InstallationSpec) *appsv1.Deployment {
		cfg := &render.ManagerConfiguration{
			TrustedCertBundle:     bundle,
			ClusterConfig:         &relasticsearch.ClusterConfig{},
			TLSKeyPair:            kp,
			VoltronLinseedKeyPair: voltronLinseedKP,
			Installation:          i,
			ESLicenseType:         render.ElasticsearchLicenseTypeUnknown,
			Replicas:              &replicas,
			UsePSP:                true,
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
		Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateCriticalAddonsAndControlPlane, t)))
	})

	It("should render all resources for certificate management", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes()
		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{CertificateManagement: &operatorv1.CertificateManagement{CACert: cert}, ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
		})

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: render.ManagerNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.ManagerPolicyName, ns: "tigera-manager", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: networkpolicy.TigeraComponentDefaultDenyPolicyName, ns: "tigera-manager", group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.ManagerServiceAccount, ns: render.ManagerNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.ManagerClusterRole, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.ManagerClusterRoleBinding, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.ManagerClusterSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerUserSettings, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettingsGroup"},
			{name: render.ManagerClusterSettingsLayerTigera, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettings"},
			{name: render.ManagerClusterSettingsViewDefault, ns: "", group: "projectcalico.org", version: "v3", kind: "UISettings"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-manager", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "apps", version: "v1", kind: "Deployment"},
		}

		Expect(resources).To(HaveLen(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(deployment.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		csrInitContainer := deployment.Spec.Template.Spec.InitContainers[0]
		Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ManagerTLSSecretName)))

		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(2))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(deployment.Spec.Template.Spec.Volumes[0].Secret).To(BeNil())
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		installation.ControlPlaneReplicas = &replicas

		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
		})
		deploy, ok := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		installation.ControlPlaneReplicas = &replicas

		resources := renderObjects(renderConfig{
			oidc:                    false,
			managementCluster:       nil,
			installation:            &operatorv1.InstallationSpec{ControlPlaneReplicas: &replicas},
			compliance:              compliance,
			complianceFeatureActive: true,
		})
		deploy, ok := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-manager", render.ManagerNamespace)))
	})

	It("should set the right env when FIPS is enabled", func() {
		fipsEnabled := operatorv1.FIPSModeEnabled
		installation.FIPSMode = &fipsEnabled
		resources := renderObjects(renderConfig{oidc: false, managementCluster: nil, installation: installation, compliance: compliance, complianceFeatureActive: true})
		Expect(resources).To(HaveLen(expectedResourcesNumber))
		deploy, ok := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Containers[0].Name).To(Equal("tigera-manager"))
		Expect(deploy.Spec.Template.Spec.Containers[1].Name).To(Equal("tigera-es-proxy"))
		Expect(deploy.Spec.Template.Spec.Containers[2].Name).To(Equal("tigera-voltron"))
		Expect(deploy.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "ENABLE_KIBANA", Value: "false"}))
		Expect(deploy.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "ENABLE_ANOMALY_DETECTION", Value: "false"}))
		Expect(deploy.Spec.Template.Spec.Containers[1].Env).To(ContainElement(corev1.EnvVar{Name: "FIPS_MODE_ENABLED", Value: "true"}))
		Expect(deploy.Spec.Template.Spec.Containers[2].Env).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_FIPS_MODE_ENABLED", Value: "true"}))
	})

	Context("allow-tigera rendering", func() {
		policyName := types.NamespacedName{Name: "allow-tigera.manager-access", Namespace: "tigera-manager"}

		getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if scenario.ManagedCluster {
				return nil
			}

			return testutils.SelectPolicyByProvider(scenario, expectedManagerPolicy, expectedManagerOpenshiftPolicy)
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				// Default configuration.
				resources := renderObjects(renderConfig{
					openshift:               scenario.Openshift,
					oidc:                    false,
					managementCluster:       nil,
					installation:            installation,
					compliance:              compliance,
					complianceFeatureActive: true,
				})

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			// Manager only renders in the presence of a Manager CR, therefore does not have a config option for managed clusters.
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
		)
	})
})

type renderConfig struct {
	oidc                    bool
	managementCluster       *operatorv1.ManagementCluster
	installation            *operatorv1.InstallationSpec
	compliance              *operatorv1.Compliance
	complianceFeatureActive bool
	openshift               bool
}

func renderObjects(roc renderConfig) []client.Object {
	var dexCfg authentication.KeyValidatorConfig
	if roc.oidc {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"},
			},
		}

		dexCfg = render.NewDexKeyValidatorConfig(authentication, nil, dns.DefaultClusterDomain)
	}

	var tunnelSecret certificatemanagement.KeyPairInterface
	var internalTraffic certificatemanagement.KeyPairInterface
	var voltronLinseedKP certificatemanagement.KeyPairInterface
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	certificateManager, err := certificatemanager.Create(cli, roc.installation, clusterDomain, common.OperatorNamespace())
	Expect(err).NotTo(HaveOccurred())
	bundle := certificatemanagement.CreateTrustedBundle(certificateManager.KeyPair())

	if roc.managementCluster != nil {
		tunnelSecret, err = certificateManager.GetOrCreateKeyPair(cli, render.VoltronTunnelSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		internalTraffic, err = certificateManager.GetOrCreateKeyPair(cli, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		voltronLinseedKP, err = certificateManager.GetOrCreateKeyPair(cli, render.VoltronLinseedTLS, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())

	}
	managerTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.ManagerTLSSecretName, common.OperatorNamespace(), []string{""})
	Expect(err).NotTo(HaveOccurred())

	esConfigMap := relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)
	cfg := &render.ManagerConfiguration{
		KeyValidatorConfig:      dexCfg,
		TrustedCertBundle:       bundle,
		ClusterConfig:           esConfigMap,
		TLSKeyPair:              managerTLS,
		Installation:            roc.installation,
		ManagementCluster:       roc.managementCluster,
		TunnelSecret:            tunnelSecret,
		VoltronLinseedKeyPair:   voltronLinseedKP,
		InternalTrafficSecret:   internalTraffic,
		ClusterDomain:           dns.DefaultClusterDomain,
		ESLicenseType:           render.ElasticsearchLicenseTypeEnterpriseTrial,
		Replicas:                roc.installation.ControlPlaneReplicas,
		Compliance:              roc.compliance,
		ComplianceLicenseActive: roc.complianceFeatureActive,
		Openshift:               roc.openshift,
		UsePSP:                  true,
	}
	component, err := render.Manager(cfg)
	Expect(err).To(BeNil(), "Expected Manager to create successfully %s", err)
	Expect(component.ResolveImages(nil)).To(BeNil())
	resources, _ := component.Objects()
	return resources
}
