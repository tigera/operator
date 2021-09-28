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
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

var _ = Describe("compliance rendering tests", func() {
	ns := "tigera-compliance"
	rbac := "rbac.authorization.k8s.io"
	clusterDomain := dns.DefaultClusterDomain
	complianceServerCertSecret := rtest.CreateCertSecret(render.ComplianceServerCertSecret, common.OperatorNamespace())

	Context("Standalone cluster", func() {
		It("should render all resources for a default configuration", func() {
			component, err := render.Compliance(nil, nil, &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}, complianceServerCertSecret, relasticsearch.NewClusterConfig("cluster", 1, 1, 1), nil, notOpenshift, nil, nil, nil, clusterDomain, false)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{ns, "", "", "v1", "Namespace"},
				{"tigera-compliance-controller", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-controller", ns, rbac, "v1", "Role"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-controller", ns, rbac, "v1", "RoleBinding"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-controller", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-reporter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera.io.report", ns, "", "v1", "PodTemplate"},
				{"tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-snapshotter", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", ns, "apps", "v1", "DaemonSet"},
				{"inventory", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"network-access", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"tigera-compliance-server", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding"},
				{render.ComplianceServerCertSecret, "tigera-operator", "", "v1", "Secret"},
				{render.ComplianceServerCertSecret, "tigera-compliance", "", "v1", "Secret"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRole"},
				{"compliance", ns, "", "v1", "Service"},
				{"compliance-server", ns, "apps", "v1", "Deployment"},
				{"compliance-benchmarker", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-controller", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-reporter", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-server", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-snapshotter", "", "policy", "v1beta1", "PodSecurityPolicy"},
			}

			Expect(len(resources)).To(Equal(len(expectedResources)))

			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}

			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "inventory", "", "projectcalico.org", "v3", "GlobalReportType"), "inventory")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "network-access", "", "projectcalico.org", "v3", "GlobalReportType"), "network-access")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"), "policy-audit")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"), "cis-benchmark")

			clusterRole := rtest.GetResource(resources, "tigera-compliance-server", "", rbac, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"globalreporttypes", "globalreports"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"authorization.k8s.io"},
					Resources: []string{"subjectaccessreviews"},
					Verbs:     []string{"create"},
				},
				{
					APIGroups:     []string{"policy"},
					Resources:     []string{"podsecuritypolicies"},
					Verbs:         []string{"use"},
					ResourceNames: []string{"compliance-server"},
				},
			}))

			d := rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env

			expectedEnvs := []corev1.EnvVar{
				{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
				{Name: "ELASTIC_PORT", Value: "9200"},
			}
			for _, expected := range expectedEnvs {
				Expect(envs).To(ContainElement(expected))
			}
		})
	})

	Context("Management cluster", func() {
		It("should render all resources for a default configuration", func() {
			component, err := render.Compliance(nil, &testutils.InternalManagerTLSSecret,
				&operatorv1.InstallationSpec{
					KubernetesProvider: operatorv1.ProviderNone,
					Registry:           "testregistry.com/",
				}, complianceServerCertSecret, relasticsearch.NewClusterConfig("cluster", 1, 1, 1), nil, notOpenshift, &operatorv1.ManagementCluster{}, nil, nil, clusterDomain, false)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{ns, "", "", "v1", "Namespace"},
				{"tigera-compliance-controller", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-controller", ns, rbac, "v1", "Role"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-controller", ns, rbac, "v1", "RoleBinding"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-controller", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-reporter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera.io.report", ns, "", "v1", "PodTemplate"},
				{"tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-snapshotter", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", ns, "apps", "v1", "DaemonSet"},
				{"inventory", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"network-access", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"tigera-compliance-server", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding"},
				{render.ManagerInternalTLSSecretName, "tigera-compliance", "", "v1", "Secret"},
				{render.ComplianceServerCertSecret, "tigera-operator", "", "v1", "Secret"},
				{render.ComplianceServerCertSecret, "tigera-compliance", "", "v1", "Secret"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRole"},
				{"compliance", ns, "", "v1", "Service"},
				{"compliance-server", ns, "apps", "v1", "Deployment"},
				{"compliance-benchmarker", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-controller", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-reporter", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-server", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-snapshotter", "", "policy", "v1beta1", "PodSecurityPolicy"},
			}

			Expect(len(resources)).To(Equal(len(expectedResources)))

			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}

			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "inventory", "", "projectcalico.org", "v3", "GlobalReportType"), "inventory")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "network-access", "", "projectcalico.org", "v3", "GlobalReportType"), "network-access")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"), "policy-audit")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"), "cis-benchmark")

			var dpComplianceServer = rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)

			Expect(len(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(3))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tls"))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/code/apiserver.local.config/certificates"))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal(render.ManagerInternalTLSSecretName))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/manager-tls"))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[2].Name).To(Equal("elastic-ca-cert-volume"))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[2].MountPath).To(Equal("/etc/ssl/elastic/"))

			Expect(len(dpComplianceServer.Spec.Template.Spec.Volumes)).To(Equal(3))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[0].Name).To(Equal("tls"))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ComplianceServerCertSecret))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[1].Name).To(Equal(render.ManagerInternalTLSSecretName))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(render.ManagerInternalTLSSecretName))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[2].Name).To(Equal("elastic-ca-cert-volume"))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal(relasticsearch.PublicCertSecret))

			clusterRole := rtest.GetResource(resources, "tigera-compliance-server", "", rbac, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"globalreporttypes", "globalreports"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"authorization.k8s.io"},
					Resources: []string{"subjectaccessreviews"},
					Verbs:     []string{"create"},
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
					ResourceNames: []string{"compliance-server"},
				},
			}))
		})
	})

	Context("ManagedCluster", func() {
		It("should render all resources for a default configuration", func() {
			component, err := render.Compliance(nil, nil, &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}, complianceServerCertSecret, relasticsearch.NewClusterConfig("cluster", 1, 1, 1), nil, notOpenshift, nil, &operatorv1.ManagementClusterConnection{}, nil, clusterDomain, false)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			ns := "tigera-compliance"
			rbac := "rbac.authorization.k8s.io"

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{ns, "", "", "v1", "Namespace"},
				{"tigera-compliance-controller", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-controller", ns, rbac, "v1", "Role"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-controller", ns, rbac, "v1", "RoleBinding"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-controller", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-reporter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera.io.report", ns, "", "v1", "PodTemplate"},
				{"tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-snapshotter", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", ns, "apps", "v1", "DaemonSet"},
				{"inventory", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"network-access", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"tigera-compliance-server", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRole"},
				{"compliance-benchmarker", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-controller", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-reporter", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-server", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-snapshotter", "", "policy", "v1beta1", "PodSecurityPolicy"},
			}

			Expect(len(resources)).To(Equal(len(expectedResources)))

			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}

			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "inventory", "", "projectcalico.org", "v3", "GlobalReportType"), "inventory")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "network-access", "", "projectcalico.org", "v3", "GlobalReportType"), "network-access")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"), "policy-audit")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"), "cis-benchmark")

			clusterRole := rtest.GetResource(resources, "tigera-compliance-server", "", rbac, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"globalreporttypes", "globalreports"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"authorization.k8s.io"},
					Resources: []string{"subjectaccessreviews"},
					Verbs:     []string{"create"},
				},
			}))
		})
	})

	Describe("node selection & affinity", func() {
		var renderCompliance = func(i *operatorv1.InstallationSpec) (server, controller, snapshotter *appsv1.Deployment, reporter *corev1.PodTemplate, benchmarker *appsv1.DaemonSet) {
			component, err := render.Compliance(nil, nil, i, complianceServerCertSecret, relasticsearch.NewClusterConfig("cluster", 1, 1, 1), nil, notOpenshift, nil, nil, nil, clusterDomain, false)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()
			server = rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			controller = rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			snapshotter = rtest.GetResource(resources, "compliance-snapshotter", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			reporter = rtest.GetResource(resources, "tigera.io.report", ns, "", "v1", "PodTemplate").(*corev1.PodTemplate)
			benchmarker = rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			return
		}
		It("should apply controlPlaneTolerations", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}
			dpComplianceServer, dpComplianceController, complianceSnapshotter, complianceReporter, complianceBenchmarker := renderCompliance(&operatorv1.InstallationSpec{
				ControlPlaneTolerations: []corev1.Toleration{t},
			})
			Expect(dpComplianceServer.Spec.Template.Spec.Tolerations).To(ContainElements(t, rmeta.TolerateMaster))
			Expect(dpComplianceController.Spec.Template.Spec.Tolerations).To(ContainElements(t, rmeta.TolerateMaster))
			Expect(complianceSnapshotter.Spec.Template.Spec.Tolerations).To(ContainElements(t, rmeta.TolerateMaster))
			Expect(complianceReporter.Template.Spec.Tolerations).To(ContainElements(t, rmeta.TolerateMaster))
			Expect(complianceBenchmarker.Spec.Template.Spec.Tolerations).To(ContainElements(rmeta.TolerateAll))
		})

		It("should apply controlPlaneNodeSelectors", func() {
			dpComplianceServer, dpComplianceController, complianceSnapshotter, _, _ := renderCompliance(&operatorv1.InstallationSpec{
				ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
			})
			Expect(dpComplianceServer.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			Expect(dpComplianceController.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			Expect(complianceSnapshotter.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
		})
	})

	Context("Certificate management enabled", func() {
		It("should render init containers and volume changes", func() {
			component, err := render.Compliance(nil, nil, &operatorv1.InstallationSpec{
				KubernetesProvider:    operatorv1.ProviderNone,
				Registry:              "testregistry.com/",
				CertificateManagement: &operatorv1.CertificateManagement{},
			}, complianceServerCertSecret, relasticsearch.NewClusterConfig("cluster", 1, 1, 1), nil, notOpenshift, nil, nil, nil, clusterDomain, false)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{ns, "", "", "v1", "Namespace"},
				{"tigera-compliance-controller", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-controller", ns, rbac, "v1", "Role"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-controller", ns, rbac, "v1", "RoleBinding"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-controller", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-reporter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera.io.report", ns, "", "v1", "PodTemplate"},
				{"tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-snapshotter", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", ns, "apps", "v1", "DaemonSet"},
				{"inventory", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"network-access", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"tigera-compliance-server", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding"},
				{render.ComplianceServerCertSecret, "tigera-operator", "", "v1", "Secret"},
				{render.ComplianceServerCertSecret, ns, "", "v1", "Secret"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRole"},
				{"compliance", ns, "", "v1", "Service"},
				{"compliance-server", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-server:csr-creator", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-controller", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-reporter", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-server", "", "policy", "v1beta1", "PodSecurityPolicy"},
				{"compliance-snapshotter", "", "policy", "v1beta1", "PodSecurityPolicy"},
			}

			for i, expectedRes := range expectedResources {
				rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
			Expect(len(resources)).To(Equal(len(expectedResources)))

			server := rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(server.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			csrInitContainer := server.Spec.Template.Spec.InitContainers[0]
			Expect(csrInitContainer.Name).To(Equal(render.CSRInitContainerName))
		})
	})
})
