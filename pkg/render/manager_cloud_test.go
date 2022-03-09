// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Tigera Secure Cloud Manager rendering tests", func() {
	installation := &operatorv1.InstallationSpec{}

	It("should render all resources for a Image Assurance configuration", func() {
		resources := renderObjects(renderConfig{oidc: false, managementCluster: nil,
			installation: installation, includeManagerTLSSecret: true, imageAssuranceEnabled: true})

		// Should render the correct resources.
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// In addition to default resources, extra resource voltron image assurance secret is expected.
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
			{name: render.VoltronImageAssuranceSecretName, ns: render.ManagerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "tigera-manager", ns: render.ManagerNamespace, group: "apps", version: "v1", kind: "Deployment"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))

		deployment := rtest.GetResource(resources, "tigera-manager", render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(len(deployment.Spec.Template.Spec.Containers)).Should(Equal(3))
		var manager = deployment.Spec.Template.Spec.Containers[0]
		var esProxy = deployment.Spec.Template.Spec.Containers[1]
		var voltron = deployment.Spec.Template.Spec.Containers[2]
		var dpSpec = deployment.Spec.Template.Spec

		Expect(manager.Image).Should(Equal(components.TigeraRegistry + "tigera/cnx-manager:" + components.ComponentManager.Version))
		Expect(esProxy.Image).Should(Equal(components.TigeraRegistry + "tigera/es-proxy:" + components.ComponentEsProxy.Version))
		Expect(voltron.Image).Should(Equal(components.TigeraRegistry + "tigera/voltron:" + components.ComponentManagerProxy.Version))

		Expect(esProxy.Env).Should(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "tenant_id.clusterTestName"},
		))
		Expect(len(esProxy.VolumeMounts)).To(Equal(1))
		Expect(esProxy.VolumeMounts[0].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(esProxy.VolumeMounts[0].MountPath).To(Equal("/etc/ssl/elastic/"))

		// In addition to default volumes, deployment should have extra volume for image assurance secret
		Expect(len(deployment.Spec.Template.Spec.Volumes)).To(Equal(7))
		Expect(dpSpec.Volumes[0].Name).To(Equal(render.ManagerTLSSecretName))
		Expect(dpSpec.Volumes[0].Secret.SecretName).To(Equal(render.ManagerTLSSecretName))
		Expect(dpSpec.Volumes[1].Name).To(Equal(render.KibanaPublicCertSecret))
		Expect(dpSpec.Volumes[1].Secret.SecretName).To(Equal(render.KibanaPublicCertSecret))
		Expect(dpSpec.Volumes[2].Name).To(Equal(render.ComplianceServerCertSecret))
		Expect(dpSpec.Volumes[2].Secret.SecretName).To(Equal(render.ComplianceServerCertSecret))
		Expect(dpSpec.Volumes[3].Name).To(Equal(render.PacketCaptureCertSecret))
		Expect(dpSpec.Volumes[3].Secret.SecretName).To(Equal(render.PacketCaptureCertSecret))
		Expect(dpSpec.Volumes[4].Name).To(Equal(render.PrometheusTLSSecretName))
		Expect(dpSpec.Volumes[4].Secret.SecretName).To(Equal(render.PrometheusTLSSecretName))
		Expect(dpSpec.Volumes[5].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(dpSpec.Volumes[5].Secret.SecretName).To(Equal(relasticsearch.PublicCertSecret))
		Expect(dpSpec.Volumes[6].Name).To(Equal(render.VoltronImageAssuranceSecretName))
		Expect(dpSpec.Volumes[6].Secret.SecretName).To(Equal(render.VoltronImageAssuranceSecretName))

		// deployment should have an annotation for image assurance cert.
		Expect(deployment.Spec.Template.Annotations).Should(HaveKey(
			render.ImageAssuranceCertAnnotation,
		))

		// in addition to default volumes mounts, voltron should have an extra volume mount for bast certs
		Expect(len(voltron.VolumeMounts)).To(Equal(6))
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
		Expect(voltron.VolumeMounts[5].Name).To(Equal(render.VoltronImageAssuranceSecretName))
		Expect(voltron.VolumeMounts[5].MountPath).To(Equal("/certs/bast"))

		// voltron should contain Image assurance related variables.
		Expect(voltron.Env).Should(ContainElements(
			corev1.EnvVar{Name: "VOLTRON_ENABLE_IMAGE_ASSURANCE", Value: "true"},
			corev1.EnvVar{Name: "VOLTRON_IMAGE_ASSURANCE_ENDPOINT", Value: "https://tigera-image-assurance-api.tigera-image-assurance.svc:9443"},
			corev1.EnvVar{Name: "VOLTRON_IMAGE_ASSURANCE_CA_BUNDLE_PATH", Value: "/certs/bast/tls.crt"},
		))

		// manager should contain Image assurance related variables.
		Expect(manager.Env).Should(ContainElements(
			corev1.EnvVar{Name: "ENABLE_IMAGE_ASSURANCE_SUPPORT", Value: "true"},
			corev1.EnvVar{Name: "CNX_IMAGE_ASSURANCE_API_URL", Value: "/bast/v1"},
		))

	})
})
