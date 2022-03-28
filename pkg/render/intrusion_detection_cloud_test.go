// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
)

var _ = Describe("Tigera Secure Cloud Intrusion Detection Controller rendering tests", func() {
	var cfg *render.IntrusionDetectionConfiguration

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		cfg = &render.IntrusionDetectionConfiguration{
			KibanaCertSecret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret}},
			Installation:     &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			ESClusterConfig:  relasticsearch.NewClusterConfig("tenant_id.clusterTestName", 1, 1, 1),
			ClusterDomain:    dns.DefaultClusterDomain,
			ESLicenseType:    render.ElasticsearchLicenseTypeUnknown,
			ManagedCluster:   notManagedCluster,
			CloudResources: render.IntrusionDetectionCloudResources{
				ImageAssuranceResources: &rcimageassurance.Resources{
					ConfigurationConfigMap: &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{
							Name:      rcimageassurance.ConfigurationConfigMapName,
							Namespace: render.IntrusionDetectionNamespace,
						},
						Data: map[string]string{
							rcimageassurance.ConfigurationConfigMapOrgIDKey: "test-org-id",
						},
					},
					TLSSecret: rtest.CreateCertSecret(rcimageassurance.ImageAssuranceSecretName, common.OperatorNamespace()),
				},
			},
		}
	})

	It("should render all resources for an Image Assurance configuration", func() {
		cfg.Openshift = notOpenshift
		cfg.ManagerInternalTLSSecret = &testutils.InternalManagerTLSSecret
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-intrusion-detection", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.TigeraKibanaCertSecret, ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{name: render.ManagerInternalTLSSecretName, ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Secret"},
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
			{name: "tigera-image-assurance-api-cert", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-image-assurance-config", ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{name: "image-assurance-api-token", ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
		}

		Expect(len(resources)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			if expectedRes.kind == "GlobalAlertTemplate" {
				rtest.ExpectGlobalAlertTemplateToBePopulated(resources[i])
			}
		}

		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(idc.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(3))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("internal-manager-tls"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("tigera-image-assurance-api-cert"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/certs/bast"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[2].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts[2].MountPath).To(Equal("/etc/ssl/elastic/"))

		Expect(idc.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_CA_BUNDLE_PATH", Value: "/certs/bast/tls.crt"},
			corev1.EnvVar{Name: "IMAGE_ASSURANCE_ENDPOINT", Value: "https://tigera-image-assurance-api.tigera-image-assurance.svc:9443"},
			corev1.EnvVar{
				Name: "IMAGE_ASSURANCE_ORGANIZATION_ID",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-image-assurance-config"},
						Key:                  "organizationID",
					},
				},
			},
		))

		Expect(idc.Spec.Template.Spec.Volumes).To(HaveLen(3))
		Expect(idc.Spec.Template.Spec.Volumes[0].Name).To(Equal("internal-manager-tls"))
		Expect(idc.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal("internal-manager-tls"))
		Expect(idc.Spec.Template.Spec.Volumes[1].Name).To(Equal("elastic-ca-cert-volume"))
		Expect(idc.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal("tigera-secure-es-gateway-http-certs-public"))
		Expect(idc.Spec.Template.Spec.Volumes[2].Name).To(Equal("tigera-image-assurance-api-cert"))
		Expect(idc.Spec.Template.Spec.Volumes[2].Secret.SecretName).To(Equal("tigera-image-assurance-api-cert"))
	})
})
