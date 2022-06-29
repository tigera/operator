// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Tigera Secure Cloud Intrusion Detection Controller rendering tests", func() {
	var cfg *render.IntrusionDetectionConfiguration

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		adAPIKeyPair, err := certificatemanagement.NewKeyPair(rtest.CreateCertSecret(render.ADAPITLSSecretName, common.OperatorNamespace(), render.ADAPITLSSecretName), []string{""}, "")
		Expect(err).NotTo(HaveOccurred())
		bundle := certificateManager.CreateTrustedBundle()
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		cfg = &render.IntrusionDetectionConfiguration{
			TrustedCertBundle:     bundle,
			ADAPIServerCertSecret: adAPIKeyPair,
			Installation:          &operatorv1.InstallationSpec{Registry: "testregistry.com/"},
			ESClusterConfig:       relasticsearch.NewClusterConfig("tenant_id.clusterTestName", 1, 1, 1),
			ClusterDomain:         dns.DefaultClusterDomain,
			ESLicenseType:         render.ElasticsearchLicenseTypeUnknown,
			ManagedCluster:        notManagedCluster,
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
					TLSSecret: rtest.CreateCertSecret(rcimageassurance.ImageAssuranceSecretName, common.OperatorNamespace(), dns.DefaultClusterDomain),
				},
			},
		}
	})

	It("should render resources for an Image Assurance configuration", func() {
		cfg.Openshift = notOpenshift
		component := render.IntrusionDetection(cfg)
		resources, _ := component.Objects()

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-image-assurance-api-cert", ns: "tigera-intrusion-detection", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-image-assurance-config", ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
			{name: render.IntrusionDetectionControllerImageAssuranceAPIClusterRoleName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "image-assurance-api-token", ns: "tigera-intrusion-detection", group: "", version: "", kind: ""},
		}

		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		idc := rtest.GetResource(resources, "intrusion-detection-controller", render.IntrusionDetectionNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(idc.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(3))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(
			corev1.VolumeMount{
				Name:      certificatemanagement.TrustedCertConfigMapName,
				MountPath: certificatemanagement.TrustedCertVolumeMountPath,
				ReadOnly:  true,
			},
		))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(
			corev1.VolumeMount{
				Name:      "tigera-image-assurance-api-cert",
				MountPath: "/certs/bast",
				ReadOnly:  true,
			},
		))
		Expect(idc.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(
			corev1.VolumeMount{
				Name:      "elastic-ca-cert-volume",
				MountPath: "/etc/ssl/elastic/",
			},
		))

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

		Expect(idc.Spec.Template.Spec.Volumes).To(ContainElement(
			corev1.Volume{
				Name: "elastic-ca-cert-volume",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: "tigera-secure-es-gateway-http-certs-public",
						Items: []corev1.KeyToPath{{
							Key:  "tls.crt",
							Path: "ca.pem",
						}},
					},
				},
			},
		))
		Expect(idc.Spec.Template.Spec.Volumes).To(ContainElement(
			corev1.Volume{
				Name: "tigera-image-assurance-api-cert",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: "tigera-image-assurance-api-cert",
						Items: []corev1.KeyToPath{{
							Key:  "tls.crt",
							Path: "tls.crt",
						}},
					},
				},
			},
		))
	})
})
