// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package intrusiondetection

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	iarender "github.com/tigera/operator/pkg/render/imageassurance"
	"github.com/tigera/operator/test"
)

var _ = Describe("Cloud Intrusion Detection Controller tests", func() {
	var (
		c          client.Client
		ctx        context.Context
		r          ReconcileIntrusionDetection
		scheme     *runtime.Scheme
		mockStatus *status.MockStatus
	)

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
		mockStatus.On("SetDegraded",
			"failed to retrieve configmap: tigera-image-assurance-config",
			`expected configmap "tigera-image-assurance-config" to have a field named "organizationID"`).Return().Maybe()
		mockStatus.On("SetDegraded",
			"failed to retrieve configmap: tigera-image-assurance-config",
			`failed to read secret "tigera-image-assurance-config": configmaps "tigera-image-assurance-config" not found`).Return().Maybe()
		mockStatus.On("ReadyToMonitor")

		cloudConfig := cloudconfig.NewCloudConfig("id", "tenantName", "externalES.com", "externalKB.com", false)
		Expect(c.Create(ctx, cloudConfig.ConfigMap())).ToNot(HaveOccurred())

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileIntrusionDetection{
			client:          c,
			scheme:          scheme,
			provider:        operatorv1.ProviderNone,
			status:          mockStatus,
			licenseAPIReady: &utils.ReadyFlag{},
			dpiAPIReady:     &utils.ReadyFlag{},
			elasticExternal: false,
		}

		// We start off with a 'standard' installation, with nothing special
		Expect(c.Create(
			ctx,
			&operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.InstallationSpec{
					Variant:  operatorv1.TigeraSecureEnterprise,
					Registry: "some.registry.org/",
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.TigeraSecureEnterprise,
					Computed: &operatorv1.InstallationSpec{
						Registry: "my-reg",
						// The test is provider agnostic.
						KubernetesProvider: operatorv1.ProviderNone,
					},
				},
			})).NotTo(HaveOccurred())

		// The compliance reconcile loop depends on a ton of objects that should be available in your client as
		// prerequisites. Without them, compliance will not even start creating objects. Let's create them now.
		Expect(c.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status:     v3.LicenseKeyStatus{Features: []string{common.ThreatDefenseFeature}}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.LogCollector{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      relasticsearch.PublicCertSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchIntrusionDetectionUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchADJobUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchPerformanceHotspotsUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ECKLicenseConfigMapName,
				Namespace: render.ECKOperatorNamespace,
			},
			Data: map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterpriseTrial)},
		})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &v3.DeepPacketInspection{ObjectMeta: metav1.ObjectMeta{Name: "test-dpi", Namespace: "test-dpi-ns"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.NodeTLSSecretName,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.TyphaTLSSecretName,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.TyphaCAConfigMapName,
				Namespace: "tigera-operator",
			},
			Data: map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterpriseTrial)},
		})).NotTo(HaveOccurred())

		// Apply the intrusiondetection CR to the fake cluster.
		Expect(c.Create(ctx, &operatorv1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())

		// mark that the watch for license key and dpi was successful
		r.licenseAPIReady.MarkAsReady()
		r.dpiAPIReady.MarkAsReady()
	})

	Context("image reconciliation for Image Assurance", func() {
		BeforeEach(func() {
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ElasticsearchIntrusionDetectionJobUserSecret,
					Namespace: "tigera-operator",
				},
			})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      iarender.APICertSecretName,
					Namespace: "tigera-operator",
				},
				Data: map[string][]byte{"tls.key": []byte("tlskey"), "tls.crt": []byte("tlscrt")},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-image-assurance-intrusion-detection-controller-api-access",
					Namespace: "tigera-operator",
				},
				Secrets: []corev1.ObjectReference{{Name: "sa-secret"}},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sa-secret",
					Namespace: "tigera-operator",
				},
				Data: map[string][]byte{"token": []byte("token")},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &operatorv1.ImageAssurance{
				ObjectMeta: metav1.ObjectMeta{
					Name: utils.DefaultTSEEInstanceKey.Name,
				},
			})).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			c.Delete(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rcimageassurance.ConfigurationConfigMapName,
					Namespace: "tigera-operator",
				},
			})
		})

		It("should reconcile Image Assurance resources", func() {
			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rcimageassurance.ConfigurationConfigMapName,
					Namespace: "tigera-operator",
				},
				Data: map[string]string{
					"organizationID": "test-org-id",
				},
			})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "intrusion-detection-controller",
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).NotTo(HaveOccurred())

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-image-assurance-api-cert"))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/certs/bast"))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("elastic-ca-cert-volume"))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/etc/ssl/elastic/"))

			Expect(d.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
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

			Expect(d.Spec.Template.Spec.Volumes).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.Volumes[0].Name).To(Equal("elastic-ca-cert-volume"))
			Expect(d.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal("tigera-secure-es-gateway-http-certs-public"))
			Expect(d.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-image-assurance-api-cert"))
			Expect(d.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal("tigera-image-assurance-api-cert"))
		})

		It("should return error when Image Assurance ConfigMap doesn't exist", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).To(HaveOccurred())
		})

		It("should return error when Image Assurance ConfigMap is missing organizationID", func() {
			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rcimageassurance.ConfigurationConfigMapName,
					Namespace: "tigera-operator",
				},
				Data: map[string]string{
					"invalid-org-id-key": "test-org-id",
				},
			})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).To(HaveOccurred())
		})

		It("should return error when Image Assurance ConfigMap contains empty organizationID", func() {
			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      rcimageassurance.ConfigurationConfigMapName,
					Namespace: "tigera-operator",
				},
				Data: map[string]string{
					"organizationID": "",
				},
			})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).To(HaveOccurred())
		})
	})
})
