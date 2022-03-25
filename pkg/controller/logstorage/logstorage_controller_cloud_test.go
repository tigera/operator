package logstorage

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"

	"github.com/tigera/operator/pkg/render/imageassurance"

	"github.com/tigera/operator/pkg/render/kubecontrollers"

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render/monitor"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = FDescribe("LogStorage controller", func() {
	var (
		cli    client.Client
		scheme *runtime.Scheme
		ctx    context.Context
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1beta.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = fake.NewFakeClientWithScheme(scheme)
		Expect(cli.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: common.OperatorNamespace(), Name: monitor.PrometheusClientTLSSecretName},
			Data:       map[string][]byte{corev1.TLSCertKey: []byte("cert")},
		})).ShouldNot(HaveOccurred())
	})
	Context("Reconcile", func() {
		Context("Management cluster with image assurance installed", func() {
			var mockStatus *status.MockStatus
			var install *operatorv1.Installation
			BeforeEach(func() {
				var replicas int32 = 2
				install = &operatorv1.Installation{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
					Status: operatorv1.InstallationStatus{
						Variant:  operatorv1.TigeraSecureEnterprise,
						Computed: &operatorv1.InstallationSpec{},
					},
					Spec: operatorv1.InstallationSpec{
						ControlPlaneReplicas: &replicas,
						Variant:              operatorv1.TigeraSecureEnterprise,
						Registry:             "some.registry.org/",
					},
				}
				Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

				Expect(cli.Create(
					ctx,
					&operatorv1.ManagementCluster{
						ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
					}),
				).NotTo(HaveOccurred())

				Expect(cli.Create(
					ctx,
					&operatorv1.ImageAssurance{
						ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
						Spec:       operatorv1.ImageAssuranceSpec{},
					}),
				).NotTo(HaveOccurred())

				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("AddDaemonsets", mock.Anything)
				mockStatus.On("AddDeployments", mock.Anything)
				mockStatus.On("AddStatefulSets", mock.Anything)
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("ReadyToMonitor")
			})
			It("sets cloud enabled controllers and env variables on kube controllers", func() {
				mockElasticsearchServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte{})
				}))
				mockElasticsearchServer.Config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
				mockElasticsearchServer.Start()
				defer mockElasticsearchServer.Close()

				Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: operatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())

				Expect(cli.Create(ctx, &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: storageClassName,
					},
				})).ShouldNot(HaveOccurred())

				Expect(cli.Create(ctx, &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: int64(1),
						},
						StorageClassName: storageClassName,
					},
				})).ShouldNot(HaveOccurred())

				Expect(cli.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
					Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
				})).ShouldNot(HaveOccurred())

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator,
					dns.DefaultClusterDomain, false, mockElasticsearchServer)
				Expect(err).ShouldNot(HaveOccurred())

				mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "").Return()
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				// Expect to be waiting for Elasticsearch and Kibana to be functional
				Expect(result).Should(Equal(reconcile.Result{}))

				By("asserting the finalizers have been set on the LogStorage CR")
				ls := &operatorv1.LogStorage{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())

				// Update ES and KB statuses to running (ECK would normally do this).
				es := &esv1.Elasticsearch{}
				Expect(cli.Get(ctx, esObjKey, es)).ShouldNot(HaveOccurred())

				es.Status.Phase = esv1.ElasticsearchReadyPhase
				Expect(cli.Update(ctx, es)).ShouldNot(HaveOccurred())

				kb := &kbv1.Kibana{}
				Expect(cli.Get(ctx, kbObjKey, kb)).ShouldNot(HaveOccurred())

				kb.Status.AssociationStatus = cmnv1.AssociationEstablished
				Expect(cli.Update(ctx, kb)).ShouldNot(HaveOccurred())

				By("confirming kibana certs are created")
				secret := &corev1.Secret{}

				// Create public ES and KB secrets (ECK would normally do this).
				Expect(cli.Get(ctx, kbCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
				esPublicSecret := createPubSecret(relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, secret.Data["tls.crt"], "tls.crt")
				Expect(cli.Create(ctx, esPublicSecret)).ShouldNot(HaveOccurred())

				Expect(cli.Get(ctx, kbCertSecretKey, secret)).ShouldNot(HaveOccurred())
				kbPublicSecret := createPubSecret(render.KibanaPublicCertSecret, render.KibanaNamespace, secret.Data["tls.crt"], "tls.crt")
				Expect(cli.Create(ctx, kbPublicSecret)).ShouldNot(HaveOccurred())

				// Create admin ES user (ECK would normally do this).
				esAdminUserSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.ElasticsearchAdminUserSecret,
						Namespace: render.ElasticsearchNamespace,
					},
					Data: map[string][]byte{
						"elastic": []byte("password"),
					},
				}
				Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

				// Create internal kibana secret (ECK would normally do this).
				kbInternalSecret := createPubSecret(render.KibanaInternalCertSecret, render.KibanaNamespace, secret.Data["tls.crt"], "tls.crt")
				Expect(cli.Create(ctx, kbInternalSecret)).ShouldNot(HaveOccurred())

				mockStatus.On("SetDegraded", "Waiting for curator secrets to become available", "").Return()
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// Expect to be waiting for curator secret.
				Expect(result).Should(Equal(reconcile.Result{}))
				Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())
				Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: esMetricsUsrSecretObjMeta})).ShouldNot(HaveOccurred())

				mockStatus.On("ClearDegraded")
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))

				By("confirming curator job is created")
				esKubeControllersDeployment := &appsv1.Deployment{}
				Expect(cli.Get(ctx, types.NamespacedName{Namespace: common.CalicoNamespace, Name: kubecontrollers.EsKubeController}, esKubeControllersDeployment)).ShouldNot(HaveOccurred())

				Expect(esKubeControllersDeployment.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
					corev1.EnvVar{Name: "IMAGE_ASSURANCE_ADMISSION_CONTROLLER_CLUSTER_ROLE_NAME", Value: imageassurance.AdmissionControllerAPIClusterRoleName},
					corev1.EnvVar{Name: "IMAGE_ASSURANCE_INTRUSION_DETECTION_CONTROLLER_CLUSTER_ROLE_NAME", Value: render.IntrusionDetectionControllerImageAssuranceAPIClusterRoleName},
					corev1.EnvVar{Name: "ENABLED_CONTROLLERS", Value: "authorization,elasticsearchconfiguration,managedcluster,imageassurance"},
				))
				mockStatus.AssertExpectations(GinkgoT())
			})
		})
	})
})
