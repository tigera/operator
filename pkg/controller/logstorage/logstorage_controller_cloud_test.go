// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package logstorage

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"

	"github.com/tigera/operator/pkg/render/imageassurance"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"

	"github.com/tigera/operator/pkg/render/kubecontrollers"

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	"github.com/stretchr/testify/mock"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render/monitor"
)

func cloudMockEsServer() *httptest.Server {
	m := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte{})
		Expect(err).NotTo(HaveOccurred())
	}))
	m.Config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	m.Start()
	return m
}

func cloudCreateESAccessSecret(cli client.Client, ctx context.Context) {
	Expect(cli.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.ElasticsearchOperatorUserSecret,
			Namespace: common.OperatorNamespace(),
		},
	})).ShouldNot(HaveOccurred())
}

var _ = Describe("LogStorage controller", func() {
	var (
		cli                client.Client
		mockStatus         *status.MockStatus
		scheme             *runtime.Scheme
		ctx                context.Context
		certificateManager certificatemanager.CertificateManager

		mockServer *httptest.Server
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
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		prometheusTLS, err := certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{render.PrometheusTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		kibanaTLS, err := certificateManager.GetOrCreateKeyPair(cli, relasticsearch.PublicCertSecret, common.OperatorNamespace(), []string{relasticsearch.PublicCertSecret})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, kibanaTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		mockServer = cloudMockEsServer()
	})
	AfterEach(func() {
		mockServer.Close()
	})
	Context("Reconcile", func() {
		Context("Management cluster with image assurance installed", func() {
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

				cloudCreateESAccessSecret(cli, ctx)
			})
			It("sets cloud enabled controllers and env variables on kube controllers", func() {
				mockElasticsearchServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err := w.Write([]byte{})
					Expect(err).NotTo(HaveOccurred())
				}))
				mockElasticsearchServer.Config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
				mockElasticsearchServer.Start()
				defer mockElasticsearchServer.Close()

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
					corev1.EnvVar{Name: "IMAGE_ASSURANCE_SCANNER_CLUSTER_ROLE_NAME", Value: imageassurance.ScannerClusterRoleName},
					corev1.EnvVar{Name: "IMAGE_ASSURANCE_POD_WATCHER_CLUSTER_ROLE_NAME", Value: imageassurance.PodWatcherClusterRoleName},
					corev1.EnvVar{Name: "ENABLED_CONTROLLERS", Value: "authorization,elasticsearchconfiguration,managedcluster,imageassurance"},
				))
				mockStatus.AssertExpectations(GinkgoT())
			})
		})
	})
	Context("Multi-Tenancy", func() {
		Context("Successful Reconcile", func() {
			var install *operatorv1.Installation
			BeforeEach(func() {
				install = &operatorv1.Installation{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
					Status: operatorv1.InstallationStatus{
						Variant:  operatorv1.TigeraSecureEnterprise,
						Computed: &operatorv1.InstallationSpec{},
					},
					Spec: operatorv1.InstallationSpec{
						Variant:  operatorv1.TigeraSecureEnterprise,
						Registry: "some.registry.org/",
					},
				}
				Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

				Expect(cli.Create(
					ctx,
					&operatorv1.ManagementCluster{
						ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
					})).NotTo(HaveOccurred())

				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("AddDaemonsets", mock.Anything)
				mockStatus.On("AddDeployments", mock.Anything)
				mockStatus.On("AddStatefulSets", mock.Anything)
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("ReadyToMonitor")

				cloudCreateESAccessSecret(cli, ctx)
			})
			It("test LogStorage reconciles successfully", func() {
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

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain, true, mockServer)
				Expect(err).ShouldNot(HaveOccurred())

				esAdminUserSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.ElasticsearchAdminUserSecret,
						Namespace: common.OperatorNamespace(),
					},
					Data: map[string][]byte{
						"tigera-mgmt": []byte("password"),
					},
				}
				Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

				esInterncalCertSecret := createPubSecret(relasticsearch.InternalCertSecret, common.OperatorNamespace(), []byte{}, "tls.crt")
				Expect(cli.Create(ctx, esInterncalCertSecret)).ShouldNot(HaveOccurred())

				kbInterncalCertSecret := createPubSecret(render.KibanaInternalCertSecret, common.OperatorNamespace(), []byte{}, "tls.crt")
				Expect(cli.Create(ctx, kbInterncalCertSecret)).ShouldNot(HaveOccurred())

				externalCertsSecret := createPubSecret(esgateway.ExternalCertsSecret, common.OperatorNamespace(), []byte{}, "tls.crt")
				Expect(cli.Create(ctx, externalCertsSecret)).ShouldNot(HaveOccurred())

				kubeControllersElasticUserSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      kubecontrollers.ElasticsearchKubeControllersUserSecret,
						Namespace: common.CalicoNamespace,
					},
					Data: map[string][]byte{
						"username": []byte("username"),
						"password": []byte("password"),
					},
				}
				Expect(cli.Create(ctx, kubeControllersElasticUserSecret)).ShouldNot(HaveOccurred())

				mockStatus.On("SetDegraded", "Failed to retrieve Elasticsearch Gateway config map", "configmaps \"tigera-secure-cloud-config\" not found").Return()
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ToNot(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))

				cloudConfig := cloudconfig.NewCloudConfig("tenantId", "tenantName", "externalES.com", "externalKb.com", true)
				Expect(cli.Create(ctx, cloudConfig.ConfigMap())).ShouldNot(HaveOccurred())

				mockStatus.On("ClearDegraded")

				mockStatus.On("SetDegraded", "Waiting for elasticsearch metrics secrets to become available", "").Return()
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))

				Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: esMetricsUsrSecretObjMeta})).ShouldNot(HaveOccurred())

				mockStatus.On("ClearDegraded")
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))

				mockStatus.AssertExpectations(GinkgoT())

				// Verify that the tenantId has been added to the clusterName.
				clusterConfig := &corev1.ConfigMap{}
				Expect(cli.Get(ctx, client.ObjectKey{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}, clusterConfig)).ToNot(HaveOccurred())
				Expect(clusterConfig.Data["clusterName"]).To(Equal("tenantId.cluster"))
			})
			It("test that a failed Elasticsearch health check degrades LogStorage status", func() {
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

				ms := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(424)
					_, err := w.Write([]byte{})
					Expect(err).NotTo(HaveOccurred())
				}))
				ms.Config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
				ms.Start()
				defer ms.Close()

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain, true, ms)
				Expect(err).ShouldNot(HaveOccurred())

				esAdminUserSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.ElasticsearchAdminUserSecret,
						Namespace: common.OperatorNamespace(),
					},
					Data: map[string][]byte{
						"tigera-mgmt": []byte("password"),
					},
				}
				Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

				esInterncalCertSecret := createPubSecret(relasticsearch.InternalCertSecret, common.OperatorNamespace(), []byte{}, "tls.crt")
				Expect(cli.Create(ctx, esInterncalCertSecret)).ShouldNot(HaveOccurred())

				kbInterncalCertSecret := createPubSecret(render.KibanaInternalCertSecret, common.OperatorNamespace(), []byte{}, "tls.crt")
				Expect(cli.Create(ctx, kbInterncalCertSecret)).ShouldNot(HaveOccurred())

				externalCertsSecret := createPubSecret(esgateway.ExternalCertsSecret, common.OperatorNamespace(), []byte{}, "tls.crt")
				Expect(cli.Create(ctx, externalCertsSecret)).ShouldNot(HaveOccurred())

				kubeControllersElasticUserSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      kubecontrollers.ElasticsearchKubeControllersUserSecret,
						Namespace: common.CalicoNamespace,
					},
					Data: map[string][]byte{
						"username": []byte("username"),
						"password": []byte("password"),
					},
				}
				Expect(cli.Create(ctx, kubeControllersElasticUserSecret)).ShouldNot(HaveOccurred())

				cloudConfig := cloudconfig.NewCloudConfig("tenantId", "tenantName", "externalES.com", "externalKb.com", true)
				Expect(cli.Create(ctx, cloudConfig.ConfigMap())).ShouldNot(HaveOccurred())

				mockStatus.On("ClearDegraded")

				mockStatus.On("SetDegraded", "Elasticsearch health check failed", "").Return()
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))
			})
		})
	})
})
