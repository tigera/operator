// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

package elastic

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	cmnv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/test"
)

var (
	eckOperatorObjKey = client.ObjectKey{Name: render.ECKOperatorName, Namespace: render.ECKOperatorNamespace}
	esObjKey          = client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}
	kbObjKey          = client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}
	curatorObjKey     = types.NamespacedName{Namespace: render.ElasticsearchNamespace, Name: render.ESCuratorName}

	esCertSecretOperKey = client.ObjectKey{Name: render.TigeraElasticsearchGatewaySecret, Namespace: common.OperatorNamespace()}

	kbCertSecretOperKey = client.ObjectKey{Name: render.TigeraKibanaCertSecret, Namespace: common.OperatorNamespace()}

	curatorUsrSecretObjMeta = metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: common.OperatorNamespace()}
	storageClassName        = "test-storage-class"
	kbDNSNames              = dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, dns.DefaultClusterDomain)

	successResult = reconcile.Result{}
)

func NewReconcilerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	esCliCreator utils.ElasticsearchClientCreator,
	clusterDomain string,
	tierWatchReady *utils.ReadyFlag,
) (*ElasticSubController, error) {
	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
	}

	r := &ElasticSubController{
		client:         cli,
		scheme:         scheme,
		esCliCreator:   esCliCreator,
		tierWatchReady: tierWatchReady,
		status:         status,
		usePSP:         opts.UsePSP,
		clusterDomain:  opts.ClusterDomain,
		provider:       opts.DetectedProvider,
		multiTenant:    opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage controller", func() {
	var (
		cli                client.Client
		mockStatus         *status.MockStatus
		readyFlag          *utils.ReadyFlag
		scheme             *runtime.Scheme
		ctx                context.Context
		certificateManager certificatemanager.CertificateManager
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		prometheusTLS, err := certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()

		// Create Elasticsearch KeyPair. This is normally created out of band by the secret controller.
		elasticKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), []string{render.ElasticsearchServiceName})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, elasticKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Create Kibana KeyPair. This is normally created out of band by the secret controller.
		dnsNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, dns.DefaultClusterDomain)
		kbKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraKibanaCertSecret, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, kbKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Create the trusted bundle configmap. This is normally created out of band by the secret controller.
		bundle := certificateManager.CreateTrustedBundle(elasticKeyPair)
		Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).NotTo(HaveOccurred())
	})

	// The ElasticController isn't meant to run on a managed cluster. However there are some edge cases covered by the following tests.
	Context("Managed Cluster", func() {
		BeforeEach(func() {
			// Test that when there is no LogStorage, on a ManagedCluster, that the controller doesn't error.
			var install *operatorv1.Installation
			It("should not error on a managed cluster", func() {
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
					},
				}
				Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

				Expect(cli.Create(ctx, &operatorv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
				})).NotTo(HaveOccurred())

				Expect(cli.Create(ctx, &v3.Tier{
					ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
				})).NotTo(HaveOccurred())

				Expect(cli.Create(
					ctx,
					&operatorv1.ManagementClusterConnection{
						ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
					})).NotTo(HaveOccurred())

				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
			})

			Context("LogStorage is nil", func() {
				// Run the reconciler, expect no error.
				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
				Expect(err).ShouldNot(HaveOccurred())
				_, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
			})

			Context("LogStorage exists", func() {
				// If the LogStorage exists on a managed cluster, the controller should error. The one exception being if the LogStorage is marked for deletion,
				// in which case the controller should facilitate the deletion of the LogStorage.

				BeforeEach(func() {
					setUpLogStorageComponents(cli, ctx, storageClassName, certificateManager)
					mockStatus.On("OnCRFound").Return()
					// mockStatus.On("SetMetaData", mock.Anything).Return()
				})

				It("returns an error if the LogStorage resource exists and is not marked for deletion", func() {
					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
					Expect(err).ShouldNot(HaveOccurred())
					mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "LogStorage validation failed - cluster type is managed but LogStorage CR still exists", mock.Anything, mock.Anything).Return()
					result, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(result).Should(Equal(reconcile.Result{}))
					Expect(err).ShouldNot(HaveOccurred())
					mockStatus.AssertExpectations(GinkgoT())
				})

				It("finalises the deletion of the LogStorage CR when marked for deletion and continues without error", func() {
					mockStatus.On("AddStatefulSets", mock.Anything).Return()
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
					mockStatus.On("AddCronJobs", mock.Anything)
					mockStatus.On("ClearDegraded", mock.Anything).Return()
					mockStatus.On("ReadyToMonitor")
					// mockStatus.On("SetMetaData", mock.Anything).Return()

					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
					Expect(err).ShouldNot(HaveOccurred())

					ls := &operatorv1.LogStorage{}
					Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())

					now := metav1.Now()
					ls.DeletionTimestamp = &now
					ls.SetFinalizers([]string{"tigera.io/eck-cleanup"})
					Expect(cli.Update(ctx, ls)).ShouldNot(HaveOccurred())

					result, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(successResult))

					By("expecting not to find the tigera-secure Elasticsearch or Kibana resources")
					err = cli.Get(ctx, esObjKey, &esv1.Elasticsearch{})
					Expect(errors.IsNotFound(err)).Should(BeTrue())
					err = cli.Get(ctx, kbObjKey, &kbv1.Kibana{})
					Expect(errors.IsNotFound(err)).Should(BeTrue())

					// The LogStorage CR should still contain the finalizer, as we wait for ES and KB to finish deleting
					By("waiting for the Elasticsearch and Kibana resources to be deleted")
					ls = &operatorv1.LogStorage{}
					Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())
					Expect(ls.Finalizers).Should(ContainElement("tigera.io/eck-cleanup"))

					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(successResult))

					By("expecting logstorage to have been deleted after the finalizer was removed")
					ls = &operatorv1.LogStorage{}
					Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).Should(HaveOccurred())

					mockStatus.AssertExpectations(GinkgoT())
				})
			})
		})
	})

	Context("Standalone cluster", func() {
		Context("successful LogStorage Reconcile", func() {
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

				Expect(cli.Create(ctx, &operatorv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
				})).NotTo(HaveOccurred())

				Expect(cli.Create(ctx, &v3.Tier{
					ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
				})).NotTo(HaveOccurred())

				Expect(cli.Create(
					ctx,
					&operatorv1.ManagementCluster{
						ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
					})).NotTo(HaveOccurred())

				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("AddStatefulSets", mock.Anything)
				mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("ReadyToMonitor")
				// mockStatus.On("SetMetaData", mock.Anything).Return()
			})

			It("test LogStorage reconciles successfully", func() {
				Expect(cli.Create(ctx, &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: storageClassName,
					},
				})).ShouldNot(HaveOccurred())

				CreateLogStorage(cli, &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: int64(1),
						},
						StorageClassName: storageClassName,
					},
					Status: operatorv1.LogStorageStatus{
						State: operatorv1.TigeraStatusReady,
					},
				})

				Expect(cli.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
					Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
				})).ShouldNot(HaveOccurred())

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
				Expect(err).ShouldNot(HaveOccurred())

				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", mock.Anything, mock.Anything).Return()
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// Expect to be waiting for Elasticsearch and Kibana to be functional
				Expect(result).Should(Equal(reconcile.Result{}))

				By("asserting the finalizers have been set on the LogStorage CR")
				ls := &operatorv1.LogStorage{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
				Expect(ls.Finalizers).Should(ContainElement("tigera.io/eck-cleanup"))
				Expect(ls.Spec.StorageClassName).To(Equal(storageClassName))

				Expect(cli.Get(ctx, eckOperatorObjKey, &appsv1.StatefulSet{})).ShouldNot(HaveOccurred())

				es := &esv1.Elasticsearch{}
				Expect(cli.Get(ctx, esObjKey, es)).ShouldNot(HaveOccurred())

				es.Status.Phase = esv1.ElasticsearchReadyPhase
				Expect(cli.Update(ctx, es)).ShouldNot(HaveOccurred())

				kb := &kbv1.Kibana{}
				Expect(cli.Get(ctx, kbObjKey, kb)).ShouldNot(HaveOccurred())

				kb.Status.AssociationStatus = cmnv1.AssociationEstablished
				Expect(cli.Update(ctx, kb)).ShouldNot(HaveOccurred())

				// Create public KB secret. This is created by the secret controller in a real cluster.
				kibanaKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, render.TigeraKibanaCertSecret, common.OperatorNamespace(), kbDNSNames)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cli.Create(ctx, kibanaKeyPair.Secret(render.KibanaNamespace))).ShouldNot(HaveOccurred())

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

				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for curator secrets to become available", mock.Anything, mock.Anything).Return()
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// Expect to be waiting for curator secret
				Expect(result).Should(Equal(reconcile.Result{}))
				Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())

				mockStatus.On("ClearDegraded")
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(successResult))

				By("confirming curator job is created")
				Expect(cli.Get(ctx, curatorObjKey, &batchv1.CronJob{})).ShouldNot(HaveOccurred())

				mockStatus.AssertExpectations(GinkgoT())
			})

			It("test LogStorage reconciles successfully for elasticsearch basic license", func() {
				Expect(cli.Create(ctx, &operatorv1.Authentication{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec: operatorv1.AuthenticationSpec{
						ManagerDomain: "https://example.com",
						OIDC: &operatorv1.AuthenticationOIDC{
							IssuerURL:     "https://example.com",
							UsernameClaim: "email",
							GroupsClaim:   "group",
						},
					},
					Status: operatorv1.AuthenticationStatus{State: operatorv1.TigeraStatusReady},
				})).ToNot(HaveOccurred())

				Expect(cli.Create(ctx, render.CreateDexClientSecret())).ToNot(HaveOccurred())

				Expect(cli.Create(ctx, &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: storageClassName,
					},
				})).ShouldNot(HaveOccurred())

				CreateLogStorage(cli, &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: int64(1),
						},
						StorageClassName: storageClassName,
					},
					Status: operatorv1.LogStorageStatus{
						State: operatorv1.TigeraStatusReady,
					},
				})

				Expect(cli.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
					Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeBasic)},
				})).ShouldNot(HaveOccurred())

				Expect(cli.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersConfigMapName},
				})).ShouldNot(HaveOccurred())

				Expect(cli.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersESSecretName},
				})).ShouldNot(HaveOccurred())

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
				Expect(err).ShouldNot(HaveOccurred())

				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", mock.Anything, mock.Anything).Return()
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				// Expect to be waiting for Elasticsearch and Kibana to be functional
				Expect(result).Should(Equal(reconcile.Result{}))

				By("asserting the finalizers have been set on the LogStorage CR")
				ls := &operatorv1.LogStorage{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
				Expect(ls.Finalizers).Should(ContainElement("tigera.io/eck-cleanup"))
				Expect(ls.Spec.StorageClassName).To(Equal(storageClassName))

				Expect(cli.Get(ctx, eckOperatorObjKey, &appsv1.StatefulSet{})).ShouldNot(HaveOccurred())

				es := &esv1.Elasticsearch{}
				Expect(cli.Get(ctx, esObjKey, es)).ShouldNot(HaveOccurred())

				es.Status.Phase = esv1.ElasticsearchReadyPhase
				Expect(cli.Update(ctx, es)).ShouldNot(HaveOccurred())

				kb := &kbv1.Kibana{}
				Expect(cli.Get(ctx, kbObjKey, kb)).ShouldNot(HaveOccurred())

				kb.Status.AssociationStatus = cmnv1.AssociationEstablished
				Expect(cli.Update(ctx, kb)).ShouldNot(HaveOccurred())

				// Create public KB secret. This is created by the secret controller in a real cluster.
				kibanaKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, render.TigeraKibanaCertSecret, common.OperatorNamespace(), kbDNSNames)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cli.Create(ctx, kibanaKeyPair.Secret(render.KibanaNamespace))).ShouldNot(HaveOccurred())

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

				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for curator secrets to become available", mock.Anything, mock.Anything).Return()
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// Expect to be waiting for curator secret
				Expect(result).Should(Equal(reconcile.Result{}))
				Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())

				mockStatus.On("ClearDegraded")
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(successResult))

				By("confirming curator job is created")
				Expect(cli.Get(ctx, curatorObjKey, &batchv1.CronJob{})).ShouldNot(HaveOccurred())

				By("confirming logstorage is degraded if ConfigMap is not available")
				mockStatus.On("SetDegraded", operatorv1.ResourceReadError, "Failed to get oidc user Secret and ConfigMap", "configmaps \"tigera-known-oidc-users\" not found", mock.Anything).Return()
				Expect(cli.Delete(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersConfigMapName},
				})).ShouldNot(HaveOccurred())

				Expect(cli.Delete(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersESSecretName},
				})).ShouldNot(HaveOccurred())
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).Should(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))

				mockStatus.AssertExpectations(GinkgoT())
			})

			It("test that LogStorage reconciles if the user-supplied certs have any DNS names", func() {
				// This test currently just validates that user-provided
				// certs will reconcile and not return an error and won't be
				// overwritten by the operator. This test
				// will change once we add validation for user-provided
				// certs.
				esDNSNames := []string{"es.example.com", "192.168.10.10"}
				testCA := test.MakeTestCA("logstorage-test")
				esSecret, err := secret.CreateTLSSecret(testCA,
					render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), "tls.key", "tls.crt",
					rmeta.DefaultCertificateDuration, nil, esDNSNames...,
				)
				Expect(err).ShouldNot(HaveOccurred())

				esPublicSecret := createPubSecret(relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, esSecret.Data["tls.crt"], "tls.crt")
				Expect(cli.Create(ctx, esSecret)).ShouldNot(HaveOccurred())
				Expect(cli.Create(ctx, esPublicSecret)).ShouldNot(HaveOccurred())

				kbDNSNames = []string{"kb.example.com", "192.168.10.11"}
				kbSecret, err := secret.CreateTLSSecret(testCA,
					render.TigeraKibanaCertSecret, common.OperatorNamespace(), "tls.key", "tls.crt", rmeta.DefaultCertificateDuration, nil, kbDNSNames...,
				)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cli.Update(ctx, kbSecret)).ShouldNot(HaveOccurred())

				Expect(cli.Create(ctx, &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: storageClassName,
					},
				})).ShouldNot(HaveOccurred())

				CreateLogStorage(cli, &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: int64(1),
						},
						StorageClassName: storageClassName,
					},
					Status: operatorv1.LogStorageStatus{
						State: operatorv1.TigeraStatusReady,
					},
				})

				Expect(cli.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
					Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
				})).ShouldNot(HaveOccurred())

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
				Expect(err).ShouldNot(HaveOccurred())

				// Elasticsearch and kibana secrets are good.
				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", mock.Anything, mock.Anything).Return()
				_, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				Expect(cli.Get(ctx, esCertSecretOperKey, esSecret)).ShouldNot(HaveOccurred())
				test.VerifyCert(esSecret, esDNSNames...)

				Expect(cli.Get(ctx, kbCertSecretOperKey, kbSecret)).ShouldNot(HaveOccurred())
				test.VerifyCert(kbSecret, kbDNSNames...)
			})

			It("should not add OwnerReference to user supplied kibana TLS cert", func() {
				mockStatus.On("ClearDegraded", mock.Anything)

				Expect(cli.Create(ctx, &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: storageClassName,
					},
				})).ShouldNot(HaveOccurred())

				CreateLogStorage(cli, &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						StorageClassName: storageClassName,
					},
					Status: operatorv1.LogStorageStatus{
						State: operatorv1.TigeraStatusReady,
					},
				})

				testCA := test.MakeTestCA("logstorage-test")
				kbSecret, err := secret.CreateTLSSecret(testCA,
					render.TigeraKibanaCertSecret, common.OperatorNamespace(), "tls.key", "tls.crt",
					rmeta.DefaultCertificateDuration, nil, "tigera-secure-kb-http.tigera-elasticsearch.svc",
				)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cli.Update(ctx, kbSecret)).ShouldNot(HaveOccurred())

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
				Expect(err).ShouldNot(HaveOccurred())

				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", mock.Anything, mock.Anything).Return()
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				// Expect to be waiting for Elasticsearch and Kibana to be functional
				Expect(result).Should(Equal(reconcile.Result{}))

				secret := &corev1.Secret{}
				Expect(cli.Get(ctx, kbCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
				Expect(secret.GetOwnerReferences()).To(HaveLen(0))
			})

			It("should not add OwnerReference to user supplied ES gateway TLS cert", func() {
				mockStatus.On("ClearDegraded", mock.Anything)

				CreateLogStorage(cli, &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: int64(1),
						},
						StorageClassName: storageClassName,
					},
					Status: operatorv1.LogStorageStatus{
						State: operatorv1.TigeraStatusReady,
					},
				})

				resources := []client.Object{
					&storagev1.StorageClass{
						ObjectMeta: metav1.ObjectMeta{
							Name: storageClassName,
						},
					},
					&esv1.Elasticsearch{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchName,
							Namespace: render.ElasticsearchNamespace,
						},
						Status: esv1.ElasticsearchStatus{
							Phase: esv1.ElasticsearchReadyPhase,
						},
					},
					&kbv1.Kibana{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.KibanaName,
							Namespace: render.KibanaNamespace,
						},
						Status: kbv1.KibanaStatus{
							AssociationStatus: cmnv1.AssociationEstablished,
						},
					},
					&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
						Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchAdminUserSecret,
							Namespace: render.ElasticsearchNamespace,
						},
						Data: map[string][]byte{
							"elastic": []byte("password"),
						},
					},
				}

				testCA := test.MakeTestCA("logstorage-test")
				dnsNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
				kbSecret, err := secret.CreateTLSSecret(testCA,
					render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), corev1.TLSPrivateKeyKey, corev1.TLSCertKey,
					rmeta.DefaultCertificateDuration, nil, dnsNames...,
				)
				Expect(err).ShouldNot(HaveOccurred())
				resources = append(resources, kbSecret)

				for _, rec := range resources {
					Expect(cli.Create(ctx, rec)).ShouldNot(HaveOccurred())
				}

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
				Expect(err).ShouldNot(HaveOccurred())

				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for curator secrets to become available", mock.Anything, mock.Anything).Return()
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))

				secret := &corev1.Secret{}
				Expect(cli.Get(ctx, esCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
				Expect(secret.GetOwnerReferences()).To(HaveLen(0))
			})

			It("should add OwnerReference to the public elasticsearch TLS cert secret", func() {
				Expect(cli.Create(ctx, &storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: storageClassName,
					},
				})).ShouldNot(HaveOccurred())

				CreateLogStorage(cli, &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: int64(1),
						},
						StorageClassName: storageClassName,
					},
					Status: operatorv1.LogStorageStatus{
						State: operatorv1.TigeraStatusReady,
					},
				})

				Expect(cli.Create(ctx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
					Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
				})).ShouldNot(HaveOccurred())

				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
				Expect(err).ShouldNot(HaveOccurred())

				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", mock.Anything, mock.Anything).Return()
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				// Expect to be waiting for Elasticsearch and Kibana to be functional
				Expect(result).Should(Equal(reconcile.Result{}))
			})

			Context("checking rendered images", func() {
				BeforeEach(func() {
					mockStatus.On("ClearDegraded", mock.Anything)

					CreateLogStorage(cli, &operatorv1.LogStorage{
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
						},
						Spec: operatorv1.LogStorageSpec{
							Nodes: &operatorv1.Nodes{
								Count: int64(1),
							},
							StorageClassName: storageClassName,
						},
						Status: operatorv1.LogStorageStatus{
							State: operatorv1.TigeraStatusReady,
						},
					})

					resources := []client.Object{
						&storagev1.StorageClass{
							ObjectMeta: metav1.ObjectMeta{
								Name: storageClassName,
							},
						},
						&esv1.Elasticsearch{
							ObjectMeta: metav1.ObjectMeta{
								Name:      render.ElasticsearchName,
								Namespace: render.ElasticsearchNamespace,
							},
							Status: esv1.ElasticsearchStatus{
								Phase: esv1.ElasticsearchReadyPhase,
							},
						},
						&kbv1.Kibana{
							ObjectMeta: metav1.ObjectMeta{
								Name:      render.KibanaName,
								Namespace: render.KibanaNamespace,
							},
							Status: kbv1.KibanaStatus{
								AssociationStatus: cmnv1.AssociationEstablished,
							},
						},
						relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap(),
						&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
						&corev1.ConfigMap{
							ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
							Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
						},
						&corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta},
						&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
							Name: render.ElasticsearchCuratorUserSecret, Namespace: render.ElasticsearchNamespace,
						}},
					}

					for _, rec := range resources {
						Expect(cli.Create(ctx, rec)).ShouldNot(HaveOccurred())
					}
				})

				It("should use default images", func() {
					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
					Expect(err).ShouldNot(HaveOccurred())

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

					By("running reconcile")
					_, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					By("confirming curator job is created")
					Expect(cli.Get(ctx, curatorObjKey, &batchv1.CronJob{})).ShouldNot(HaveOccurred())

					mockStatus.AssertExpectations(GinkgoT())

					cj := batchv1.CronJob{
						TypeMeta: metav1.TypeMeta{Kind: "CronJob", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ESCuratorName,
							Namespace: render.ElasticsearchNamespace,
						},
					}
					Expect(test.GetResource(cli, &cj)).To(BeNil())
					Expect(cj.Spec.JobTemplate.Spec.Template.Spec.Containers).To(HaveLen(1))
					curator := test.GetContainer(cj.Spec.JobTemplate.Spec.Template.Spec.Containers, render.ESCuratorName)
					Expect(curator).ToNot(BeNil())
					Expect(curator.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s:%s",
							components.ComponentEsCurator.Image,
							components.ComponentEsCurator.Version)))

					escfg := esv1.Elasticsearch{
						TypeMeta: metav1.TypeMeta{Kind: "Elasticsearch", APIVersion: "elasticsearch.k8s.elastic.co/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchName,
							Namespace: render.ElasticsearchNamespace,
						},
					}
					Expect(test.GetResource(cli, &escfg)).To(BeNil())
					Expect(escfg.Spec.NodeSets).To(HaveLen(1))
					// The Image is not populated for the container so no need to get and check it
					Expect(escfg.Spec.NodeSets[0].PodTemplate.Spec.Containers).To(HaveLen(1))
					Expect(escfg.Spec.NodeSets[0].PodTemplate.Spec.InitContainers).To(HaveLen(1))
					initset := test.GetContainer(escfg.Spec.NodeSets[0].PodTemplate.Spec.InitContainers, "elastic-internal-init-os-settings")
					Expect(initset).ToNot(BeNil())
					Expect(initset.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s:%s",
							components.ComponentElasticsearch.Image,
							components.ComponentElasticsearch.Version)))

					kb := kbv1.Kibana{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.KibanaName,
							Namespace: render.KibanaNamespace,
						},
					}
					Expect(test.GetResource(cli, &kb)).To(BeNil())
					Expect(kb.Spec.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s:%s",
							components.ComponentKibana.Image,
							components.ComponentKibana.Version)))

					ss := appsv1.StatefulSet{
						TypeMeta: metav1.TypeMeta{Kind: "StatefuleSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ECKOperatorName,
							Namespace: render.ECKOperatorNamespace,
						},
					}
					Expect(test.GetResource(cli, &ss)).To(BeNil())
					Expect(ss.Spec.Template.Spec.Containers).To(HaveLen(1))
					mgr := test.GetContainer(ss.Spec.Template.Spec.Containers, "manager")
					Expect(mgr).ToNot(BeNil())
					Expect(mgr.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s:%s",
							components.ComponentElasticsearchOperator.Image,
							components.ComponentElasticsearchOperator.Version)))
				})

				It("should use images from ImageSet", func() {
					Expect(cli.Create(ctx, &operatorv1.ImageSet{
						ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
						Spec: operatorv1.ImageSetSpec{
							Images: []operatorv1.Image{
								{Image: "tigera/elasticsearch", Digest: "sha256:elasticsearchhash"},
								{Image: "tigera/kube-controllers", Digest: "sha256:kubecontrollershash"},
								{Image: "tigera/kibana", Digest: "sha256:kibanahash"},
								{Image: "tigera/eck-operator", Digest: "sha256:eckoperatorhash"},
								{Image: "tigera/es-curator", Digest: "sha256:escuratorhash"},
								{Image: "tigera/elasticsearch-metrics", Digest: "sha256:esmetricshash"},
								{Image: "tigera/es-gateway", Digest: "sha256:esgatewayhash"},
								{Image: "tigera/linseed", Digest: "sha256:linseedhash"},
							},
						},
					})).ToNot(HaveOccurred())
					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
					Expect(err).ShouldNot(HaveOccurred())

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

					By("running reconcile")
					_, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					By("confirming curator job is created")
					Expect(cli.Get(ctx, curatorObjKey, &batchv1.CronJob{})).ShouldNot(HaveOccurred())

					mockStatus.AssertExpectations(GinkgoT())

					cj := batchv1.CronJob{
						TypeMeta: metav1.TypeMeta{Kind: "CronJob", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ESCuratorName,
							Namespace: render.ElasticsearchNamespace,
						},
					}
					Expect(test.GetResource(cli, &cj)).To(BeNil())
					Expect(cj.Spec.JobTemplate.Spec.Template.Spec.Containers).To(HaveLen(1))
					curator := test.GetContainer(cj.Spec.JobTemplate.Spec.Template.Spec.Containers, render.ESCuratorName)
					Expect(curator).ToNot(BeNil())
					Expect(curator.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s@%s",
							components.ComponentEsCurator.Image,
							"sha256:escuratorhash")))

					escfg := esv1.Elasticsearch{
						TypeMeta: metav1.TypeMeta{Kind: "Elasticsearch", APIVersion: "elasticsearch.k8s.elastic.co/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchName,
							Namespace: render.ElasticsearchNamespace,
						},
					}
					Expect(test.GetResource(cli, &escfg)).To(BeNil())
					Expect(escfg.Spec.NodeSets).To(HaveLen(1))
					// The Image is not populated for the container so no need to get and check it
					Expect(escfg.Spec.NodeSets[0].PodTemplate.Spec.Containers).To(HaveLen(1))
					Expect(escfg.Spec.NodeSets[0].PodTemplate.Spec.InitContainers).To(HaveLen(1))
					initset := test.GetContainer(escfg.Spec.NodeSets[0].PodTemplate.Spec.InitContainers, "elastic-internal-init-os-settings")
					Expect(initset).ToNot(BeNil())
					Expect(initset.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s@%s",
							components.ComponentElasticsearch.Image,
							"sha256:elasticsearchhash")))

					kb := kbv1.Kibana{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.KibanaName,
							Namespace: render.KibanaNamespace,
						},
					}
					Expect(test.GetResource(cli, &kb)).To(BeNil())
					Expect(kb.Spec.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s@%s",
							components.ComponentKibana.Image,
							"sha256:kibanahash")))

					ss := appsv1.StatefulSet{
						TypeMeta: metav1.TypeMeta{Kind: "StatefuleSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ECKOperatorName,
							Namespace: render.ECKOperatorNamespace,
						},
					}
					Expect(test.GetResource(cli, &ss)).To(BeNil())
					Expect(ss.Spec.Template.Spec.Containers).To(HaveLen(1))
					mgr := test.GetContainer(ss.Spec.Template.Spec.Containers, "manager")
					Expect(mgr).ToNot(BeNil())
					Expect(mgr.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s@%s",
							components.ComponentElasticsearchOperator.Image,
							"sha256:eckoperatorhash")))
				})
			})

			Context("allow-tigera rendering", func() {
				var r reconcile.Reconciler
				BeforeEach(func() {
					Expect(cli.Create(ctx, &storagev1.StorageClass{
						ObjectMeta: metav1.ObjectMeta{
							Name: storageClassName,
						},
					})).ShouldNot(HaveOccurred())

					CreateLogStorage(cli, &operatorv1.LogStorage{
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
						},
						Spec: operatorv1.LogStorageSpec{
							Nodes: &operatorv1.Nodes{
								Count: int64(1),
							},
							StorageClassName: storageClassName,
						},
						Status: operatorv1.LogStorageStatus{
							State: operatorv1.TigeraStatusReady,
						},
					})

					Expect(cli.Create(ctx, &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
						Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
					})).ShouldNot(HaveOccurred())

					mockStatus = &status.MockStatus{}
					mockStatus.On("Run").Return()
					mockStatus.On("OnCRFound").Return()
					// mockStatus.On("SetMetaData", mock.Anything).Return()

					var err error
					r, err = NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("should wait if allow-tigera tier is unavailable", func() {
					utils.DeleteAllowTigeraTierAndExpectWait(ctx, cli, r, mockStatus)
				})

				It("should wait if tier watch is not ready", func() {
					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, &utils.ReadyFlag{})
					Expect(err).ShouldNot(HaveOccurred())
					utils.ExpectWaitForTierWatch(ctx, r, mockStatus)
				})
			})
		})

		Context("LogStorage CR deleted", func() {
			var mockStatus *status.MockStatus

			BeforeEach(func() {
				var replicas int32 = 2
				Expect(cli.Create(ctx, &operatorv1.Installation{
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
					},
				})).ShouldNot(HaveOccurred())

				Expect(cli.Create(ctx, &operatorv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
				})).NotTo(HaveOccurred())

				Expect(cli.Create(ctx, &v3.Tier{
					ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
				})).NotTo(HaveOccurred())

				Expect(cli.Create(
					ctx,
					&operatorv1.ManagementCluster{
						ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
					})).NotTo(HaveOccurred())

				setUpLogStorageComponents(cli, ctx, "", certificateManager)

				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("AddStatefulSets", mock.Anything)
				mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("ClearDegraded", mock.Anything)
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("ReadyToMonitor")
				// mockStatus.On("SetMetaData", mock.Anything).Return()
				readyFlag = &utils.ReadyFlag{}
				readyFlag.MarkAsReady()
			})

			It("deletes Elasticsearch and Kibana then removes the finalizers on the LogStorage CR", func() {
				r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockESCLICreator, dns.DefaultClusterDomain, readyFlag)
				Expect(err).ShouldNot(HaveOccurred())

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

				By("making sure LogStorage has successfully reconciled")

				// The first reconcile should create the Elasticsearch and Kibana resources, but won't
				// complete the reconcile because the Elasticsearch and Kibana clusters won't be ready.
				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Kibana cluster to be created", nil, mock.Anything)
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))

				// However, the Kibana and ES instances should have been created.
				Expect(cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, &esv1.Elasticsearch{})).ShouldNot(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}, &kbv1.Kibana{})).ShouldNot(HaveOccurred())

				// Update the Kibana instance to be considered ready.
				kb := &kbv1.Kibana{}
				Expect(cli.Get(ctx, client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}, kb)).ShouldNot(HaveOccurred())
				kb.Status.AssociationStatus = cmnv1.AssociationEstablished
				Expect(cli.Status().Update(ctx, kb)).ShouldNot(HaveOccurred())

				By("setting the DeletionTimestamp on the LogStorage CR")
				ls := &operatorv1.LogStorage{}
				Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())
				// The fake library does seem to respect finalizers when Delete is called, so we need to manually set the
				// DeletionTimestamp.
				now := metav1.Now()
				ls.DeletionTimestamp = &now
				Expect(cli.Update(ctx, ls)).ShouldNot(HaveOccurred())
				Expect(ls.Spec.StorageClassName).To(Equal(initializer.DefaultElasticsearchStorageClass))

				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(successResult))

				By("expecting tigera-secure Elasticsearch or Kibana resources to have been deleted")
				err = cli.Get(ctx, esObjKey, &esv1.Elasticsearch{})
				Expect(errors.IsNotFound(err)).Should(BeTrue())
				err = cli.Get(ctx, kbObjKey, &kbv1.Kibana{})
				Expect(errors.IsNotFound(err)).Should(BeTrue())

				// The LogStorage CR should still contain the finalizer, as we wait for ES and KB to finish deleting
				By("checking LogStorage finalizer")
				ls = &operatorv1.LogStorage{}
				Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())
				Expect(ls.Finalizers).Should(ContainElement("tigera.io/eck-cleanup"))

				// One more reconcile should remove the finalizer and thus trigger deletion of the CR.
				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", mock.Anything, mock.Anything).Return()
				result, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).Should(Equal(reconcile.Result{}))

				By("expecting the LogStorage CR to have been cleaned up")
				ls = &operatorv1.LogStorage{}
				Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).Should(HaveOccurred())

				mockStatus.AssertExpectations(GinkgoT())
			})
		})
	})
})

func setUpLogStorageComponents(cli client.Client, ctx context.Context, storageClass string, certificateManager certificatemanager.CertificateManager) {
	if storageClass == "" {
		Expect(cli.Create(ctx, &storagev1.StorageClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: initializer.DefaultElasticsearchStorageClass,
			},
		})).ShouldNot(HaveOccurred())
	} else {
		Expect(cli.Create(ctx, &storagev1.StorageClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: storageClass,
			},
		})).ShouldNot(HaveOccurred())
	}

	retention := int32(1)
	ls := &operatorv1.LogStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-secure",
		},
		Spec: operatorv1.LogStorageSpec{
			Nodes: &operatorv1.Nodes{
				Count: int64(1),
			},
			Retention: &operatorv1.Retention{
				Flows:             &retention,
				AuditReports:      &retention,
				Snapshots:         &retention,
				ComplianceReports: &retention,
				DNSLogs:           &retention,
				BGPLogs:           &retention,
			},
			StorageClassName: storageClass,
		},
		Status: operatorv1.LogStorageStatus{
			State: operatorv1.TigeraStatusReady,
		},
	}

	// TODO: setLogStorageFinalizer(ls)

	By("creating all the components needed for LogStorage to be available")
	trustedBundle := certificateManager.CreateTrustedBundle()
	esKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), []string{render.TigeraElasticsearchInternalCertSecret})
	Expect(err).NotTo(HaveOccurred())
	esPublic, err := certificateManager.GetOrCreateKeyPair(cli, relasticsearch.PublicCertSecret, common.OperatorNamespace(), []string{render.TigeraElasticsearchInternalCertSecret})
	Expect(err).NotTo(HaveOccurred())
	Expect(cli.Create(context.Background(), esPublic.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

	var replicas int32 = 2
	cfg := &render.ElasticsearchConfiguration{
		LogStorage: ls,
		Installation: &operatorv1.InstallationSpec{
			ControlPlaneReplicas: &replicas,
			KubernetesProvider:   operatorv1.ProviderNone,
			Registry:             "testregistry.com/",
		},
		Elasticsearch:        &esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
		Kibana:               &kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace}},
		ClusterConfig:        relasticsearch.NewClusterConfig("cluster", 1, 1, 1),
		ElasticsearchKeyPair: esKeyPair,
		TrustedBundle:        trustedBundle,
		PullSecrets: []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
		},
		Provider: operatorv1.ProviderNone,
		CuratorSecrets: []*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: common.OperatorNamespace()}},
		},
		ClusterDomain:      "cluster.local",
		ElasticLicenseType: render.ElasticsearchLicenseTypeBasic,
	}

	component := render.LogStorage(cfg)

	CreateLogStorage(cli, ls)

	createObj, _ := component.Objects()
	for _, obj := range createObj {
		switch x := obj.(type) {
		case *esv1.Elasticsearch:
			By("setting the Elasticsearch status to operational so we pass the Elasticsearch ready check")
			x.Status.Phase = esv1.ElasticsearchReadyPhase
			obj = x

		case *kbv1.Kibana:
			By("setting the Kibana status to operational so we pass the Kibana ready check")
			x.Status.AssociationStatus = cmnv1.AssociationEstablished
			obj = x
		}

		Expect(cli.Create(ctx, obj)).ShouldNot(HaveOccurred())
	}
	Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())
}

func createPubSecret(name string, ns string, bytes []byte, certName string) client.Object {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
		},
		Data: map[string][]byte{
			certName: bytes,
		},
	}
}

// CreateLogStorage creates a LogStorage object with the given parameters after filling in defaults,
// and asserts that the creation succeeds.
func CreateLogStorage(client client.Client, ls *operatorv1.LogStorage) {
	// First, simulate the initializing controller being run by filling defaults.
	initializer.FillDefaults(ls)

	// Create the LogStorage object.
	ExpectWithOffset(1, client.Create(context.Background(), ls)).ShouldNot(HaveOccurred())
}

type mockESClient struct{}

func mockESCLICreator(client client.Client, ctx context.Context, elasticHTTPSEndpoint string) (utils.ElasticClient, error) {
	return &mockESClient{}, nil
}

func (m *mockESClient) CreateUser(ctx context.Context, user *utils.User) error {
	return fmt.Errorf("CreateUser not implemented in mock client")
}

func (*mockESClient) SetILMPolicies(ctx context.Context, ls *operatorv1.LogStorage) error {
	return nil
}
