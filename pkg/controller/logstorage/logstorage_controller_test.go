// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package logstorage

import (
	"context"
	"fmt"
	"reflect"

	"github.com/tigera/operator/pkg/common"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/test"

	"github.com/stretchr/testify/mock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"

	operatorv1 "github.com/tigera/operator/api/v1"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

var (
	eckOperatorObjKey = client.ObjectKey{Name: render.ECKOperatorName, Namespace: render.ECKOperatorNamespace}
	esObjKey          = client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}
	kbObjKey          = client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}
	curatorObjKey     = types.NamespacedName{Namespace: render.ElasticsearchNamespace, Name: render.EsCuratorName}

	esCertSecretKey        = client.ObjectKey{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}
	esCertSecretOperKey    = client.ObjectKey{Name: render.TigeraElasticsearchCertSecret, Namespace: rmeta.OperatorNamespace()}
	esCertPubSecretKey     = client.ObjectKey{Name: relasticsearch.PublicCertSecret, Namespace: render.ElasticsearchNamespace}
	esCertPubSecretOperKey = client.ObjectKey{Name: relasticsearch.PublicCertSecret, Namespace: rmeta.OperatorNamespace()}

	kbCertSecretKey        = client.ObjectKey{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}
	kbCertSecretOperKey    = client.ObjectKey{Name: render.TigeraKibanaCertSecret, Namespace: rmeta.OperatorNamespace()}
	kbCertPubSecretKey     = client.ObjectKey{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}
	kbCertPubSecretOperKey = client.ObjectKey{Name: render.KibanaPublicCertSecret, Namespace: rmeta.OperatorNamespace()}

	esPublicCertObjMeta       = metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: render.ElasticsearchNamespace}
	kbPublicCertObjMeta       = metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}
	curatorUsrSecretObjMeta   = metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: rmeta.OperatorNamespace()}
	esMetricsUsrSecretObjMeta = metav1.ObjectMeta{Name: esmetrics.ElasticsearchMetricsSecret, Namespace: rmeta.OperatorNamespace()}
	operatorUsrSecretObjMeta  = metav1.ObjectMeta{Name: render.ElasticsearchOperatorUserSecret, Namespace: rmeta.OperatorNamespace()}
	storageClassName          = "test-storage-class"

	esDNSNames = dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	kbDNSNames = dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, dns.DefaultClusterDomain)
)

func mockEsCliCreator(client client.Client, ctx context.Context, elasticHTTPSEndpoint string) (utils.ElasticClient, error) {
	return &mockESClient{}, nil
}

type mockESClient struct {
}

var _ = Describe("LogStorage controller", func() {
	var (
		cli        client.Client
		mockStatus *status.MockStatus
		scheme     *runtime.Scheme
		ctx        context.Context
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
	})
	Context("Reconcile", func() {
		Context("Check default logstorage settings", func() {
			var ls *operatorv1.LogStorage
			var err error
			BeforeEach(func() {
				Expect(cli.Create(ctx, &operatorv1.LogStorage{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.LogStorageSpec{
						Nodes: &operatorv1.Nodes{
							Count: int64(1),
						},
					},
				})).To(BeNil())
				ls, err = GetLogStorage(ctx, cli)
				Expect(err).To(BeNil())
			})

			It("should set the replica values to the default settings", func() {
				retain8 := int32(8)
				retain91 := int32(91)
				Expect(ls.Spec.Retention.Flows).To(Equal(&retain8))
				Expect(ls.Spec.Retention.AuditReports).To(Equal(&retain91))
				Expect(ls.Spec.Retention.ComplianceReports).To(Equal(&retain91))
				Expect(ls.Spec.Retention.Snapshots).To(Equal(&retain91))
			})

			It("should set the retention values to the default settings", func() {
				var replicas int32 = render.DefaultElasticsearchReplicas
				Expect(ls.Spec.Indices.Replicas).To(Equal(&replicas))
			})

			It("should set the storage class to the default settings", func() {
				Expect(ls.Spec.StorageClassName).To(Equal(DefaultElasticsearchStorageClass))
			})

			It("should default the spec.nodes structure", func() {
				Expect(ls.Spec.Nodes).NotTo(BeNil())
				Expect(ls.Spec.Nodes.Count).To(Equal(int64(1)))
			})

			It("should set spec.componentResources to the default settings", func() {
				limits := corev1.ResourceList{}
				requests := corev1.ResourceList{}
				limits[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
				requests[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
				expectedComponentResources := []operatorv1.LogStorageComponentResource{
					{
						ComponentName: operatorv1.ComponentNameECKOperator,
						ResourceRequirements: &corev1.ResourceRequirements{
							Limits:   limits,
							Requests: requests,
						},
					},
				}
				Expect(ls.Spec.ComponentResources).NotTo(BeNil())
				Expect(reflect.DeepEqual(expectedComponentResources, ls.Spec.ComponentResources)).To(BeTrue())
			})
		})

		It("should not panic if an empty log storage is provided", func() {
			Expect(cli.Create(ctx, &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{},
			})).To(BeNil())
			ls, err := GetLogStorage(ctx, cli)
			Expect(err).To(BeNil())

			Expect(ls.Spec.Nodes).NotTo(BeNil())
			Expect(ls.Spec.Nodes.Count).To(Equal(int64(1)))
		})

		Context("Managed Cluster", func() {
			Context("LogStorage is nil", func() {
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
							Variant: operatorv1.TigeraSecureEnterprise,
						},
					}
					Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

					Expect(cli.Create(
						ctx,
						&operatorv1.ManagementClusterConnection{
							ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
						})).NotTo(HaveOccurred())

					mockStatus = &status.MockStatus{}
					mockStatus.On("Run").Return()
				})
				Context("ExternalService is correctly setup", func() {
					BeforeEach(func() {
						mockStatus.On("AddDaemonsets", mock.Anything).Return()
						mockStatus.On("AddDeployments", mock.Anything).Return()
						mockStatus.On("AddStatefulSets", mock.Anything).Return()
						mockStatus.On("AddCronJobs", mock.Anything)
						mockStatus.On("OnCRNotFound").Return()
						mockStatus.On("ClearDegraded")
						mockStatus.On("ReadyToMonitor")
					})
					DescribeTable("tests that the ExternalService is setup with the default service name", func(clusterDomain, expectedSvcName string) {
						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, clusterDomain)
						Expect(err).ShouldNot(HaveOccurred())
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						svc := &corev1.Service{}
						Expect(
							cli.Get(ctx, client.ObjectKey{Name: esgateway.EsGatewayElasticServiceName, Namespace: render.ElasticsearchNamespace}, svc),
						).ShouldNot(HaveOccurred())

						Expect(svc.Spec.ExternalName).Should(Equal(expectedSvcName))
						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
					},
						Entry("default cluster domain", dns.DefaultClusterDomain, "tigera-guardian.tigera-guardian.svc.cluster.local"),
						Entry("custom cluster domain", "custom-domain.internal", "tigera-guardian.tigera-guardian.svc.custom-domain.internal"),
					)
				})

				Context("LogStorage exists", func() {
					BeforeEach(func() {
						setUpLogStorageComponents(cli, ctx, storageClassName, nil)
						mockStatus.On("OnCRFound").Return()
					})

					It("returns an error if the LogStorage resource exists and is not marked for deletion", func() {
						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
						Expect(err).ShouldNot(HaveOccurred())
						mockStatus.On("SetDegraded", "LogStorage validation failed", "cluster type is managed but LogStorage CR still exists").Return()
						result, err := r.Reconcile(ctx, reconcile.Request{})
						Expect(result).Should(Equal(reconcile.Result{}))
						Expect(err).ShouldNot(HaveOccurred())

						mockStatus.AssertExpectations(GinkgoT())
					})

					It("finalises the deletion of the LogStorage CR when marked for deletion and continues without error", func() {
						mockStatus.On("AddDaemonsets", mock.Anything).Return()
						mockStatus.On("AddDeployments", mock.Anything).Return()
						mockStatus.On("AddStatefulSets", mock.Anything).Return()
						mockStatus.On("AddCronJobs", mock.Anything)
						mockStatus.On("ClearDegraded", mock.Anything).Return()
						mockStatus.On("ReadyToMonitor")

						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
						Expect(err).ShouldNot(HaveOccurred())

						ls := &operatorv1.LogStorage{}
						Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())

						now := metav1.Now()
						ls.DeletionTimestamp = &now
						ls.SetFinalizers([]string{"tigera.io/eck-cleanup"})
						Expect(cli.Update(ctx, ls)).ShouldNot(HaveOccurred())

						result, err := r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(result).Should(Equal(reconcile.Result{}))

						By("expecting not to find the tigera-secure-internal Elasticsearch or Kibana resources")
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
						Expect(result).Should(Equal(reconcile.Result{}))

						By("expecting not to find the eck-cleanup finalizer in the LogStorage CR anymore")
						ls = &operatorv1.LogStorage{}
						Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())
						Expect(ls.Finalizers).ShouldNot(ContainElement("tigera.io/eck-cleanup"))

						mockStatus.AssertExpectations(GinkgoT())
					})
				})
			})
		})
		Context("Unmanaged cluster", func() {
			Context("successful LogStorage Reconcile", func() {
				var mockStatus *status.MockStatus
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
				})
				It("test LogStorage reconciles successfully", func() {
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

					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
					Expect(err).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "").Return()
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

					By("confirming elasticsearch certs are created")
					secret := &corev1.Secret{}

					Expect(cli.Get(ctx, esCertSecretKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyCert(secret, "tls.key", "tls.crt", esDNSNames...)

					Expect(cli.Get(ctx, esCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyCert(secret, "tls.key", "tls.crt", esDNSNames...)

					By("confirming kibana certs are created")
					Expect(cli.Get(ctx, kbCertSecretKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyCert(secret, "tls.key", "tls.crt", kbDNSNames...)

					Expect(cli.Get(ctx, kbCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyCert(secret, "tls.key", "tls.crt", kbDNSNames...)

					// Create public ES and KB secrets
					Expect(cli.Get(ctx, esCertSecretKey, secret)).ShouldNot(HaveOccurred())
					esPublicSecret := createPubSecret(relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, secret.Data["tls.crt"], "tls.crt")
					Expect(cli.Create(ctx, esPublicSecret)).ShouldNot(HaveOccurred())

					Expect(cli.Get(ctx, kbCertSecretKey, secret)).ShouldNot(HaveOccurred())
					kbPublicSecret := createPubSecret(render.KibanaPublicCertSecret, render.KibanaNamespace, secret.Data["tls.crt"], "tls.crt")
					Expect(cli.Create(ctx, kbPublicSecret)).ShouldNot(HaveOccurred())

					esGatewayPublicSecret := createPubSecret(esgateway.EsGatewayElasticPublicCertSecret, rmeta.OperatorNamespace(), secret.Data["tls.crt"], "tls.crt")
					Expect(cli.Create(ctx, esGatewayPublicSecret)).ShouldNot(HaveOccurred())

					esAdminUserSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchAdminUserSecret,
							Namespace: render.ElasticsearchNamespace,
						},
						Data: map[string][]byte{
							"username": []byte("elastic"),
							"password": []byte("password"),
						},
					}
					Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

					kubeControllersElasticUserSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchKubeControllersUserSecret,
							Namespace: common.CalicoNamespace,
						},
						Data: map[string][]byte{
							"username": []byte("username"),
							"password": []byte("password"),
						},
					}
					Expect(cli.Create(ctx, kubeControllersElasticUserSecret)).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for curator secrets to become available", "").Return()
					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					// Expect to be waiting for curator secret
					Expect(result).Should(Equal(reconcile.Result{}))
					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())

					By("confirming public ES and KB certs are still valid")
					Expect(cli.Get(ctx, esCertPubSecretKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyPublicCert(secret, "tls.crt", esDNSNames...)

					Expect(cli.Get(ctx, kbCertPubSecretKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyPublicCert(secret, "tls.crt", kbDNSNames...)

					By("confirming public ES and KB certs were copied to operator namespace")
					Expect(cli.Get(ctx, esCertPubSecretOperKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyPublicCert(secret, "tls.crt", esDNSNames...)

					Expect(cli.Get(ctx, kbCertPubSecretOperKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyPublicCert(secret, "tls.crt", kbDNSNames...)

					mockStatus.On("SetDegraded", "Waiting for elasticsearch metrics secrets to become available", "").Return()
					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: esMetricsUsrSecretObjMeta})).ShouldNot(HaveOccurred())

					mockStatus.On("ClearDegraded")
					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(reconcile.Result{}))

					By("confirming curator job is created")
					Expect(cli.Get(ctx, curatorObjKey, &batchv1beta.CronJob{})).ShouldNot(HaveOccurred())

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
					Expect(cli.Create(ctx, render.CreateCertificateSecret([]byte(""), render.DexCertSecretName, rmeta.OperatorNamespace()))).ToNot(HaveOccurred())

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
						Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeBasic)},
					})).ShouldNot(HaveOccurred())

					Expect(cli.Create(ctx, &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersConfigMapName},
					})).ShouldNot(HaveOccurred())

					Expect(cli.Create(ctx, &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersEsSecreteName},
					})).ShouldNot(HaveOccurred())

					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
					Expect(err).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "").Return()
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

					// Create public ES and KB secrets
					secret := &corev1.Secret{}
					Expect(cli.Get(ctx, esCertSecretKey, secret)).ShouldNot(HaveOccurred())
					esPublicSecret := createPubSecret(relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, secret.Data["tls.crt"], "tls.crt")
					Expect(cli.Create(ctx, esPublicSecret)).ShouldNot(HaveOccurred())

					Expect(cli.Get(ctx, kbCertSecretKey, secret)).ShouldNot(HaveOccurred())
					kbPublicSecret := createPubSecret(render.KibanaPublicCertSecret, render.KibanaNamespace, secret.Data["tls.crt"], "tls.crt")
					Expect(cli.Create(ctx, kbPublicSecret)).ShouldNot(HaveOccurred())

					esGatewayPublicSecret := createPubSecret(esgateway.EsGatewayElasticPublicCertSecret, rmeta.OperatorNamespace(), secret.Data["tls.crt"], "tls.crt")
					Expect(cli.Create(ctx, esGatewayPublicSecret)).ShouldNot(HaveOccurred())

					esAdminUserSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchAdminUserSecret,
							Namespace: render.ElasticsearchNamespace,
						},
						Data: map[string][]byte{
							"username": []byte("elastic"),
							"password": []byte("password"),
						},
					}
					Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

					kubeControllersElasticUserSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchKubeControllersUserSecret,
							Namespace: common.CalicoNamespace,
						},
						Data: map[string][]byte{
							"username": []byte("username"),
							"password": []byte("password"),
						},
					}
					Expect(cli.Create(ctx, kubeControllersElasticUserSecret)).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for curator secrets to become available", "").Return()
					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					// Expect to be waiting for curator secret
					Expect(result).Should(Equal(reconcile.Result{}))
					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())
					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: esMetricsUsrSecretObjMeta})).ShouldNot(HaveOccurred())

					mockStatus.On("ClearDegraded")
					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(reconcile.Result{}))

					By("confirming curator job is created")
					Expect(cli.Get(ctx, curatorObjKey, &batchv1beta.CronJob{})).ShouldNot(HaveOccurred())

					By("confirming logstorage is degraded if ConfigMap is not available")
					mockStatus.On("SetDegraded", "Failed to get oidc user Secret and ConfigMap", "configmaps \"tigera-known-oidc-users\" not found").Return()
					Expect(cli.Delete(ctx, &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersConfigMapName},
					})).ShouldNot(HaveOccurred())

					Expect(cli.Delete(ctx, &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersEsSecreteName},
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
						render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace(), "tls.key", "tls.crt",
						rmeta.DefaultCertificateDuration, nil, esDNSNames...,
					)
					Expect(err).ShouldNot(HaveOccurred())

					esPublicSecret := createPubSecret(relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, esSecret.Data["tls.crt"], "tls.crt")
					Expect(cli.Create(ctx, esSecret)).ShouldNot(HaveOccurred())
					Expect(cli.Create(ctx, esPublicSecret)).ShouldNot(HaveOccurred())

					kbDNSNames = []string{"kb.example.com", "192.168.10.11"}
					kbSecret, err := secret.CreateTLSSecret(testCA,
						render.TigeraKibanaCertSecret, rmeta.OperatorNamespace(), "tls.key", "tls.crt", rmeta.DefaultCertificateDuration, nil, kbDNSNames...,
					)
					Expect(err).ShouldNot(HaveOccurred())
					kbPublicSecret := createPubSecret(render.KibanaPublicCertSecret, render.KibanaNamespace, kbSecret.Data["tls.crt"], "tls.crt")
					Expect(cli.Create(ctx, kbSecret)).ShouldNot(HaveOccurred())
					Expect(cli.Create(ctx, kbPublicSecret)).ShouldNot(HaveOccurred())

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

					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
					Expect(err).ShouldNot(HaveOccurred())

					// Elasticsearch and kibana secrets are good.
					mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "").Return()
					_, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					Expect(cli.Get(ctx, esCertSecretOperKey, esSecret)).ShouldNot(HaveOccurred())
					test.VerifyCert(esSecret, "tls.key", "tls.crt", esDNSNames...)

					Expect(cli.Get(ctx, kbCertSecretOperKey, kbSecret)).ShouldNot(HaveOccurred())
					test.VerifyCert(kbSecret, "tls.key", "tls.crt", kbDNSNames...)
				})

				It("test that LogStorage creates new certs if operator managed certs have invalid DNS names", func() {
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

					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
					Expect(err).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "").Return()
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

					By("deleting the existing ES and KB secrets")
					esSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.TigeraElasticsearchCertSecret,
							Namespace: rmeta.OperatorNamespace(),
						},
					}
					Expect(cli.Delete(ctx, esSecret)).NotTo(HaveOccurred())

					kbSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.TigeraKibanaCertSecret,
							Namespace: rmeta.OperatorNamespace(),
						},
					}
					Expect(cli.Delete(ctx, kbSecret)).NotTo(HaveOccurred())

					By("creating new ES and KB secrets with an old invalid DNS name")
					esSecret, err = secret.CreateTLSSecret(nil,
						render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace(), "tls.key", "tls.crt",
						rmeta.DefaultCertificateDuration, nil, "tigera-secure-es-http.tigera-elasticsearch.svc",
					)
					Expect(err).ShouldNot(HaveOccurred())

					kbSecret, err = secret.CreateTLSSecret(nil,
						render.TigeraKibanaCertSecret, rmeta.OperatorNamespace(), "tls.key", "tls.crt",
						rmeta.DefaultCertificateDuration, nil, "tigera-secure-kb-http.tigera-elasticsearch.svc",
					)
					Expect(err).ShouldNot(HaveOccurred())

					kubeControllersElasticUserSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchKubeControllersUserSecret,
							Namespace: common.CalicoNamespace,
						},
						Data: map[string][]byte{
							"username": []byte("username"),
							"password": []byte("password"),
						},
					}
					Expect(cli.Create(ctx, kubeControllersElasticUserSecret)).ShouldNot(HaveOccurred())

					// Create the public ES and KB secrets that would come from
					// the ECK operator. These public certs use the cert
					// bytes from the certs above and so they have invalid DNS
					// names.
					Expect(cli.Create(
						ctx, createPubSecret(render.KibanaPublicCertSecret, render.KibanaNamespace, kbSecret.Data["tls.crt"], "tls.crt")),
					).ShouldNot(HaveOccurred())

					Expect(cli.Create(
						ctx, createPubSecret(relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, esSecret.Data["tls.crt"], "tls.crt"),
					)).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for curator secrets to become available", "").Return()
					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					By("confirming elasticsearch certs were updated and have the expected DNS names")
					esDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
					secret := &corev1.Secret{}

					Expect(cli.Get(ctx, esCertSecretKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyCert(secret, "tls.key", "tls.crt", esDNSNames...)

					Expect(cli.Get(ctx, esCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyCert(secret, "tls.key", "tls.crt", esDNSNames...)

					By("confirming kibana certs were updated and have the expected DNS names")
					kbDNSNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, r.clusterDomain)
					Expect(cli.Get(ctx, kbCertSecretKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyCert(secret, "tls.key", "tls.crt", kbDNSNames...)

					Expect(cli.Get(ctx, kbCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
					test.VerifyCert(secret, "tls.key", "tls.crt", kbDNSNames...)

					By("confirming public ES and KB certs in the ES/KB namespace are deleted")
					err = cli.Get(ctx, esCertPubSecretKey, secret)
					Expect(err).Should(HaveOccurred())
					Expect(errors.IsNotFound(err)).To(BeTrue())

					err = cli.Get(ctx, kbCertPubSecretKey, secret)
					Expect(err).Should(HaveOccurred())
					Expect(errors.IsNotFound(err)).To(BeTrue())

					mockStatus.AssertExpectations(GinkgoT())
				})

				Context("checking rendered images", func() {
					BeforeEach(func() {
						mockStatus.On("ClearDegraded", mock.Anything)
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
							&corev1.Secret{ObjectMeta: esMetricsUsrSecretObjMeta},
							&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
								Name: render.ElasticsearchCuratorUserSecret, Namespace: render.ElasticsearchNamespace}},
							&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
								Name: esgateway.EsGatewayElasticPublicCertSecret, Namespace: rmeta.OperatorNamespace()}},
						}
						resources = append(resources, createESSecrets()...)
						resources = append(resources, createKibanaSecrets()...)

						for _, rec := range resources {
							Expect(cli.Create(ctx, rec)).ShouldNot(HaveOccurred())
						}
					})
					It("should use default images", func() {
						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
						Expect(err).ShouldNot(HaveOccurred())

						kubeControllersElasticUserSecret := &corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Name:      render.ElasticsearchKubeControllersUserSecret,
								Namespace: common.CalicoNamespace,
							},
							Data: map[string][]byte{
								"username": []byte("username"),
								"password": []byte("password"),
							},
						}
						Expect(cli.Create(ctx, kubeControllersElasticUserSecret)).ShouldNot(HaveOccurred())

						By("running reconcile")
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())

						By("confirming curator job is created")
						Expect(cli.Get(ctx, curatorObjKey, &batchv1beta.CronJob{})).ShouldNot(HaveOccurred())

						mockStatus.AssertExpectations(GinkgoT())

						cj := batchv1beta.CronJob{
							TypeMeta: metav1.TypeMeta{Kind: "CronJob", APIVersion: "v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      render.EsCuratorName,
								Namespace: render.ElasticsearchNamespace,
							},
						}
						Expect(test.GetResource(cli, &cj)).To(BeNil())
						Expect(cj.Spec.JobTemplate.Spec.Template.Spec.Containers).To(HaveLen(1))
						curator := test.GetContainer(cj.Spec.JobTemplate.Spec.Template.Spec.Containers, render.EsCuratorName)
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

						dp := appsv1.Deployment{
							TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      esgateway.EsGatewayName,
								Namespace: render.ElasticsearchNamespace,
							},
						}
						Expect(test.GetResource(cli, &dp)).To(BeNil())
						Expect(dp.Spec.Template.Spec.Containers).To(HaveLen(1))
						gateway := test.GetContainer(dp.Spec.Template.Spec.Containers, esgateway.EsGatewayName)
						Expect(gateway).ToNot(BeNil())
						Expect(gateway.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s:%s",
								components.ComponentEsGateway.Image,
								components.ComponentEsGateway.Version)))
					})
					It("should use images from ImageSet", func() {
						Expect(cli.Create(ctx, &operatorv1.ImageSet{
							ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
							Spec: operatorv1.ImageSetSpec{
								Images: []operatorv1.Image{
									{Image: "tigera/elasticsearch", Digest: "sha256:elasticsearchhash"},
									{Image: "tigera/kibana", Digest: "sha256:kibanahash"},
									{Image: "eck/eck-operator", Digest: "sha256:eckoperatorhash"},
									{Image: "tigera/es-curator", Digest: "sha256:escuratorhash"},
									{Image: "tigera/elasticsearch-metrics", Digest: "sha256:esmetricshash"},
									{Image: "tigera/es-gateway", Digest: "sha256:esgatewayhash"},
								},
							},
						})).ToNot(HaveOccurred())
						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
						Expect(err).ShouldNot(HaveOccurred())

						kubeControllersElasticUserSecret := &corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Name:      render.ElasticsearchKubeControllersUserSecret,
								Namespace: common.CalicoNamespace,
							},
							Data: map[string][]byte{
								"username": []byte("username"),
								"password": []byte("password"),
							},
						}
						Expect(cli.Create(ctx, kubeControllersElasticUserSecret)).ShouldNot(HaveOccurred())

						By("running reconcile")
						_, err = r.Reconcile(ctx, reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())

						By("confirming curator job is created")
						Expect(cli.Get(ctx, curatorObjKey, &batchv1beta.CronJob{})).ShouldNot(HaveOccurred())

						mockStatus.AssertExpectations(GinkgoT())

						cj := batchv1beta.CronJob{
							TypeMeta: metav1.TypeMeta{Kind: "CronJob", APIVersion: "v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      render.EsCuratorName,
								Namespace: render.ElasticsearchNamespace,
							},
						}
						Expect(test.GetResource(cli, &cj)).To(BeNil())
						Expect(cj.Spec.JobTemplate.Spec.Template.Spec.Containers).To(HaveLen(1))
						curator := test.GetContainer(cj.Spec.JobTemplate.Spec.Template.Spec.Containers, render.EsCuratorName)
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

						dp := appsv1.Deployment{
							TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      esgateway.EsGatewayName,
								Namespace: render.ElasticsearchNamespace,
							},
						}
						Expect(test.GetResource(cli, &dp)).To(BeNil())
						Expect(dp.Spec.Template.Spec.Containers).To(HaveLen(1))
						gateway := test.GetContainer(dp.Spec.Template.Spec.Containers, esgateway.EsGatewayName)
						Expect(gateway).ToNot(BeNil())
						Expect(gateway.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s@%s",
								components.ComponentEsGateway.Image,
								"sha256:esgatewayhash")))
					})
				})
			})

			Context("LogStorage CR deleted", func() {
				var mockStatus *status.MockStatus

				BeforeEach(func() {

					Expect(cli.Create(ctx, &operatorv1.Installation{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Status: operatorv1.InstallationStatus{
							Variant:  operatorv1.TigeraSecureEnterprise,
							Computed: &operatorv1.InstallationSpec{},
						},
						Spec: operatorv1.InstallationSpec{
							Variant: operatorv1.TigeraSecureEnterprise,
						},
					})).ShouldNot(HaveOccurred())

					Expect(cli.Create(
						ctx,
						&operatorv1.ManagementCluster{
							ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
						})).NotTo(HaveOccurred())

					setUpLogStorageComponents(cli, ctx, "", nil)

					mockStatus = &status.MockStatus{}
					mockStatus.On("Run").Return()
					mockStatus.On("AddDaemonsets", mock.Anything)
					mockStatus.On("AddDeployments", mock.Anything)
					mockStatus.On("AddStatefulSets", mock.Anything)
					mockStatus.On("AddCronJobs", mock.Anything)
					mockStatus.On("ClearDegraded", mock.Anything)
					mockStatus.On("OnCRFound").Return()
					mockStatus.On("ReadyToMonitor")
				})

				It("deletes Elasticsearch and Kibana then removes the finalizers on the LogStorage CR", func() {
					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, mockEsCliCreator, dns.DefaultClusterDomain)
					Expect(err).ShouldNot(HaveOccurred())
					esGatewayPublicSecret := createPubSecret(esgateway.EsGatewayElasticPublicCertSecret, rmeta.OperatorNamespace(), []byte{}, "tls.crt")
					Expect(cli.Create(ctx, esGatewayPublicSecret)).ShouldNot(HaveOccurred())

					esAdminUserSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchAdminUserSecret,
							Namespace: render.ElasticsearchNamespace,
						},
						Data: map[string][]byte{
							"username": []byte("elastic"),
							"password": []byte("password"),
						},
					}
					Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

					kubeControllersElasticUserSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.ElasticsearchKubeControllersUserSecret,
							Namespace: common.CalicoNamespace,
						},
						Data: map[string][]byte{
							"username": []byte("username"),
							"password": []byte("password"),
						},
					}
					Expect(cli.Create(ctx, kubeControllersElasticUserSecret)).ShouldNot(HaveOccurred())

					By("making sure LogStorage has successfully reconciled")
					result, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(reconcile.Result{}))

					ls := &operatorv1.LogStorage{}
					Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())

					By("setting the DeletionTimestamp on the LogStorage CR")
					// The fake library does seem to respect finalizers when Delete is called, so we need to manually set the
					// DeletionTimestamp.
					now := metav1.Now()
					ls.DeletionTimestamp = &now
					Expect(cli.Update(ctx, ls)).ShouldNot(HaveOccurred())
					Expect(ls.Spec.StorageClassName).To(Equal(DefaultElasticsearchStorageClass))

					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(reconcile.Result{}))

					By("expecting not to find the tigera-secure-internal Elasticsearch or Kibana resources")
					err = cli.Get(ctx, esObjKey, &esv1.Elasticsearch{})
					Expect(errors.IsNotFound(err)).Should(BeTrue())
					err = cli.Get(ctx, kbObjKey, &kbv1.Kibana{})
					Expect(errors.IsNotFound(err)).Should(BeTrue())

					// The LogStorage CR should still contain the finalizer, as we wait for ES and KB to finish deleting
					By("waiting for the Elasticsearch and Kibana resources to be deleted")
					ls = &operatorv1.LogStorage{}
					Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())
					Expect(ls.Finalizers).Should(ContainElement("tigera.io/eck-cleanup"))

					mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "")
					result, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(reconcile.Result{}))

					By("expecting not to find the eck-cleanup finalizer in the LogStorage CR anymore")
					ls = &operatorv1.LogStorage{}
					Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())
					Expect(ls.Finalizers).ShouldNot(ContainElement("tigera.io/eck-cleanup"))

					mockStatus.AssertExpectations(GinkgoT())
				})
			})
		})
	})
	Context("LogStorageSpec, validateComponentResources", func() {
		ls := operatorv1.LogStorage{Spec: operatorv1.LogStorageSpec{}}

		It("should return an error when spec.ComponentResources is nil", func() {
			Expect(validateComponentResources(&ls.Spec)).NotTo(BeNil())
		})

		It("should return an error when spec.ComponentResources.ComponentName is not ECKOperator", func() {
			ls.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
				{
					ComponentName: "Typha",
				},
			}
			Expect(validateComponentResources(&ls.Spec)).NotTo(BeNil())
		})

		It("should return an error when spec.ComponentResources has more than one entry", func() {
			ls.Spec.ComponentResources = append(ls.Spec.ComponentResources, operatorv1.LogStorageComponentResource{
				ComponentName: "KubeControllers",
			})
			Expect(validateComponentResources(&ls.Spec)).NotTo(BeNil())
		})

		It("should return nil when spec.ComponentResources has 1 entry for ECKOperator", func() {
			ls.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
				{
					ComponentName: operatorv1.ComponentNameECKOperator,
				},
			}
			Expect(validateComponentResources(&ls.Spec)).To(BeNil())
		})
	})
	Context("LogStorageSpec, fillDefaults", func() {
		ls := operatorv1.LogStorage{Spec: operatorv1.LogStorageSpec{}}
		fillDefaults(&ls)

		var fr int32 = 8
		var arr int32 = 91
		var sr int32 = 91
		var crr int32 = 91
		var replicas int32 = render.DefaultElasticsearchReplicas
		var esGatewayReplicaCount int32 = 1
		limits := corev1.ResourceList{}
		requests := corev1.ResourceList{}
		limits[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
		requests[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)

		expectedSpec := operatorv1.LogStorageSpec{
			Nodes: &operatorv1.Nodes{Count: 1},
			Retention: &operatorv1.Retention{
				Flows:             &fr,
				AuditReports:      &arr,
				Snapshots:         &sr,
				ComplianceReports: &crr,
			},
			Indices: &operatorv1.Indices{
				Replicas: &replicas,
			},
			StorageClassName: DefaultElasticsearchStorageClass,
			ComponentResources: []operatorv1.LogStorageComponentResource{
				{
					ComponentName: operatorv1.ComponentNameECKOperator,
					ResourceRequirements: &corev1.ResourceRequirements{
						Limits:   limits,
						Requests: requests,
					},
				},
			},
			IngestReplicaCount: &esGatewayReplicaCount,
		}
		It("should have initialized all LogStorageSpec fields with default values", func() {
			Expect(ls.Spec).To(Equal(expectedSpec))
		})
	})
})

func setUpLogStorageComponents(cli client.Client, ctx context.Context, storageClass string, managementClusterConnection *operatorv1.ManagementClusterConnection) {
	if storageClass == "" {
		Expect(cli.Create(ctx, &storagev1.StorageClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: DefaultElasticsearchStorageClass,
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
	replicaCount := int32(1)
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
			},
			StorageClassName:   storageClass,
			IngestReplicaCount: &replicaCount,
		},
	}

	By("creating all the components needed for LogStorage to be available")
	component := render.LogStorage(
		ls,
		&operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
			Registry:           "testregistry.com/",
		},
		nil, managementClusterConnection,
		&esv1.Elasticsearch{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}},
		&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaName, Namespace: render.KibanaNamespace}},
		relasticsearch.NewClusterConfig("cluster", 1, 1, 1),
		toSecrets(createESSecrets()),
		toSecrets(createKibanaSecrets()),
		[]*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
		},
		operatorv1.ProviderNone,
		[]*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: rmeta.OperatorNamespace()}},
		},
		nil, nil, "cluster.local", nil, render.ElasticsearchLicenseTypeBasic)

	createObj, _ := component.Objects()
	for _, obj := range createObj {
		switch obj.(type) {
		case *esv1.Elasticsearch:
			By("setting the Elasticsearch status to operational so we pass the Elasticsearch ready check")
			es := obj.(*esv1.Elasticsearch)
			es.Status.Phase = esv1.ElasticsearchReadyPhase
			obj = es

		case *kbv1.Kibana:
			By("setting the Kibana status to operational so we pass the Kibana ready check")
			kb := obj.(*kbv1.Kibana)
			kb.Status.AssociationStatus = cmnv1.AssociationEstablished
			obj = kb
		}

		Expect(cli.Create(ctx, obj)).ShouldNot(HaveOccurred())
	}

	Expect(
		cli.Create(ctx, &corev1.Secret{
			ObjectMeta: curatorUsrSecretObjMeta,
		}),
	).ShouldNot(HaveOccurred())
	Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: esMetricsUsrSecretObjMeta})).ShouldNot(HaveOccurred())
}

func toSecrets(objs []client.Object) []*corev1.Secret {
	var secrets []*corev1.Secret
	for _, o := range objs {
		secrets = append(secrets, o.(*corev1.Secret))
	}
	return secrets
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

func createESSecrets() []client.Object {
	dnsNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	esSecret, err := secret.CreateTLSSecret(nil,
		render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace(), "tls.key", "tls.crt",
		rmeta.DefaultCertificateDuration, nil, dnsNames...,
	)
	Expect(err).ShouldNot(HaveOccurred())

	esOperNsSecret := secret.CopyToNamespace(render.ElasticsearchNamespace, esSecret)[0]

	esPublicOperNsSecret := createPubSecret(relasticsearch.PublicCertSecret, rmeta.OperatorNamespace(), esSecret.Data["tls.crt"], "tls.crt")
	esPublicSecret := createPubSecret(relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, esSecret.Data["tls.crt"], "tls.crt")
	return []client.Object{
		esSecret,
		esOperNsSecret,
		esPublicOperNsSecret,
		esPublicSecret,
	}
}

func createKibanaSecrets() []client.Object {
	dnsNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, dns.DefaultClusterDomain)
	kbSecret, err := secret.CreateTLSSecret(nil,
		render.TigeraKibanaCertSecret, rmeta.OperatorNamespace(), "tls.key", "tls.crt",
		rmeta.DefaultCertificateDuration, nil, dnsNames...,
	)
	Expect(err).ShouldNot(HaveOccurred())

	kbOperNsSecret := secret.CopyToNamespace(render.KibanaNamespace, kbSecret)[0]

	kbPublicOperNsSecret := createPubSecret(render.KibanaPublicCertSecret, rmeta.OperatorNamespace(), kbSecret.Data["tls.crt"], "tls.crt")
	kbPublicSecret := createPubSecret(render.KibanaPublicCertSecret, render.KibanaNamespace, kbSecret.Data["tls.crt"], "tls.crt")
	return []client.Object{
		kbSecret,
		kbOperNsSecret,
		kbPublicOperNsSecret,
		kbPublicSecret,
	}
}

func (*mockESClient) SetILMPolicies(ctx context.Context, ls *operatorv1.LogStorage) error {
	return nil
}
