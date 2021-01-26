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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

var (
	eckOperatorObjKey = client.ObjectKey{Name: render.ECKOperatorName, Namespace: render.ECKOperatorNamespace}
	esObjKey          = client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}
	kbObjKey          = client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}
	curatorObjKey     = types.NamespacedName{Namespace: render.ElasticsearchNamespace, Name: render.EsCuratorName}

	esPublicCertObjMeta      = metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}
	kbPublicCertObjMeta      = metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}
	curatorUsrSecretObjMeta  = metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: render.OperatorNamespace()}
	operatorUsrSecretObjMeta = metav1.ObjectMeta{Name: render.ElasticsearchOperatorUserSecret, Namespace: render.OperatorNamespace()}
	storageClassName         = "test-storage-class"
)

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
					})

					DescribeTable("tests that the ExternalService is setup with the default service name", func(clusterDomain, expectedSvcName string) {
						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, clusterDomain)
						Expect(err).ShouldNot(HaveOccurred())
						_, err = r.Reconcile(reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						svc := &corev1.Service{}
						Expect(
							cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace}, svc),
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
						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, dns.DefaultClusterDomain)
						Expect(err).ShouldNot(HaveOccurred())
						mockStatus.On("SetDegraded", "LogStorage validation failed", "cluster type is managed but LogStorage CR still exists").Return()
						result, err := r.Reconcile(reconcile.Request{})
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

						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, dns.DefaultClusterDomain)
						Expect(err).ShouldNot(HaveOccurred())

						ls := &operatorv1.LogStorage{}
						Expect(cli.Get(ctx, utils.DefaultTSEEInstanceKey, ls)).ShouldNot(HaveOccurred())

						now := metav1.Now()
						ls.DeletionTimestamp = &now
						ls.SetFinalizers([]string{"tigera.io/eck-cleanup"})
						Expect(cli.Update(ctx, ls)).ShouldNot(HaveOccurred())

						result, err := r.Reconcile(reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(result).Should(Equal(reconcile.Result{}))

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

						result, err = r.Reconcile(reconcile.Request{})
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

					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, dns.DefaultClusterDomain)
					Expect(err).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "").Return()
					result, err := r.Reconcile(reconcile.Request{})
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

					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: esPublicCertObjMeta})).ShouldNot(HaveOccurred())
					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: kbPublicCertObjMeta})).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for curator secrets to become available", "").Return()
					result, err = r.Reconcile(reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					// Expect to be waiting for curator secret
					Expect(result).Should(Equal(reconcile.Result{}))
					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())

					mockStatus.On("ClearDegraded")
					result, err = r.Reconcile(reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(reconcile.Result{}))

					By("confirming curator job is created")
					Expect(cli.Get(ctx, curatorObjKey, &batchv1beta.CronJob{})).ShouldNot(HaveOccurred())

					By("confirming elastic user ConfigMap is not available")
					Expect(cli.Get(ctx,
						types.NamespacedName{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersConfigMapName},
						&corev1.ConfigMap{})).Should(HaveOccurred())

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
					Expect(cli.Create(ctx, render.CreateDexTLSSecret("tigera-dex.tigera-dex.svc.cluster.local"))).ToNot(HaveOccurred())

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

					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, dns.DefaultClusterDomain)
					Expect(err).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "").Return()
					result, err := r.Reconcile(reconcile.Request{})
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

					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: esPublicCertObjMeta})).ShouldNot(HaveOccurred())
					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: kbPublicCertObjMeta})).ShouldNot(HaveOccurred())

					mockStatus.On("SetDegraded", "Waiting for curator secrets to become available", "").Return()
					result, err = r.Reconcile(reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					// Expect to be waiting for curator secret
					Expect(result).Should(Equal(reconcile.Result{}))
					Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta})).ShouldNot(HaveOccurred())

					mockStatus.On("ClearDegraded")
					result, err = r.Reconcile(reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(reconcile.Result{}))

					By("confirming curator job is created")
					Expect(cli.Get(ctx, curatorObjKey, &batchv1beta.CronJob{})).ShouldNot(HaveOccurred())

					By("confirming elastic user ConfigMap is created")
					Expect(cli.Get(ctx,
						types.NamespacedName{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersConfigMapName},
						&corev1.ConfigMap{})).ShouldNot(HaveOccurred())
					Expect(cli.Get(ctx,
						types.NamespacedName{Namespace: render.ElasticsearchNamespace, Name: render.OIDCUsersEsSecreteName},
						&corev1.Secret{})).ShouldNot(HaveOccurred())

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

						resources := []runtime.Object{
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
							render.NewElasticsearchClusterConfig("cluster", 1, 1, 1).ConfigMap(),
							&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
							&corev1.ConfigMap{
								ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKLicenseConfigMapName},
								Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
							},
							&corev1.Secret{ObjectMeta: curatorUsrSecretObjMeta},
							&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
								Name: render.ElasticsearchCuratorUserSecret, Namespace: render.ElasticsearchNamespace}},
						}
						resources = append(resources, createESSecrets()...)
						resources = append(resources, createKibanaSecrets()...)

						for _, rec := range resources {
							Expect(cli.Create(ctx, rec)).ShouldNot(HaveOccurred())
						}
					})
					It("should use default images", func() {
						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, dns.DefaultClusterDomain)
						Expect(err).ShouldNot(HaveOccurred())

						By("running reconcile")
						_, err = r.Reconcile(reconcile.Request{})
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
								},
							},
						})).ToNot(HaveOccurred())
						r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, dns.DefaultClusterDomain)
						Expect(err).ShouldNot(HaveOccurred())

						By("running reconcile")
						_, err = r.Reconcile(reconcile.Request{})
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
				})

				It("deletes Elasticsearch and Kibana then removes the finalizers on the LogStorage CR", func() {
					r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, dns.DefaultClusterDomain)
					Expect(err).ShouldNot(HaveOccurred())

					By("making sure LogStorage has successfully reconciled")
					//mockStatus.On("SetDegraded", "Waiting for curator secrets to become available", "").Return()

					result, err := r.Reconcile(reconcile.Request{})
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

					result, err = r.Reconcile(reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).Should(Equal(reconcile.Result{}))

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

					mockStatus.On("SetDegraded", "Waiting for Elasticsearch cluster to be operational", "")
					result, err = r.Reconcile(reconcile.Request{})
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
			StorageClassName: storageClass,
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
		render.NewElasticsearchClusterConfig("cluster", 1, 1, 1),
		toSecrets(createESSecrets()),
		toSecrets(createKibanaSecrets()),
		[]*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
		}, operatorv1.ProviderNone,
		[]*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: render.OperatorNamespace()}},
			//{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
		},
		nil, nil, "cluster.local", false, nil, render.ElasticsearchLicenseTypeBasic,
		&corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.OIDCUsersConfigMapName,
				Namespace: render.ElasticsearchNamespace,
			}},
		&corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.OIDCUsersEsSecreteName,
				Namespace: render.ElasticsearchNamespace,
			}})

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
}

func toSecrets(objs []runtime.Object) []*corev1.Secret {
	var secrets []*corev1.Secret
	for _, o := range objs {
		secrets = append(secrets, o.(*corev1.Secret))
	}
	return secrets
}

func createESSecrets() []runtime.Object {
	dnsNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	esSecret, err := utils.EnsureCertificateSecret(context.TODO(), render.TigeraElasticsearchCertSecret, nil, dnsNames...)
	Expect(err).ShouldNot(HaveOccurred())
	esOperNsSecret := render.CopySecrets(render.ElasticsearchNamespace, esSecret)[0]

	return []runtime.Object{
		esSecret,
		esOperNsSecret,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}},
	}
}

func createKibanaSecrets() []runtime.Object {
	dnsNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, dns.DefaultClusterDomain)
	kibanaSecret, err := utils.EnsureCertificateSecret(context.TODO(), render.TigeraKibanaCertSecret, nil, dnsNames...)
	Expect(err).ShouldNot(HaveOccurred())
	kibanaOperNsSecret := render.CopySecrets(render.KibanaNamespace, kibanaSecret)[0]

	return []runtime.Object{
		kibanaSecret,
		kibanaOperNsSecret,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: render.KibanaPublicCertSecret, Namespace: render.OperatorNamespace()}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: render.KibanaPublicCertSecret, Namespace: render.ElasticsearchNamespace}},
	}
}

var _ = Describe("LogStorage w/ Certificate management", func() {
	Context("Reconcile", func() {
		var (
			cli          client.Client
			mockStatus   *status.MockStatus
			scheme       *runtime.Scheme
			ctx          = context.Background()
			install      *operatorv1.Installation
			logstorageCR *operatorv1.LogStorage
		)
		BeforeEach(func() {
			install = &operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			logstorageCR = &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{},
			}
			mockStatus = &status.MockStatus{}
			mockStatus.On("Run").Return()
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("SetDegraded", "Certificate Management is not yet supported for clusters with LogStorage, please remove the setting from your Installation resource.", "").Return()
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			cli = fake.NewFakeClientWithScheme(scheme)
			Expect(cli.Create(ctx, &storagev1.StorageClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: DefaultElasticsearchStorageClass,
				},
			}))
		})
		It("should return an error when certification management is enabled while logstorage is present", func() {
			install.Spec.CertificateManagement = &operatorv1.CertificateManagement{CACert: []byte("ca"), SignerName: "a.b/c"}
			Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, logstorageCR)).To(BeNil())
			r, err := NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, &mockESClient{}, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(reconcile.Request{})
			Expect(err).Should(HaveOccurred())
		})
	})
})

func (*mockESClient) SetILMPolicies(client client.Client, ctx context.Context, ls *operatorv1.LogStorage, elasticHTTPSEndpoint string) error {
	return nil
}
