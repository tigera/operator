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

package logstorage_test

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/logstorage"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

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

	esPublicCertObjMeta     = metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}
	kbPublicCertObjMeta     = metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}
	curatorUsrSecretObjMeta = metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: render.OperatorNamespace()}
	storageClassName        = "test-storage-class"
)

var _ = Describe("LogStorage controller", func() {
	Context("Reconcile", func() {
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
				ls, err = logstorage.GetLogStorage(ctx, cli)
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
				Expect(ls.Spec.StorageClassName).To(Equal(logstorage.DefaultElasticsearchStorageClass))
			})
		})

		Context("Managed Cluster", func() {
			Context("LogStorage is nil", func() {
				BeforeEach(func() {
					Expect(cli.Create(ctx, &operatorv1.Installation{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Status: operatorv1.InstallationStatus{
							Variant: operatorv1.TigeraSecureEnterprise,
						},
						Spec: operatorv1.InstallationSpec{
							Variant: operatorv1.TigeraSecureEnterprise,
						},
					})).ShouldNot(HaveOccurred())

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
					It("tests that the ExternalService is setup with the default service name", func() {
						r, err := logstorage.NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, "")
						Expect(err).ShouldNot(HaveOccurred())

						_, err = r.Reconcile(reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())

						svc := &corev1.Service{}
						Expect(
							cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace}, svc),
						).ShouldNot(HaveOccurred())

						Expect(svc.Spec.ExternalName).Should(Equal("tigera-guardian.tigera-guardian.svc.cluster.local"))
						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
					})
					It("tests that the ExternalService is setup with the url parsed from the given resolv.conf", func() {
						dir, err := os.Getwd()
						if err != nil {
							panic(err)
						}
						resolvConfPath := dir + "/testdata/resolv.conf"

						r, err := logstorage.NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, resolvConfPath)
						Expect(err).ShouldNot(HaveOccurred())

						_, err = r.Reconcile(reconcile.Request{})
						Expect(err).ShouldNot(HaveOccurred())

						svc := &corev1.Service{}
						Expect(
							cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace}, svc),
						).ShouldNot(HaveOccurred())

						Expect(svc.Spec.ExternalName).Should(Equal("tigera-guardian.tigera-guardian.svc.othername.local"))
						Expect(svc.Spec.Type).Should(Equal(corev1.ServiceTypeExternalName))
					})
				})

				Context("LogStorage exists", func() {
					BeforeEach(func() {
						setUpLogStorageComponents(cli, ctx, storageClassName, nil)
						mockStatus.On("OnCRFound").Return()
					})

					It("returns an error if the LogStorage resource exists and is not marked for deletion", func() {
						r, err := logstorage.NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, "")
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

						r, err := logstorage.NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, "")
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

				BeforeEach(func() {
					Expect(cli.Create(ctx, &operatorv1.Installation{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Status: operatorv1.InstallationStatus{
							Variant: operatorv1.TigeraSecureEnterprise,
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

					r, err := logstorage.NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, "")
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

					mockStatus.AssertExpectations(GinkgoT())
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
							Variant: operatorv1.TigeraSecureEnterprise,
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
					r, err := logstorage.NewReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, "")
					Expect(err).ShouldNot(HaveOccurred())

					By("making sure LogStorage has successfully reconciled")
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
					Expect(ls.Spec.StorageClassName).To(Equal(logstorage.DefaultElasticsearchStorageClass))

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
				Name: logstorage.DefaultElasticsearchStorageClass,
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
		[]*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}},
			{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraElasticsearchCertSecret, Namespace: render.ElasticsearchNamespace}},
			{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
		},
		[]*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}},
			{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraKibanaCertSecret, Namespace: render.KibanaNamespace}},
			{ObjectMeta: metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}},
		},
		false,
		[]*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
		}, operatorv1.ProviderNone,
		[]*corev1.Secret{
			{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchCuratorUserSecret, Namespace: render.OperatorNamespace()}},
			{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}},
		},
		nil, nil, "cluster.local", true, nil)

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
