// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.
//
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

	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var _ = Describe("External ES Controller", func() {
	var (
		cli                client.Client
		mockStatus         *status.MockStatus
		scheme             *runtime.Scheme
		ctx                context.Context
		certificateManager certificatemanager.CertificateManager
		install            *operatorv1.Installation
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
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		mockStatus = &status.MockStatus{}
		mockStatus.On("Run").Return()
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")

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

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.LogStorageSpec{},
			Status:     operatorv1.LogStorageStatus{State: operatorv1.TigeraStatusReady},
		})

		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())

		Expect(cli.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
		})).NotTo(HaveOccurred())

	})

	Context("Single tenant", func() {
		BeforeEach(func() {
			var err error
			certificateManager, err = certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.

			// Create secrets necessary for reconcile to complete. These are typically created by the secrets controller.
			esKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), []string{render.TigeraElasticsearchInternalCertSecret})
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, esKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			dnsNames := dns.GetServiceDNSNames(kibana.ServiceName, kibana.Namespace, dns.DefaultClusterDomain)
			kbKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, kibana.TigeraKibanaCertSecret, common.OperatorNamespace(), dnsNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, kbKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			// Create the trusted bundle configmap. This is normally created out of band by the secret controller.
			bundle := certificateManager.CreateTrustedBundle(esKeyPair)
			Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).NotTo(HaveOccurred())

			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())

			Expect(cli.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			// Create the public certs used to verify the Elasticsearch and Kibana.
			esPublicCert, err := secret.CreateTLSSecret(
				nil,
				"tigera-secure-es-http-certs-public",
				common.OperatorNamespace(),
				"tls.key",
				"tls.crt",
				tls.DefaultCertificateDuration,
				nil,
			)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, esPublicCert)).ShouldNot(HaveOccurred())

			kbPublicCert, err := secret.CreateTLSSecret(
				nil,
				"tigera-secure-kb-http-certs-public",
				common.OperatorNamespace(),
				"tls.key",
				"tls.crt",
				tls.DefaultCertificateDuration,
				nil,
			)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, kbPublicCert)).ShouldNot(HaveOccurred())

			// Create the ES admin username and password.
			esAdminUserSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ElasticsearchAdminUserSecret,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{"tigera-mgmt": []byte("password")},
			}
			Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

			// Create the ExternalCertsSecret which contains the client certificate for connecting to the external ES cluster.
			externalCertsSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      logstorage.ExternalCertsSecret,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{
					"tls.crt": {},
				},
			}
			Expect(cli.Create(ctx, externalCertsSecret)).ShouldNot(HaveOccurred())
		})

		It("reconciles successfully", func() {
			// Run the reconciler and expect it to reach the end successfully.
			mockStatus.On("ClearDegraded")
			r, err := NewExternalESReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, false)
			Expect(err).ShouldNot(HaveOccurred())
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ToNot(HaveOccurred())
			Expect(result).Should(Equal(reconcile.Result{}))
			mockStatus.AssertExpectations(GinkgoT())
		})
	})

	Context("Multi tenant", func() {
		var (
			tenant      *operatorv1.Tenant
			tenantNS    = "tenant-ns-a"
			eckOperator = appsv1.StatefulSet{
				TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      eck.OperatorName,
					Namespace: eck.OperatorNamespace,
				},
			}
			kibanaCR = kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: kibana.CRName, Namespace: tenantNS}}
		)

		BeforeEach(func() {
			Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tenantNS}})).ShouldNot(HaveOccurred())

			// Create a dummy secret mocking the client certificates needed for mTLS.
			esClientSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: logstorage.ExternalCertsSecret, Namespace: common.OperatorNamespace()},
				Data:       map[string][]byte{"client.crt": []byte("cert"), "client.key": []byte("key")},
			}
			Expect(cli.Create(ctx, esClientSecret)).ShouldNot(HaveOccurred())

			clusterIDConfigMap := corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cluster-info",
					Namespace: "tigera-operator",
				},
				Data: map[string]string{
					"cluster-id": "cluster-id",
				},
			}
			err := cli.Create(ctx, &clusterIDConfigMap)
			Expect(err).NotTo(HaveOccurred())

			tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: tenantNS,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a",
					Elastic: &operatorv1.TenantElasticSpec{
						URL:       "https://external.elastic:443",
						MutualTLS: true,
					},
					Kibana: &operatorv1.TenantKibanaSpec{
						URL: fmt.Sprintf("https://kibana.%s.svc:5601", tenantNS),
					},
				},
			}
			Expect(cli.Create(ctx, tenant)).ShouldNot(HaveOccurred())

			// Create a CA secret for the test, and create its KeyPair.
			opts := []certificatemanager.Option{
				certificatemanager.AllowCACreation(),
				certificatemanager.WithTenant(tenant),
			}
			cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, tenantNS, opts...)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, cm.KeyPair().Secret(tenantNS))).ShouldNot(HaveOccurred())
			bundle := cm.CreateTrustedBundle()
			Expect(cli.Create(ctx, bundle.ConfigMap(tenantNS))).ShouldNot(HaveOccurred())
		})

		It("should reconcile resources", func() {
			mockStatus.On("AddStatefulSets", mock.Anything)
			mockStatus.On("ClearDegraded")

			r, err := NewExternalESReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, true)
			Expect(err).ShouldNot(HaveOccurred())
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).ToNot(HaveOccurred())
			Expect(result).Should(Equal(reconcile.Result{}))
			mockStatus.AssertExpectations(GinkgoT())

			// Check that ECK was created as expected. We don't need to check every resource in detail, since
			// the render package has its own tests which cover this in more detail.
			Expect(test.GetResource(cli, &eckOperator)).NotTo(HaveOccurred())

			// Check that Kibana CR was created as expected. We don't need to check every resource in detail, since
			// the render package has its own tests which cover this in more detail.
			Expect(test.GetResource(cli, &kibanaCR)).NotTo(HaveOccurred())
		})

		It("should reconcile resources when kibana is disabled per tenant", func() {
			mockStatus.On("ClearDegraded")

			// Disable Kibana
			tenant.Spec.Kibana = nil
			Expect(cli.Update(ctx, tenant)).ShouldNot(HaveOccurred())

			r, err := NewExternalESReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, true)
			Expect(err).ShouldNot(HaveOccurred())
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).ToNot(HaveOccurred())
			Expect(result).Should(Equal(reconcile.Result{}))
			mockStatus.AssertExpectations(GinkgoT())

			Expect(test.GetResource(cli, &eckOperator)).To(HaveOccurred())
			Expect(test.GetResource(cli, &kibanaCR)).To(HaveOccurred())
		})

		It("should wait for the tenant CA to be provisioned", func() {
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

			// Delete the CA secret for this test.
			caSecret := &corev1.Secret{}
			caSecret.Name = certificatemanagement.TenantCASecretName
			caSecret.Namespace = tenantNS
			Expect(cli.Delete(ctx, caSecret)).ShouldNot(HaveOccurred())

			// Run the reconciler.
			r, err := NewExternalESReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, true)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("CA secret"))
		})

		It("should not reconcile any resources if no Namespace was given", func() {
			// Run the reconciler.
			r, err := NewExternalESReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, true)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

})

func NewExternalESReconcilerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
	multiTenant bool,
) (*ExternalESController, error) {
	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		ElasticExternal:  true,
		MultiTenant:      multiTenant,
	}

	r := &ExternalESController{
		client:        cli,
		scheme:        scheme,
		status:        status,
		usePSP:        opts.UsePSP,
		clusterDomain: opts.ClusterDomain,
		provider:      opts.DetectedProvider,
		multiTenant:   opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}
