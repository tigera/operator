// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.
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

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/tls"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
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
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.

		// Create secrets necessary for reconcile to complete. These are typically created by the secrets controller.
		esKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), []string{render.TigeraElasticsearchInternalCertSecret})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, esKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		dnsNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, dns.DefaultClusterDomain)
		kbKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraKibanaCertSecret, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, kbKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Create the trusted bundle configmap. This is normally created out of band by the secret controller.
		bundle := certificateManager.CreateTrustedBundle(esKeyPair)
		Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).NotTo(HaveOccurred())

		prometheusTLS, err := certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusServerTLSSecretName})
		Expect(err).NotTo(HaveOccurred())

		Expect(cli.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())

		Expect(cli.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
		})).NotTo(HaveOccurred())

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
		externalCertsSecret := createPubSecret(logstorage.ExternalCertsSecret, common.OperatorNamespace(), []byte{}, "tls.crt")
		Expect(cli.Create(ctx, externalCertsSecret)).ShouldNot(HaveOccurred())

		Expect(cli.Create(
			ctx,
			&operatorv1.ManagementCluster{
				ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
			})).NotTo(HaveOccurred())

		mockStatus = &status.MockStatus{}
		mockStatus.On("Run").Return()
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
	})

	It("reconciles successfully", func() {
		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.LogStorageSpec{},
			Status:     operatorv1.LogStorageStatus{State: operatorv1.TigeraStatusReady},
		})

		// Run the reconciler and expect it to reach the end successfully.
		mockStatus.On("ClearDegraded")
		r, err := NewExternalESReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ToNot(HaveOccurred())
		Expect(result).Should(Equal(reconcile.Result{}))
		mockStatus.AssertExpectations(GinkgoT())
	})
})

func NewExternalESReconcilerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
) (*ExternalESController, error) {
	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		ElasticExternal:  true,
	}

	r := &ExternalESController{
		client:        cli,
		scheme:        scheme,
		status:        status,
		usePSP:        opts.UsePSP,
		clusterDomain: opts.ClusterDomain,
		provider:      opts.DetectedProvider,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}
