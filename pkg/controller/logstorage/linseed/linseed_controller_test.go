// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package linseed

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/test"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

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
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var successResult = reconcile.Result{}

func NewLinseedControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
	multiTenant bool,
) (*LinseedSubController, error) {
	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		MultiTenant:      multiTenant,
	}

	r := &LinseedSubController{
		client:         cli,
		scheme:         scheme,
		status:         status,
		clusterDomain:  opts.ClusterDomain,
		multiTenant:    opts.MultiTenant,
		tierWatchReady: &utils.ReadyFlag{},
		dpiAPIReady:    &utils.ReadyFlag{},
	}
	r.tierWatchReady.MarkAsReady()
	r.dpiAPIReady.MarkAsReady()
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage Linseed controller", func() {
	var (
		cli        client.Client
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
		mockStatus *status.MockStatus
		r          *LinseedSubController
	)

	BeforeEach(func() {
		// This BeforeEach contains common preparation for all tests - both single-tenant and multi-tenant.
		// Any test-specific preparation should be done in subsequen BeforeEach blocks in the Contexts below.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		ctx = context.Background()
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		// Create a basic Installation.
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

		// Create a basic LogStorage.
		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		initializer.FillDefaults(ls)
		Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

		// Create a basic Elasticsearch instance.
		es := &esv1.Elasticsearch{}
		es.Name = "tigera-secure"
		es.Namespace = render.ElasticsearchNamespace
		es.Status.Phase = esv1.ElasticsearchReadyPhase
		Expect(cli.Create(ctx, es)).ShouldNot(HaveOccurred())

		// Create the allow-tigera Tier, since the controller blocks on its existence.
		tier := &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}}
		Expect(cli.Create(ctx, tier)).ShouldNot(HaveOccurred())
	})

	Context("Single tenant", func() {
		BeforeEach(func() {
			mockStatus = &status.MockStatus{}
			mockStatus.On("Run").Return()
			mockStatus.On("AddDaemonsets", mock.Anything)
			mockStatus.On("AddDeployments", mock.Anything)
			mockStatus.On("AddStatefulSets", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			mockStatus.On("ClearDegraded")

			// Create a CA secret for the test, and create its KeyPair.
			cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

			// Create secrets needed for successful installation.
			linseedKeyPair, err := cm.GetOrCreateKeyPair(cli, render.TigeraLinseedSecret, common.OperatorNamespace(), []string{"localhost"})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, linseedKeyPair.Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())
			tokenKeyPair, err := cm.GetOrCreateKeyPair(cli, render.TigeraLinseedTokenSecret, common.OperatorNamespace(), []string{"localhost"})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, tokenKeyPair.Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())
			bundle := cm.CreateTrustedBundle(linseedKeyPair)
			Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).ShouldNot(HaveOccurred())

			// Create the ES user secret. Generally this is created by either es-kube-controllers or the user controller in this operator.
			userSecret := &corev1.Secret{}
			userSecret.Name = render.ElasticsearchLinseedUserSecret
			userSecret.Namespace = render.ElasticsearchNamespace
			userSecret.Data = map[string][]byte{"username": []byte("test-username"), "password": []byte("test-password")}
			Expect(cli.Create(ctx, userSecret)).ShouldNot(HaveOccurred())

			// Create the reconciler for the tests.
			r, err = NewLinseedControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, false)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should wait for the cluster CA to be provisioned", func() {
			// Delete the CA secret for this test.
			caSecret := &corev1.Secret{}
			caSecret.Name = certificatemanagement.CASecretName
			caSecret.Namespace = common.OperatorNamespace()
			Expect(cli.Delete(ctx, caSecret)).ShouldNot(HaveOccurred())

			// Run the reconciler.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("CA secret"))
		})

		It("should reconcile resources for a standlone cluster", func() {
			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			// Check that Linseed was created as expected. We don't need to check every resource in detail, since
			// the render package has its own tests which cover this in more detail.
			linseedDp := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      linseed.DeploymentName,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &linseedDp)).To(BeNil())
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

			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			linseedDp := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      linseed.DeploymentName,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &linseedDp)).To(BeNil())
			linseed := test.GetContainer(linseedDp.Spec.Template.Spec.Containers, linseed.DeploymentName)
			Expect(linseed).ToNot(BeNil())
			Expect(linseed.Image).To(Equal(fmt.Sprintf("some.registry.org/%s@%s", components.ComponentLinseed.Image, "sha256:linseedhash")))
		})
	})

	Context("Multi-tenant", func() {
		var tenantNS string

		BeforeEach(func() {
			// Create the tenant Namespace.
			tenantNS = "tenant-namespace"
			Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tenantNS}})).ShouldNot(HaveOccurred())

			// Create the Tenant object.
			tenant := &operatorv1.Tenant{}
			tenant.Name = "default"
			tenant.Namespace = tenantNS
			tenant.Spec.ID = "test-tenant-id"
			Expect(cli.Create(ctx, tenant)).ShouldNot(HaveOccurred())

			mockStatus = &status.MockStatus{}
			mockStatus.On("Run").Return()
			mockStatus.On("AddDaemonsets", mock.Anything)
			mockStatus.On("AddDeployments", mock.Anything)
			mockStatus.On("AddStatefulSets", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			mockStatus.On("ClearDegraded")

			// Create a CA secret for the test, and create its KeyPair.
			opts := []certificatemanager.Option{
				certificatemanager.AllowCACreation(),
				certificatemanager.WithTenant(tenant),
			}
			cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, tenantNS, opts...)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, cm.KeyPair().Secret(tenantNS))).ShouldNot(HaveOccurred())

			// Create secrets needed for successful installation.
			linseedKeyPair, err := cm.GetOrCreateKeyPair(cli, render.TigeraLinseedSecret, tenantNS, []string{"localhost"})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, linseedKeyPair.Secret(tenantNS))).ShouldNot(HaveOccurred())
			tokenKeyPair, err := cm.GetOrCreateKeyPair(cli, render.TigeraLinseedTokenSecret, tenantNS, []string{"localhost"})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, tokenKeyPair.Secret(tenantNS))).ShouldNot(HaveOccurred())
			bundle := cm.CreateTrustedBundle(linseedKeyPair)
			Expect(cli.Create(ctx, bundle.ConfigMap(tenantNS))).ShouldNot(HaveOccurred())

			// Create the ES user secret. Generally this is created by either es-kube-controllers or the user controller in this operator.
			userSecret := &corev1.Secret{}
			userSecret.Name = render.ElasticsearchLinseedUserSecret
			userSecret.Namespace = tenantNS
			userSecret.Data = map[string][]byte{"username": []byte("test-username"), "password": []byte("test-password")}
			Expect(cli.Create(ctx, userSecret)).ShouldNot(HaveOccurred())

			// Create the reconciler for the test.
			r, err = NewLinseedControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, true)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should wait for the tenant CA to be provisioned", func() {
			// Delete the CA secret for this test.
			caSecret := &corev1.Secret{}
			caSecret.Name = certificatemanagement.TenantCASecretName
			caSecret.Namespace = tenantNS
			Expect(cli.Delete(ctx, caSecret)).ShouldNot(HaveOccurred())

			// Run the reconciler.
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("CA secret"))
		})

		It("should not reconcile any resources if no Namespace was given", func() {
			// Run the reconciler, passing in a Request with no Namespace. It should return successfully.
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that nothing was installed on the cluster.
			linseedDp := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      linseed.DeploymentName,
					Namespace: tenantNS,
				},
			}
			err = cli.Get(ctx, types.NamespacedName{Name: linseedDp.Name, Namespace: linseedDp.Namespace}, &linseedDp)
			Expect(err).Should(HaveOccurred())
			Expect(errors.IsNotFound(err)).Should(BeTrue())

			// Check that OnCRFound was not called.
			mockStatus.AssertNotCalled(GinkgoT(), "OnCRFound")
		})

		It("should reconcile resources for a standlone cluster", func() {
			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			// Check that Linseed was created as expected. We don't need to check every resource in detail, since
			// the render package has its own tests which cover this in more detail.
			linseedDp := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      linseed.DeploymentName,
					Namespace: tenantNS,
				},
			}
			Expect(test.GetResource(cli, &linseedDp)).To(BeNil())
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

			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			linseedDp := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      linseed.DeploymentName,
					Namespace: tenantNS,
				},
			}
			Expect(test.GetResource(cli, &linseedDp)).To(BeNil())
			linseed := test.GetContainer(linseedDp.Spec.Template.Spec.Containers, linseed.DeploymentName)
			Expect(linseed).ToNot(BeNil())
			Expect(linseed.Image).To(Equal(fmt.Sprintf("some.registry.org/%s@%s", components.ComponentLinseed.Image, "sha256:linseedhash")))
		})
	})
})
