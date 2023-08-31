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

package kubecontrollers

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/test"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
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
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var successResult = reconcile.Result{RequeueAfter: 60 * time.Second}

func NewControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
	multiTenant bool,
) (*ESKubeControllersController, error) {
	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		MultiTenant:      multiTenant,
	}

	r := &ESKubeControllersController{
		client:        cli,
		scheme:        scheme,
		status:        status,
		clusterDomain: opts.ClusterDomain,
		multiTenant:   opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage ES kube-controllers controller", func() {
	var (
		cli        client.Client
		readyFlag  *utils.ReadyFlag
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
		mockStatus *status.MockStatus
		r          *ESKubeControllersController
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

		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()

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

		// Create ESGW admin secret. This is normally created by the ECK operator.
		esAdminUserSecret := &corev1.Secret{}
		esAdminUserSecret.Name = render.ElasticsearchAdminUserSecret
		esAdminUserSecret.Namespace = render.ElasticsearchNamespace
		esAdminUserSecret.Data = map[string][]byte{"username": []byte("password")}
		Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

		// Create a CA secret for the test, and create its KeyPair.
		cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create ESGW key pair.
		kp, err := cm.GetOrCreateKeyPair(cli, render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), []string{"localhost"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, kp.Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create secrets needed for successful installation.
		bundle := cm.CreateTrustedBundle()
		Expect(cli.Create(ctx, bundle.ConfigMap(common.CalicoNamespace))).ShouldNot(HaveOccurred())

		// Create the reconciler for the tests.
		r, err = NewControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, false)
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

		// SetDegraded should not have been called.
		mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)

		// Check that kube-controllers was created as expected. We don't need to check every resource in detail, since
		// the render package has its own tests which cover this in more detail.
		dep := appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubecontrollers.EsKubeController,
				Namespace: common.CalicoNamespace,
			},
		}
		Expect(test.GetResource(cli, &dep)).To(BeNil())

		// We also expect es-gateway to be created.
		dep = appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      esgateway.DeploymentName,
				Namespace: render.ElasticsearchNamespace,
			},
		}
		Expect(test.GetResource(cli, &dep)).To(BeNil())
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

		// Check that kube-controllers was created as expected. We don't need to check every resource in detail, since
		// the render package has its own tests which cover this in more detail.
		dep := appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubecontrollers.EsKubeController,
				Namespace: common.CalicoNamespace,
			},
		}
		Expect(test.GetResource(cli, &dep)).To(BeNil())
		kc := test.GetContainer(dep.Spec.Template.Spec.Containers, kubecontrollers.EsKubeController)
		Expect(kc).ToNot(BeNil())
		Expect(kc.Image).To(Equal(fmt.Sprintf("some.registry.org/%s@%s", components.ComponentTigeraKubeControllers.Image, "sha256:kubecontrollershash")))
	})
})

var _ = Describe("LogStorage ES kube-controllers controller - multi-tenant", func() {
	var (
		cli        client.Client
		readyFlag  *utils.ReadyFlag
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
		mockStatus *status.MockStatus
		r          *ESKubeControllersController
		tenantNS   string
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

		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()

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

		// Create the tenant Namespace.
		tenantNS = "tenant-namespace"
		Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tenantNS}})).ShouldNot(HaveOccurred())

		// Create the Tenant object.
		tenant := &operatorv1.Tenant{}
		tenant.Name = "default"
		tenant.Namespace = tenantNS
		tenant.Spec.ID = "test-tenant-id"
		Expect(cli.Create(ctx, tenant)).ShouldNot(HaveOccurred())

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

		// Create the cluster-wide CA secret.
		clusterCM, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), opts...)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, clusterCM.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create secrets needed for successful installation.
		bundle := cm.CreateTrustedBundle()
		Expect(cli.Create(ctx, bundle.ConfigMap(tenantNS))).ShouldNot(HaveOccurred())

		// Create ESGW admin secret. This is normally created by the ECK operator.
		// This is unused in multi-tenant mode, but create it anyway so that we can be more confident that the controller
		// is not using it.
		esAdminUserSecret := &corev1.Secret{}
		esAdminUserSecret.Name = render.ElasticsearchAdminUserSecret
		esAdminUserSecret.Namespace = render.ElasticsearchNamespace
		esAdminUserSecret.Data = map[string][]byte{"username": []byte("password")}
		Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

		// Create ESGW key pair.
		// This is unused in multi-tenant mode, but create it anyway so that we can be more confident that the controller
		// is not using it.
		kp, err := cm.GetOrCreateKeyPair(cli, render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), []string{"localhost"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, kp.Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create the reconciler for the test.
		r, err = NewControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, true)
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

	It("should reconcile resources for a standlone cluster", func() {
		// Run the reconciler.
		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(successResult))

		// Check that kube-controllers was created as expected. We don't need to check every resource in detail, since
		// the render package has its own tests which cover this in more detail.
		dep := appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubecontrollers.EsKubeController,
				Namespace: tenantNS,
			},
		}
		Expect(test.GetResource(cli, &dep)).To(BeNil())

		// There should be no ESGW in multi-tenant mode in either Namespace.
		dep = appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      esgateway.DeploymentName,
				Namespace: render.ElasticsearchNamespace,
			},
		}
		Expect(test.GetResource(cli, &dep)).ToNot(BeNil())
		dep.Namespace = tenantNS
		Expect(test.GetResource(cli, &dep)).ToNot(BeNil())
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

		// Check that kube-controllers was created as expected. We don't need to check every resource in detail, since
		// the render package has its own tests which cover this in more detail.
		dep := appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubecontrollers.EsKubeController,
				Namespace: tenantNS,
			},
		}
		Expect(test.GetResource(cli, &dep)).To(BeNil())
		kc := test.GetContainer(dep.Spec.Template.Spec.Containers, kubecontrollers.EsKubeController)
		Expect(kc).ToNot(BeNil())
		Expect(kc.Image).To(Equal(fmt.Sprintf("some.registry.org/%s@%s", components.ComponentTigeraKubeControllers.Image, "sha256:kubecontrollershash")))
	})
})
