// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package cloudrbac

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/cloudrbac"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Runtime Security Controller Tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileCloudRBAC
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		// Create a client that will have a crud interface of k8s objects.
		c = fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx = context.Background()

		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("RemoveCronJobs", mock.Anything).Return()
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()

		Expect(c.Create(ctx, &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Registry: "some.registry.org/",
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.TigeraSecureEnterprise,
				Computed: &operatorv1.InstallationSpec{
					Registry: "my-reg",
					// The test is provider agnostic.
					KubernetesProvider: operatorv1.ProviderNone,
				},
			},
		})).NotTo(HaveOccurred())

		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain)
		Expect(err).NotTo(HaveOccurred())
		internalManagerTLS, err := certificateManager.GetOrCreateKeyPair(c, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
		Expect(err).NotTo(HaveOccurred())

		Expect(c.Create(ctx, internalManagerTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		r = ReconcileCloudRBAC{
			client: c,
			scheme: scheme,
			status: mockStatus,
		}

	})

	It("should render accurate resources for Cloud RBAC", func() {

		By("applying the CloudRBAC CR to the fake cluster")
		Expect(c.Create(ctx, &operatorv1.CloudRBAC{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.CloudRBACSpec{
				PortalURL: "https://dummy.portal.url",
			},
		})).NotTo(HaveOccurred())

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		By("ensuring the Cloud RBAC API Deployment resource created ")
		deploy := appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cloudrbac.RBACApiDeploymentName,
				Namespace: cloudrbac.RBACApiNamespace,
			},
		}
		Expect(test.GetResource(c, &deploy)).To(BeNil())

		spec := deploy.Spec.Template.Spec
		Expect(spec.Containers).To(HaveLen(1))
		Expect(spec.Containers[0].Image).To(Equal(fmt.Sprintf("some.registry.org/%s:%s",
			components.ComponentCloudRBACApi.Image, components.ComponentCloudRBACApi.Version)))

	})

})
