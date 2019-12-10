package tunnel_test

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/tigera/operator/pkg/render"

	"github.com/tigera/operator/pkg/controller/tunnel"

	"github.com/tigera/operator/pkg/apis"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Tunnel controller tests", func() {
	var c client.Client
	var ctx context.Context
	var cfg *operatorv1.MulticlusterConfig
	var r tunnel.ReconcileTunnel
	var scheme *runtime.Scheme
	var dpl *appsv1.Deployment

	BeforeSuite(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		scheme.AddKnownTypes(schema.GroupVersion{Group: "apps", Version: "v1"}, &appsv1.Deployment{})
		scheme.AddKnownTypes(schema.GroupVersion{Group: "", Version: "v1"}, &rbacv1.ClusterRole{})
		scheme.AddKnownTypes(schema.GroupVersion{Group: "", Version: "v1"}, &rbacv1.ClusterRoleBinding{})
		err = operatorv1.SchemeBuilder.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()
		r = tunnel.ReconcileTunnel{
			Client:   c,
			Scheme:   scheme,
			Provider: operatorv1.ProviderAKS,
		}
		dpl = &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-guardian",
				Namespace: "tigera-guardian",
			},
		}
	})

	AfterSuite(func() {
		err := c.Delete(context.Background(), cfg)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should create a default multicluster config cfg", func() {
		// Create a multicluster config in the k8s client.
		cfg = &operatorv1.MulticlusterConfig{
			Spec: operatorv1.MulticlusterConfigSpec{
				ClusterManagementType: "Managed",
				ManagementClusterAddr: "127.0.0.1:12345",
			},
		}
		err := c.Create(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(
			ctx,
			&operatorv1.Installation{
				Spec: operatorv1.InstallationSpec{
					Registry:           "my-reg",
					KubernetesProvider: operatorv1.ProviderAKS,
				},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			})
		Expect(err).NotTo(HaveOccurred())
		// Create the Guardian deployment.
		_, err = tunnel.CreateOrModifyGuardian(ctx, &r, cfg)
		Expect(err).NotTo(HaveOccurred())
		err = c.Get(ctx, client.ObjectKey{Name: "tigera-guardian", Namespace: render.GuardianNamespace}, dpl)
		// Verify there is a deployment is enough for the purpose of this test. More detailed testing will be done
		// in the render package.
		Expect(err).NotTo(HaveOccurred())
		Expect(dpl.Labels["k8s-app"]).To(Equal("tigera-guardian"))
	})

	It("should cleanup a guardian deployment.", func() {
		// See if we can now delete the deployment by applying a new manifest.
		_, err := tunnel.CleanupGuardian(ctx, &r)
		Expect(err).NotTo(HaveOccurred())
		err = c.Get(ctx, client.ObjectKey{Name: "tigera-guardian", Namespace: render.GuardianNamespace}, dpl)
		Expect(err).To(HaveOccurred())
		Expect(errors.IsNotFound(err)).To(BeTrue())
	})
})
