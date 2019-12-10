package manager

import (
	"context"

	"github.com/tigera/operator/pkg/apis"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Manager controller tests", func() {
	var c client.Client
	var instance *operatorv1.Manager

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme := runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		c = fake.NewFakeClientWithScheme(scheme)
	})

	AfterEach(func() {
		err := c.Delete(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should query a default manager instance", func() {
		By("Creating a CRD")
		instance = &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())
		instance, err = GetManager(context.Background(), c)
		Expect(err).NotTo(HaveOccurred())
	})
})
