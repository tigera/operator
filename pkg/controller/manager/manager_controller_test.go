package manager

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

var _ = Describe("Manager controller tests", func() {
	var c client.Client
	BeforeEach(func() {
		// Create a Kubernetes client.
		cfg, err := config.GetConfig()
		Expect(err).NotTo(HaveOccurred())
		c, err = client.New(cfg, client.Options{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should query a default manager instance", func() {
		By("Creating a CRD")
		instance := &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())
		instance, err = GetManager(context.Background(), c, operatorv1.ProviderNone)
		Expect(err).NotTo(HaveOccurred())
	})
})
