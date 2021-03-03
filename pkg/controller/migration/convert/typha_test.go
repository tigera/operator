package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
)

func getK8sNodes(x int) *corev1.NodeList {
	nodes := &corev1.NodeList{
		Items: []corev1.Node{},
	}
	for i := 0; i < x; i++ {
		nodes.Items = append(nodes.Items, corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("node%d", i),
			},
		})
	}
	return nodes
}

var _ = Describe("Convert typha check tests", func() {
	var ctx = context.Background()
	var scheme *runtime.Scheme
	var pool *crdv1.IPPool
	BeforeEach(func() {
		scheme = kscheme.Scheme
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		pool = crdv1.NewIPPool()
		pool.Spec = crdv1.IPPoolSpec{
			CIDR:        "192.168.4.0/24",
			IPIPMode:    crdv1.IPIPModeAlways,
			NATOutgoing: true,
		}
	})

	Describe("handle when previous typha exists", func() {
		It("should not return an error with 2 nodes and 1 typha", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(1)

			c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td, getK8sNodes(2))
			_, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
		})
		It("should not return an error with 3 nodes and 1 typha", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(1)

			c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td, getK8sNodes(3))
			_, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
		})
	})
	Describe("handle enough nodes with previous Typha", func() {
		It("should succeed with 5 nodes and 1 typha ", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(1)

			c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td, getK8sNodes(5))
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
		It("should succeed with 8 nodes and 4 typha ", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(4)

			c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td, getK8sNodes(8))
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
	})
	Describe("handle no previous Typha", func() {
		It("should not error with 0 replicas", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(0)

			c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td, getK8sNodes(2))
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
		It("should not error with no replicas", func() {
			td := emptyTyphaDeployment()

			c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td, getK8sNodes(2))
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
		It("should not error with no typha deployment", func() {
			c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), getK8sNodes(2))
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
