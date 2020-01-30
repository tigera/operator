package migration

import (
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Namespace Migration tests", func() {
	var c kubernetes.Interface
	var instance *CoreNamespaceMigration

	BeforeEach(func() {
		// Create a Kubernetes clientset.
		c = fake.NewSimpleClientset()
		instance = &CoreNamespaceMigration{
			client: c,
		}
	})

	AfterEach(func() {
		c = nil
	})

	Context("addNodeLabels", func() {
		It("should add labels to nodes", func() {
			_, err := c.CoreV1().Nodes().Create(&v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "testNode"},
			})
			Expect(err).NotTo(HaveOccurred())
			err = instance.addNodeLabels("testNode", map[string]string{"labelKey": "labelValue"})
			Expect(err).NotTo(HaveOccurred())
			n, err := c.CoreV1().Nodes().Get("testNode", metav1.GetOptions{})
			Expect(n.Labels).To(HaveKey("labelKey"))
			Expect(n.Labels["labelKey"]).To(Equal("labelValue"))
		})
	})
	Context("removeNodeLabels", func() {
		It("should remove labels from nodes", func() {
			_, err := c.CoreV1().Nodes().Create(&v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "testNode",
					Labels: map[string]string{"labelKey": "labelValue"},
				},
			})
			Expect(err).NotTo(HaveOccurred())
			err = instance.removeNodeLabels("testNode", map[string]string{"labelKey": "labelValue"})
			Expect(err).NotTo(HaveOccurred())
			n, err := c.CoreV1().Nodes().Get("testNode", metav1.GetOptions{})
			Expect(n.Labels).NotTo(HaveKey("labelKey"))
		})
	})

	Context("ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady ", func() {
		It("adds node selector correctly", func() {
			_, err := c.AppsV1().DaemonSets("kube-system").Create(&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-node",
					Namespace: "kube-system",
				},
				Spec: appsv1.DaemonSetSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
						//NodeSelector: map[string]string{"selectorKey": "selectorValue"},
						},
					},
				},
				Status: appsv1.DaemonSetStatus{
					DesiredNumberScheduled: 2,
					NumberReady:            2,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			err = instance.ensureKubeSysNodeDaemonSetHasNodeSelectorAndIsReady()
			Expect(err).NotTo(HaveOccurred())
			ds, err := c.AppsV1().DaemonSets(kubeSystem).Get("calico-node", metav1.GetOptions{})
			Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveKey(nodeSelectorKey))
		})
	})
})
