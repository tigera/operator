// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package installation

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	kfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Calico windows upgrader", func() {
	var cs *kfake.Clientset
	var nlw cache.ListerWatcher
	var client client.Client

	var mockStatus *status.MockStatus
	var currentCalicoVersion string
	var requestChan chan utils.ReconcileRequest

	one := intstr.FromInt(1)
	var updateStrategy appsv1.DaemonSetUpdateStrategy

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())

		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(schedv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		client = fake.NewFakeClientWithScheme(scheme)

		cs = kfake.NewSimpleClientset()
		nlw = nodeListWatch{cs}
		mockStatus = &status.MockStatus{}

		currentCalicoVersion = fmt.Sprintf("Calico-%v", components.CalicoRelease)
		requestChan = make(chan utils.ReconcileRequest)

		updateStrategy = appsv1.DaemonSetUpdateStrategy{
			RollingUpdate: &appsv1.RollingUpdateDaemonSet{
				MaxUnavailable: &one,
			},
		}
	})

	It("should do nothing if the product is Enterprise", func() {
		n1 := createNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := createNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, nil)
		n3 := createNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v2.0.0"})

		// Create the upgrader and start it.
		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(operator.TigeraSecureEnterprise, updateStrategy)
		})
		r.run()
		defer r.stop()
		c.start()

		// Nodes should not have changed.
		Consistently(func() error {
			return assertNodesUnchanged(cs, n1, n2, n3)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should ignore linux nodes", func() {
		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(operator.Calico, updateStrategy)
		})
		r.run()
		defer r.stop()
		c.start()

		n1 := createNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := createNode(cs, "node2", map[string]string{"kubernetes.io/os": "linux"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v2.0.0"})

		Consistently(func() error {
			return assertNodesUnchanged(cs, n1, n2)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should return an error if Windows nodes are missing the version annotation ", func() {
		n1 := createNode(cs, "unsupported-node", map[string]string{"kubernetes.io/os": "windows"}, nil)

		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		var err error
		r := newTestReconciler(requestChan, func() error {
			// Check that the upgrade fails.
			err = c.upgradeWindowsNodes(operator.Calico, updateStrategy)
			// Don't return the error, we want the test to continue.
			return nil
		})
		r.run()
		defer r.stop()
		c.start()

		Consistently(func() error {
			return assertNodesUnchanged(cs, n1)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		Expect(err).To(HaveOccurred())
		errString := "Error getting windows nodes: Node unsupported-node does not have the version annotation, it might be unhealthy or it might be running an unsupported Calico version."
		Expect(err.Error()).To(Equal(errString))
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should upgrade outdated nodes", func() {
		// Only node n2 should be upgraded.
		mockStatus.On("AddWindowsNodeUpgrade", "node2", currentCalicoVersion)

		n1 := createNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := createNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		n3 := createNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: currentCalicoVersion})

		// Create the upgrader and start it.
		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(operator.Calico, updateStrategy)
		})
		r.run()
		defer r.stop()
		c.start()

		// Only node n2 should have changed.
		Consistently(func() error {
			return assertNodesUnchanged(cs, n1, n3)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		// Ensure that node n2 has the new label and taint.
		Eventually(func() error {
			return assertNodesHadUpgradeTriggered(cs, n2)
		}, 10*time.Second).Should(BeNil())

		// At this point, we should only have a call to AddWindowsNodeUpgrade.
		mockStatus.AssertExpectations(GinkgoT())

		// Set the latest Calico Windows version like the node service would.
		mockStatus.On("RemoveWindowsNodeUpgrade", "node2")
		setNodeVersion(cs, c.nodeIndexer, n2, currentCalicoVersion)

		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n2)
		}, 20*time.Second).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should upgrade outdated nodes if the installation variant differs", func() {
		// Create a Windows node running Enterprise with the Calico Windows
		// version annotation. This can't actually exist
		// yet since Calico Windows upgrades on Enterprise are not supported yet. However, this is a way to test
		// that the upgrade is triggered when going to a different product
		// variant.
		n1 := createNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v3.11.0"})

		// Trigger calicoWindowsUpgrader to run with Calico variant. Node should be upgraded.
		mockStatus.On("AddWindowsNodeUpgrade", "node1", currentCalicoVersion)
		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(operator.Calico, updateStrategy)
		})
		r.run()
		defer r.stop()
		c.start()

		// Ensure the node has the new label and taint.
		Eventually(func() error {
			return assertNodesHadUpgradeTriggered(cs, n1)
		}, 10*time.Second).Should(BeNil())

		// At this point, we should only have a call to AddWindowsNodeUpgrade.
		mockStatus.AssertExpectations(GinkgoT())

		// Set the latest Calico Windows version like the node service would. This will trigger a reconcile.
		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		mockStatus.On("RemoveWindowsNodeUpgrade", "node1")
		setNodeVersion(cs, c.nodeIndexer, n1, currentCalicoVersion)

		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n1)
		}, 20*time.Second).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should set maxUnavailable correctly", func() {
		// Create 5 nodes, all ready to be upgraded.
		createNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		createNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		createNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		createNode(cs, "node4", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		createNode(cs, "node5", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})

		// We won't know which node will end up being added for upgrade.
		mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, currentCalicoVersion)

		mu := intstr.FromString("20%")
		pctStrategy := appsv1.DaemonSetUpdateStrategy{
			RollingUpdate: &appsv1.RollingUpdateDaemonSet{
				MaxUnavailable: &mu,
			},
		}

		// Create the upgrader and start it.
		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(operator.Calico, pctStrategy)
		})
		r.run()
		defer r.stop()
		c.start()

		Expect(c.maxUnavailable.String()).To(Equal("20%"))

		Eventually(func() error {
			if len(c.nodesToUpgrade) == 1 {
				return fmt.Errorf("nodesToUpgrade is %v", len(c.nodesToUpgrade))
			}
			return nil
		}, 10*time.Second).Should(BeNil())

		// Now change to 60% which should be 3 nodes that should be
		// upgradable/upgrading.
		mu = intstr.FromString("60%")
		pctStrategy.RollingUpdate.MaxUnavailable = &mu
		err := c.upgradeWindowsNodes(operator.Calico, pctStrategy)
		Expect(err).To(BeNil())

		Eventually(func() error {
			if len(c.nodesToUpgrade) == 3 {
				return fmt.Errorf("nodesToUpgrade is %v", len(c.nodesToUpgrade))
			}
			return nil
		}, 10*time.Second).Should(BeNil())
	})

	Context("getMaxNodesToUpgrade", func() {
		node := func(name, version string) *corev1.Node {
			return &corev1.Node{
				TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:        "pending1",
					Annotations: map[string]string{common.CalicoWindowsVersionAnnotation: version},
				},
			}
		}

		It("should count already upgrading nodes against maxUnavailable, for Calico to Calico upgrades", func() {
			c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)

			p1 := node("pending1", "Calico-v3.21.999")
			p2 := node("pending2", "Calico-v3.21.999")
			u1 := node("upgrading1", "Calico-v3.21.999")

			// 2 maxUnavailable, 1 already upgrading
			toUpgrade := c.getMaxNodesToUpgrade("Calico-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 2)
			Expect(len(toUpgrade)).To(Equal(1))
			Expect(toUpgrade).To(ContainElements(p1))

			// 1 maxUnavailable, 1 already upgrading
			toUpgrade = c.getMaxNodesToUpgrade("Calico-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 1)
			Expect(len(toUpgrade)).To(Equal(0))

			// 0 maxUnavailable, 1 already upgrading
			toUpgrade = c.getMaxNodesToUpgrade("Calico-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 0)
			Expect(len(toUpgrade)).To(Equal(0))
		})

		It("should count already upgrading nodes against maxUnavailable, for Enterprise to Calico upgrades", func() {
			c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)

			p1 := node("pending1", "Enterprise-v3.11.0")
			p2 := node("pending2", "Enterprise-v3.11.0")
			u1 := node("upgrading1", "Enterprise-v3.11.0")

			// 2 maxUnavailable, 1 already upgrading
			toUpgrade := c.getMaxNodesToUpgrade("Calico-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 2)
			Expect(len(toUpgrade)).To(Equal(1))
			Expect(toUpgrade).To(ContainElements(p1))

			// 1 maxUnavailable, 1 already upgrading
			toUpgrade = c.getMaxNodesToUpgrade("Calico-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 1)
			Expect(len(toUpgrade)).To(Equal(0))

			// 0 maxUnavailable, 1 already upgrading
			toUpgrade = c.getMaxNodesToUpgrade("Calico-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 0)
			Expect(len(toUpgrade)).To(Equal(0))
		})

		It("should count already upgrading nodes against maxUnavailable, for Enterprise to Enterprise upgrades", func() {
			c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)

			p1 := node("pending1", "Enterprise-v3.11.0")
			p2 := node("pending2", "Enterprise-v3.11.0")
			u1 := node("upgrading1", "Enterprise-v3.11.0")

			// 2 maxUnavailable, 1 already upgrading
			toUpgrade := c.getMaxNodesToUpgrade("Enterprise-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 2)
			Expect(len(toUpgrade)).To(Equal(1))
			Expect(toUpgrade).To(ContainElements(p1))

			// 1 maxUnavailable, 1 already upgrading
			toUpgrade = c.getMaxNodesToUpgrade("Enterprise-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 1)
			Expect(len(toUpgrade)).To(Equal(0))

			// 0 maxUnavailable, 1 already upgrading
			toUpgrade = c.getMaxNodesToUpgrade("Enterprise-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 0)
			Expect(len(toUpgrade)).To(Equal(0))
		})

		It("should upgrade nodes going from Calico to Enterprise right away, even if available slots is 0", func() {
			c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)

			p1 := node("pending1", "Calico-v3.21.999")
			p2 := node("pending2", "Calico-v3.21.999")
			u1 := node("upgrading1", "Calico-v3.21.999")

			// maxUnavailable = 0. The pending nodes should still be upgraded
			// despite 0 availability.
			toUpgrade := c.getMaxNodesToUpgrade("Enterprise-master", []*corev1.Node{p1, p2}, []*corev1.Node{u1}, 0)
			Expect(len(toUpgrade)).To(Equal(2))
			Expect(toUpgrade).To(ContainElements(p1, p2))

			// Have an upgrade from Ent -> Ent and maxUnavailable = 1. Same
			// 2 pending nodes should be upgraded.
			u2 := node("upgrading1", "Enterprise-old")
			toUpgrade = c.getMaxNodesToUpgrade("Enterprise-master", []*corev1.Node{p1, p2}, []*corev1.Node{u2}, 1)
			Expect(len(toUpgrade)).To(Equal(2))
			Expect(toUpgrade).To(ContainElements(p1, p2))
		})

	})
})

func assertNodesUnchanged(c kubernetes.Interface, nodes ...*corev1.Node) error {
	for _, node := range nodes {
		newNode, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
		Expect(err).To(BeNil())
		if !reflect.DeepEqual(node, newNode) {
			return fmt.Errorf("expected node %q to be unchanged", node.Name)
		}
	}
	return nil
}

func assertNodesHadUpgradeTriggered(c kubernetes.Interface, nodes ...*corev1.Node) error {
	for _, node := range nodes {
		newNode, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
		Expect(err).To(BeNil())

		label := newNode.Labels[common.CalicoWindowsUpgradeScriptLabel]
		if label != common.CalicoWindowsUpgradeScript {
			return fmt.Errorf("expected node %q to have upgrade label but it had: %q", node.Name, label)
		}

		var found bool
		for _, taint := range newNode.Spec.Taints {
			if taint.MatchTaint(calicoWindowsUpgradingTaint) {
				found = true
			}
		}

		if !found {
			return fmt.Errorf("expected node %q to have upgrade taint", node.Name)
		}
	}
	return nil
}

func assertNodesFinishedUpgrade(c kubernetes.Interface, nodes ...*corev1.Node) error {
	for _, node := range nodes {
		newNode, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
		Expect(err).To(BeNil())

		if _, ok := newNode.Labels[common.CalicoWindowsUpgradeScriptLabel]; ok {
			return fmt.Errorf("expected node %q to have upgrade label removed", newNode.Name)
		}

		var found bool
		for _, taint := range newNode.Spec.Taints {
			if taint.MatchTaint(calicoWindowsUpgradingTaint) {
				found = true
			}
		}

		if found {
			return fmt.Errorf("expected node %q to have upgrade taint removed", node.Name)
		}
	}
	return nil
}

func setNodeVersion(c kubernetes.Interface, indexer cache.Indexer, node *corev1.Node, version string) {
	n, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
	Expect(err).To(BeNil())
	n.Annotations[common.CalicoWindowsVersionAnnotation] = version
	_, err = c.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
	Expect(err).To(BeNil())

	Eventually(func() error {
		obj, exists, err := indexer.GetByKey(node.Name)
		if !exists {
			return fmt.Errorf("node doesn't exist, did a test get updated?")
		}
		if err != nil {
			return fmt.Errorf("got an error: %w", err)
		}

		node := obj.(*corev1.Node)
		if node.Annotations[common.CalicoWindowsVersionAnnotation] == version {
			return nil
		}

		return fmt.Errorf("node does not have expected version yet: %v", version)
	}, 20*time.Second).Should(BeNil())
}

// testReconciler processes ReconcileRequests from a request chan and runs
// a handler for each request.
type testReconciler struct {
	requestChan <-chan utils.ReconcileRequest
	doneChan    chan interface{}
	handler     func() error
}

func newTestReconciler(requestChan <-chan utils.ReconcileRequest, handler func() error) *testReconciler {
	return &testReconciler{
		requestChan: requestChan,
		doneChan:    make(chan interface{}),
		handler:     handler,
	}
}

// run processes reconcile requests.
func (r *testReconciler) run() {
	go func() {
	out:
		for {
			select {
			case <-r.requestChan:
				err := r.handler()
				if err != nil {
					fmt.Printf("\n\nHandler returned error: %v\n\n", err)
				}
				Expect(err).NotTo(HaveOccurred())
			case <-r.doneChan:
				break out
			default:
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()

}

func (r *testReconciler) stop() {
	close(r.doneChan)
}
