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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	kfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Calico windows upgrader", func() {
	var cs *kfake.Clientset
	var nlw cache.ListerWatcher
	var client client.Client

	var mockStatus *status.MockStatus

	var currentEnterpriseVersion string
	var currentCalicoVersion string
	var savedVersion string
	var product operator.ProductVariant

	var requestChan chan utils.ReconcileRequest

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

		// Override the release version to the minimum Enterprise version that
		// supports upgrades.
		savedVersion = components.EnterpriseRelease
		components.EnterpriseRelease = "v3.11.0"
		currentEnterpriseVersion = "Enterprise-v3.11.0"

		currentCalicoVersion = fmt.Sprintf("Calico-%v", components.CalicoRelease)
		requestChan = make(chan utils.ReconcileRequest)
		product = operator.TigeraSecureEnterprise
	})

	AfterEach(func() {
		components.EnterpriseRelease = savedVersion
	})

	It("should do nothing if the product is Enterprise and version does not support Calico Windows upgrades", func() {
		components.EnterpriseRelease = savedVersion

		n1 := createNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := createNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, nil)

		// Create the upgrader and start it.
		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(product)
		})
		r.run()
		defer r.stop()
		c.start()

		// Nodes should not have changed.
		Consistently(func() error {
			return assertNodesUnchanged(cs, n1, n2)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should ignore linux nodes", func() {
		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(product)
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
			err = c.upgradeWindowsNodes(product)
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
		mockStatus.On("AddWindowsNodeUpgrade", "node2", currentEnterpriseVersion)

		n1 := createNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := createNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v2.0.0"})
		n3 := createNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: currentEnterpriseVersion})

		// Create the upgrader and start it.
		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(product)
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
		setNodeVersion(cs, c.nodeIndexer, n2, currentEnterpriseVersion)

		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n2)
		}, 20*time.Second).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should upgrade outdated nodes based on the installation variant", func() {
		n1 := createNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: currentEnterpriseVersion})

		c := newCalicoWindowsUpgrader(cs, client, nlw, mockStatus, requestChan)
		r := newTestReconciler(requestChan, func() error {
			return c.upgradeWindowsNodes(product)
		})
		r.run()
		defer r.stop()
		c.start()

		// None of the nodes have changed.
		Consistently(func() error {
			return assertNodesUnchanged(cs, n1)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		// Nothing was called.
		mockStatus.AssertExpectations(GinkgoT())

		// Trigger calicoWindowsUpgrader to run again but with Calico variant. Node should be upgraded.
		product = operator.Calico
		mockStatus.On("AddWindowsNodeUpgrade", "node1", currentCalicoVersion)

		// Trigger a reconcile (this would normally happen in the core
		// controller when the Installation cr changed).
		req := utils.ReconcileRequest{
			Context:    context.Background(),
			Request:    reconcile.Request{NamespacedName: types.NamespacedName{Name: n1.Name}},
			ResultChan: make(chan utils.ReconcileResult),
		}
		requestChan <- req

		// Ensure that the node has the new label and taint.
		Eventually(func() error {
			return assertNodesHadUpgradeTriggered(cs, n1)
		}, 20*time.Second).Should(BeNil())

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
