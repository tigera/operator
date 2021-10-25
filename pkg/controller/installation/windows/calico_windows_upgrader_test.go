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

package windows

import (
	"context"
	"fmt"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/node"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	test "github.com/tigera/operator/test"
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
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Calico windows upgrader", func() {
	var c CalicoWindowsUpgrader
	var cs *kfake.Clientset
	var client kclient.Client
	var r *testReconciler

	var mockStatus *status.MockStatus
	var currentCalicoVersion string
	var nodeIndexer cache.Indexer
	var nodeInformer cache.Controller

	var syncPeriodOption calicoWindowsUpgraderOption
	var requestChan chan utils.ReconcileRequest
	var ctx context.Context
	var cancel context.CancelFunc

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
		mockStatus = &status.MockStatus{}

		syncPeriodOption = calicoWindowsUpgraderSyncPeriod(2 * time.Second)

		currentCalicoVersion = fmt.Sprintf("Calico-%v", components.CalicoRelease)
		nlw := test.NodeListWatch{cs}
		nodeIndexer, nodeInformer = node.CreateNodeIndexerInformer(nlw)

		ctx, cancel = context.WithCancel(context.TODO())
		go nodeInformer.Run(ctx.Done())
		for !nodeInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}
		requestChan = make(chan utils.ReconcileRequest, 1)

		c = NewCalicoWindowsUpgrader(cs, client, nodeIndexer, mockStatus, requestChan, syncPeriodOption)
		one := intstr.FromInt(1)
		r = newTestReconciler(requestChan, operator.Calico, &one)
		r.handler = func() error {
			c.SetInstallationParams(r.variant, r.maxUnavailable)
			return c.UpgradeWindowsNodes()
		}
	})

	AfterEach(func() {
		cancel()
	})

	It("should do nothing if the product is Enterprise", func() {
		// We start off Enterprise install
		r.variant = operator.TigeraSecureEnterprise

		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.0.0"})
		n3 := test.CreateNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v2.0.0"})

		// Create the upgrader and start it.
		r.run(ctx)
		c.Start(ctx)
		r.reconcile()

		// Nodes should not have changed.
		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1, n2, n3)
		}, 5*time.Second, 100*time.Millisecond).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should ignore linux nodes", func() {
		r.run(ctx)
		c.Start(ctx)
		r.reconcile()

		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "linux"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v2.0.0"})

		r.reconcile()

		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1, n2)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should set degraded if Windows nodes are missing the version annotation", func() {
		n1 := test.CreateNode(cs, "unsupported-node", map[string]string{"kubernetes.io/os": "windows"}, nil)

		mockStatus.On("SetDegraded", "Failed to sync Windows nodes", "Node unsupported-node does not have the version annotation, it might be unhealthy or it might be running an unsupported Calico version.").Return()

		r.run(ctx)
		c.Start(ctx)
		r.reconcile()

		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1)
		}, 5*time.Second, 100*time.Millisecond).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should upgrade outdated nodes", func() {
		// Only node n2 should be upgraded.
		mockStatus.On("AddWindowsNodeUpgrade", "node2", "Calico-v3.21.999", currentCalicoVersion)

		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		n3 := test.CreateNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: currentCalicoVersion})

		r.run(ctx)
		c.Start(ctx)
		r.reconcile()

		Eventually(func() error {
			return test.AssertNodesUnchanged(cs, n1, n3)
		}, 5*time.Second, 100*time.Millisecond).Should(BeNil())

		// Only node n2 should have changed.
		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1, n3)
		}, 5*time.Second, 100*time.Millisecond).Should(BeNil())

		// Ensure that node n2 has the new label and taint.
		Eventually(func() error {
			return test.AssertNodesHadUpgradeTriggered(cs, n2)
		}, 5*time.Second).Should(BeNil())

		// At this point, we should only have a call to AddWindowsNodeUpgrade.
		mockStatus.AssertExpectations(GinkgoT())

		// Set the latest Calico Windows version like the node service would.
		mockStatus.On("RemoveWindowsNodeUpgrade", "node2")
		setNodeVersion(cs, nodeIndexer, n2, currentCalicoVersion)

		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n2)
		}, 5*time.Second).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should upgrade outdated nodes if the installation variant differs", func() {
		// Create a Windows node running Enterprise with the Calico Windows
		// version annotation. This can't actually exist
		// yet since Calico Windows upgrades on Enterprise are not supported yet. However, this is a way to test
		// that the upgrade is triggered when going to a different product
		// variant.
		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v3.11.0"})

		mockStatus.On("AddWindowsNodeUpgrade", "node1", "Enterprise-v3.11.0", currentCalicoVersion)

		r.run(ctx)
		c.Start(ctx)
		r.reconcile()

		// Ensure the node has the new label and taint.
		Eventually(func() error {
			return test.AssertNodesHadUpgradeTriggered(cs, n1)
		}, 5*time.Second).Should(BeNil())

		// At this point, we should only have a call to AddWindowsNodeUpgrade.
		mockStatus.AssertExpectations(GinkgoT())

		// Set the latest Calico Windows version like the node service would. This will trigger a reconcile.
		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		mockStatus.On("RemoveWindowsNodeUpgrade", "node1")
		setNodeVersion(cs, nodeIndexer, n1, currentCalicoVersion)

		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n1)
		}, 5*time.Second).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should use maxUnavailable correctly", func() {
		// Create installation with rolling update strategy with 20%
		// maxUnavailable.
		mu := intstr.FromString("20%")
		r.maxUnavailable = &mu

		// Create 5 nodes, all ready to be upgraded.
		test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		test.CreateNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		test.CreateNode(cs, "node4", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
		test.CreateNode(cs, "node5", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})

		// We won't know which nodes will end up being added for upgrade.
		mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, "Calico-v3.21.999", currentCalicoVersion)

		r.run(ctx)
		c.Start(ctx)
		r.reconcile()

		count := func() int {
			return countNodesUpgrading(nodeIndexer)
		}
		Eventually(count, 10*time.Second).Should(Equal(1))
		Consistently(count, 10*time.Second).Should(Equal(1))

		// Now change to 60% which should result in 3 nodes that should be
		// upgradable.
		mu = intstr.FromString("60%")
		r.maxUnavailable = &mu

		// Reconcile the installation (normally this would be triggered by the
		// watch by the core controller)
		r.reconcile()

		Eventually(count, 5*time.Second).Should(Equal(3))
		Consistently(count, 10*time.Second).Should(Equal(3))
	})

	Context("Test max upgrading nodes depending on upgrade type", func() {
		It("should count already upgrading nodes against maxUnavailable, for Calico to Calico upgrades", func() {
			test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
			test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
			test.CreateNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})

			mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, "Calico-v3.21.999", currentCalicoVersion)

			r.run(ctx)
			c.Start(ctx)
			r.reconcile()

			count := func() int {
				return countNodesUpgrading(nodeIndexer)
			}
			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu := intstr.FromInt(0)
			r.maxUnavailable = &mu
			r.reconcile()

			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu = intstr.FromInt(2)
			r.maxUnavailable = &mu
			r.reconcile()

			Eventually(count, 5*time.Second).Should(Equal(2))
			Consistently(count, 5*time.Second).Should(Equal(2))
		})

		It("should count already upgrading nodes against maxUnavailable, for Enterprise to Calico upgrades", func() {
			test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v3.11.0"})
			test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v3.11.0"})
			test.CreateNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-v3.11.0"})

			mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, "Enterprise-v3.11.0", currentCalicoVersion)

			r.run(ctx)
			c.Start(ctx)
			r.reconcile()

			count := func() int {
				return countNodesUpgrading(nodeIndexer)
			}
			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu := intstr.FromInt(0)
			r.maxUnavailable = &mu
			r.reconcile()

			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu = intstr.FromInt(2)
			r.maxUnavailable = &mu
			r.reconcile()

			Eventually(count, 5*time.Second).Should(Equal(2))
			Consistently(count, 5*time.Second).Should(Equal(2))
		})

		It("should count already upgrading nodes against maxUnavailable, for Enterprise to Enterprise upgrades", func() {
			Skip("This test does not yet work since upgrades to Enterprise are not supported yet")

			test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-old"})
			test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-old"})
			test.CreateNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Enterprise-old"})

			mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, "Enterprise-v3.11.0", currentCalicoVersion)

			r.variant = operator.TigeraSecureEnterprise
			r.run(ctx)
			c.Start(ctx)
			r.reconcile()

			count := func() int {
				return countNodesUpgrading(nodeIndexer)
			}
			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu := intstr.FromInt(0)
			r.maxUnavailable = &mu
			r.reconcile()

			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu = intstr.FromInt(2)
			r.maxUnavailable = &mu
			r.reconcile()

			Eventually(count, 5*time.Second).Should(Equal(2))
			Consistently(count, 5*time.Second).Should(Equal(2))
		})

		It("should upgrade nodes going from Calico to Enterprise right away, even if max available slots is 0", func() {
			Skip("This test does not yet work since upgrades to Enterprise are not supported yet")

			test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
			test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})
			test.CreateNode(cs, "node3", map[string]string{"kubernetes.io/os": "windows"}, map[string]string{common.CalicoWindowsVersionAnnotation: "Calico-v3.21.999"})

			mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, "Calico-v3.21.999", "Enterprise-master")

			r.variant = operator.TigeraSecureEnterprise
			r.run(ctx)
			c.Start(ctx)
			r.reconcile()

			count := func() int {
				return countNodesUpgrading(nodeIndexer)
			}
			// The pending nodes should still be upgraded despite max unavailability
			// value.
			Eventually(count, 5*time.Second).Should(Equal(3))
			Consistently(count, 5*time.Second).Should(Equal(3))

			mu := intstr.FromInt(0)
			r.maxUnavailable = &mu
			r.reconcile()

			// The pending nodes should still be upgraded despite max unavailability
			// value.
			Eventually(count, 5*time.Second).Should(Equal(3))
			Consistently(count, 5*time.Second).Should(Equal(3))

			mu = intstr.FromInt(2)
			r.maxUnavailable = &mu
			r.reconcile()

			// The pending nodes should still be upgraded despite max unavailability
			// value.
			Eventually(count, 5*time.Second).Should(Equal(3))
			Consistently(count, 5*time.Second).Should(Equal(3))
		})
	})
})

func countNodesUpgrading(nodeIndexer cache.Indexer) int {
	count := 0
	for _, obj := range nodeIndexer.List() {
		node := obj.(*corev1.Node)
		if _, ok := node.Labels[common.CalicoWindowsUpgradeLabel]; !ok {
			continue
		}
		found := false
		for _, taint := range node.Spec.Taints {
			if taint.MatchTaint(common.CalicoWindowsUpgradingTaint) {
				found = true
			}
		}
		if !found {
			continue
		}
		count++
	}
	return count
}

func assertNodesFinishedUpgrade(c kubernetes.Interface, nodes ...*corev1.Node) error {
	for _, node := range nodes {
		newNode, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
		Expect(err).To(BeNil())

		if _, ok := newNode.Labels[common.CalicoWindowsUpgradeLabel]; ok {
			return fmt.Errorf("expected node %q to have upgrade label removed", newNode.Name)
		}

		var found bool
		for _, taint := range newNode.Spec.Taints {
			if taint.MatchTaint(common.CalicoWindowsUpgradingTaint) {
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
	// Get the existing node.
	n, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
	Expect(err).To(BeNil())

	// Add the version annotation to the node.
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
	requestChan    chan utils.ReconcileRequest
	variant        operator.ProductVariant
	maxUnavailable *intstr.IntOrString
	handler        func() error
}

func newTestReconciler(requestChan chan utils.ReconcileRequest, variant operator.ProductVariant, maxUnavailable *intstr.IntOrString) *testReconciler {
	return &testReconciler{
		requestChan:    requestChan,
		variant:        variant,
		maxUnavailable: maxUnavailable,
	}
}

func (r *testReconciler) reconcile() {
	r.requestChan <- utils.ReconcileRequest{
		Context:    context.TODO(),
		Request:    reconcile.Request{},
		ResultChan: make(chan utils.ReconcileResult),
	}
}

// run processes reconcile requests.
func (r *testReconciler) run(ctx context.Context) {
	go func() {
		for {
			select {
			case <-r.requestChan:
				err := r.handler()
				if err != nil {
					fmt.Printf("\n\nHandler returned error: %v\n\n", err)
				}
				Expect(err).NotTo(HaveOccurred())
			case <-ctx.Done():
				return
			}
		}
	}()
}
