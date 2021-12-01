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
	"github.com/tigera/operator/pkg/controller/status"

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
)

var _ = Describe("Calico windows upgrader", func() {
	var c CalicoWindowsUpgrader
	var cs *kfake.Clientset
	var client kclient.Client
	var cr *operator.InstallationSpec

	var mockStatus *status.MockStatus
	var nodeIndexInformer cache.SharedIndexInformer

	var syncPeriodOption calicoWindowsUpgraderOption
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

		syncPeriodOption = CalicoWindowsUpgraderSyncPeriod(2 * time.Second)

		nlw := test.NewNodeListWatch(cs)
		nodeIndexInformer = cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

		ctx, cancel = context.WithCancel(context.TODO())
		go nodeIndexInformer.Run(ctx.Done())
		for !nodeIndexInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}

		c = NewCalicoWindowsUpgrader(cs, client, nodeIndexInformer, mockStatus, syncPeriodOption)
		one := intstr.FromInt(1)
		cr = &operator.InstallationSpec{
			KubernetesProvider: operator.ProviderAKS,
			NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &one,
				},
			},
		}
	})

	AfterEach(func() {
		cancel()
	})

	It("should do nothing if provider is not AKS", func() {
		c.Start(ctx)

		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateWindowsNode(cs, "node2", operator.Calico, "v3.21.999")
		n3 := test.CreateWindowsNode(cs, "node3", operator.Calico, components.ComponentWindows.Version)

		cr.KubernetesProvider = operator.ProviderEKS
		cr.Variant = operator.TigeraSecureEnterprise
		c.UpdateConfig(cr)

		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1, n2, n3)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		// No SetWindowsUpgradeStatus calls are expected since
		// calicoWindowsUpgrader should have exited its loop because
		// provider != AKS.
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should ignore linux nodes", func() {
		c.Start(ctx)

		// Setup some linux nodes, one with "outdated" Enterprise version.
		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "linux"},
			map[string]string{common.CalicoVersionAnnotation: "v2.0.0", common.CalicoVariantAnnotation: string(operator.TigeraSecureEnterprise)})

		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{}, []string{}, nil)
		cr.Variant = operator.TigeraSecureEnterprise
		c.UpdateConfig(cr)

		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1, n2)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{}, []string{}, nil)
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should do nothing for Calico to Calico", func() {
		c.Start(ctx)

		n1 := test.CreateWindowsNode(cs, "node2", operator.Calico, "v3.21.999")

		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{}, []string{}, nil)
		cr.Variant = operator.Calico
		c.UpdateConfig(cr)

		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{}, []string{}, nil)
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should upgrade outdated nodes", func() {
		// Setup 3 nodes, only the Calico node (n2) should be upgraded.
		// - n1 is a Linux node so it is ignored.
		// - n2 is a Windows node running Calico so it is upgraded.
		// - n3 is a Windows node running Enterprise using latest version so it is up-to-date.
		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateWindowsNode(cs, "node2", operator.Calico, "v3.21.999")
		n3 := test.CreateWindowsNode(cs, "node3", operator.TigeraSecureEnterprise, components.ComponentTigeraWindows.Version)
		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{"node2"}, []string{"node3"}, nil)

		c.Start(ctx)
		cr.Variant = operator.TigeraSecureEnterprise
		c.UpdateConfig(cr)

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

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{"node2"}, []string{"node3"}, nil)
		mockStatus.AssertExpectations(GinkgoT())

		// Last arg will contain both node 2 and node 3, in some order.
		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{}, mock.Anything, nil)

		// Set the latest Calico Windows variant and version like the node service would.
		setNodeVariantAndVersion(cs, nodeIndexInformer, n2, operator.TigeraSecureEnterprise, components.ComponentTigeraWindows.Version)

		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n2)
		}, 5*time.Second).Should(BeNil())

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{}, mock.Anything, nil)
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should upgrade outdated nodes if the installation variant differs", func() {
		// Create a Windows node running Calico with a version that is the same
		// as the latest Enteprise version.
		n1 := test.CreateWindowsNode(cs, "node1", operator.Calico, components.ComponentTigeraWindows.Version)
		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{"node1"}, []string{}, nil)

		c.Start(ctx)
		cr.Variant = operator.TigeraSecureEnterprise
		c.UpdateConfig(cr)

		// Ensure the node has the new label and taint.
		Eventually(func() error {
			return test.AssertNodesHadUpgradeTriggered(cs, n1)
		}, 5*time.Second).Should(BeNil())

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{"node1"}, []string{}, nil)
		mockStatus.AssertExpectations(GinkgoT())

		// Set the latest Calico Windows version like the node service would. This will trigger a reconcile.
		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{}, []string{"node1"}, nil)

		setNodeVariantAndVersion(cs, nodeIndexInformer, n1, operator.TigeraSecureEnterprise, components.ComponentTigeraWindows.Version)

		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n1)
		}, 5*time.Second).Should(BeNil())

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{}, []string{"node1"}, nil)
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should patch nodes for upgrade even if the upgrade taint already exists", func() {
		// Create a node with the NoSchedule taint already added for some
		// reason.
		n1 := &corev1.Node{
			TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node1",
				Labels: map[string]string{"kubernetes.io/os": "windows"},
				Annotations: map[string]string{
					common.CalicoVersionAnnotation: string(operator.Calico),
					common.CalicoVariantAnnotation: "v3.20.999",
				},
			},
			Spec: corev1.NodeSpec{
				Taints: []corev1.Taint{
					*common.CalicoWindowsUpgradingTaint,
				},
			},
		}
		n1, err := cs.CoreV1().Nodes().Create(context.Background(), n1, metav1.CreateOptions{})
		Expect(err).To(BeNil())

		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{"node1"}, []string{}, nil)

		c.Start(ctx)
		cr.Variant = operator.TigeraSecureEnterprise
		c.UpdateConfig(cr)

		// Ensure the node has the new label and taint.
		Eventually(func() error {
			return test.AssertNodesHadUpgradeTriggered(cs, n1)
		}, 5*time.Second).Should(BeNil())

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{"node1"}, []string{}, nil)
		mockStatus.AssertExpectations(GinkgoT())

		// Set the latest Calico Windows version like the node service would. This will trigger a reconcile.
		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{}, []string{"node1"}, nil)
		setNodeVariantAndVersion(cs, nodeIndexInformer, n1, operator.TigeraSecureEnterprise, components.ComponentTigeraWindows.Version)

		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n1)
		}, 5*time.Second).Should(BeNil())

		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{}, []string{"node1"}, nil)
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should patch nodes to complete upgrade even if the upgrade taint is missing", func() {
		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{"node1"}, []string{}, nil)

		n1 := test.CreateWindowsNode(cs, "node1", operator.Calico, "v3.21.999")

		c.Start(ctx)
		cr.Variant = operator.TigeraSecureEnterprise
		c.UpdateConfig(cr)

		// Ensure that both nodes have the new label and taint.
		Eventually(func() error {
			return test.AssertNodesHadUpgradeTriggered(cs, n1)
		}, 5*time.Second).Should(BeNil())

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{"node1"}, []string{}, nil)
		mockStatus.AssertExpectations(GinkgoT())

		mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{}, []string{"node1"}, nil)

		n, err := cs.CoreV1().Nodes().Get(context.Background(), "node1", metav1.GetOptions{})
		Expect(err).To(BeNil())
		n.Spec.Taints = []corev1.Taint{}
		_, err = cs.CoreV1().Nodes().Update(ctx, n, metav1.UpdateOptions{})
		Expect(err).To(BeNil())

		// Set the latest Calico Windows variant and version like the node service would.
		setNodeVariantAndVersion(cs, nodeIndexInformer, n1, operator.TigeraSecureEnterprise, components.ComponentTigeraWindows.Version)

		// Ensure that when calicoWindowsUpgrader runs again, the node taint and
		// label are removed.
		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n1)
		}, 5*time.Second).Should(BeNil())

		// Wait until SetWindowsUpgradeStatus has been called.
		waitForSetWindowsUpgradeStatusCalled(mockStatus, []string{}, []string{}, []string{"node1"}, nil)
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should use maxUnavailable correctly", func() {
		// Create installation with rolling update strategy with 20%
		// maxUnavailable.
		mu := intstr.FromString("20%")
		cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu

		// Create 5 nodes, all ready to be upgraded from an old Enterprise
		// version to the latest.
		_ = test.CreateWindowsNode(cs, "node1", operator.TigeraSecureEnterprise, "v3.11-old")
		_ = test.CreateWindowsNode(cs, "node2", operator.TigeraSecureEnterprise, "v3.11-old")
		_ = test.CreateWindowsNode(cs, "node3", operator.TigeraSecureEnterprise, "v3.11-old")
		_ = test.CreateWindowsNode(cs, "node4", operator.TigeraSecureEnterprise, "v3.11-old")
		_ = test.CreateWindowsNode(cs, "node5", operator.TigeraSecureEnterprise, "v3.11-old")

		// We won't know which nodes will end up being added for upgrade.
		mockStatus.On("SetWindowsUpgradeStatus", mock.Anything, mock.Anything, mock.Anything, nil)

		c.Start(ctx)
		cr.Variant = operator.TigeraSecureEnterprise
		c.UpdateConfig(cr)

		count := func() int {
			return countNodesUpgrading(nodeIndexInformer)
		}
		Eventually(count, 10*time.Second).Should(Equal(1))
		Consistently(count, 10*time.Second).Should(Equal(1))

		// Now change to 60% which should result in 3 nodes that should be
		// upgradable.
		mu = intstr.FromString("60%")
		cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu

		// Update the config (normally this would be triggered by the core controller)
		c.UpdateConfig(cr)

		Eventually(count, 5*time.Second).Should(Equal(3))
		Consistently(count, 10*time.Second).Should(Equal(3))
	})

	Context("Test max upgrading nodes depending on upgrade type", func() {
		It("should do nothing for Calico to Calico upgrades", func() {
			_ = test.CreateWindowsNode(cs, "node1", operator.Calico, "v3.21.999")
			_ = test.CreateWindowsNode(cs, "node2", operator.Calico, "v3.21.999")
			_ = test.CreateWindowsNode(cs, "node3", operator.Calico, "v3.21.999")
			mockStatus.On("SetWindowsUpgradeStatus", mock.Anything, mock.Anything, mock.Anything, nil)

			c.Start(ctx)
			cr.Variant = operator.Calico
			c.UpdateConfig(cr)

			count := func() int {
				return countNodesUpgrading(nodeIndexInformer)
			}
			Eventually(count, 5*time.Second).Should(Equal(0))
			Consistently(count, 5*time.Second).Should(Equal(0))

			mu := intstr.FromInt(0)
			cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu
			c.UpdateConfig(cr)

			Eventually(count, 5*time.Second).Should(Equal(0))
			Consistently(count, 5*time.Second).Should(Equal(0))

			mu = intstr.FromInt(2)
			cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu
			c.UpdateConfig(cr)

			Eventually(count, 5*time.Second).Should(Equal(0))
			Consistently(count, 5*time.Second).Should(Equal(0))
		})

		It("should count already upgrading nodes against maxUnavailable, for Enterprise to Calico upgrades", func() {
			_ = test.CreateWindowsNode(cs, "node1", operator.TigeraSecureEnterprise, "v3.11.0")
			_ = test.CreateWindowsNode(cs, "node2", operator.TigeraSecureEnterprise, "v3.11.0")
			_ = test.CreateWindowsNode(cs, "node3", operator.TigeraSecureEnterprise, "v3.11.0")

			mockStatus.On("SetWindowsUpgradeStatus", mock.Anything, mock.Anything, mock.Anything, nil)

			c.Start(ctx)
			cr.Variant = operator.Calico
			c.UpdateConfig(cr)

			count := func() int {
				return countNodesUpgrading(nodeIndexInformer)
			}
			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu := intstr.FromInt(0)
			cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu
			c.UpdateConfig(cr)

			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu = intstr.FromInt(2)
			cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu
			c.UpdateConfig(cr)

			Eventually(count, 5*time.Second).Should(Equal(2))
			Consistently(count, 5*time.Second).Should(Equal(2))
		})

		It("should count already upgrading nodes against maxUnavailable, for Enterprise to Enterprise upgrades", func() {
			Skip("This test does not yet work since upgrades to Enterprise are not supported yet")

			_ = test.CreateWindowsNode(cs, "node1", operator.TigeraSecureEnterprise, "old")
			_ = test.CreateWindowsNode(cs, "node2", operator.TigeraSecureEnterprise, "old")
			_ = test.CreateWindowsNode(cs, "node3", operator.TigeraSecureEnterprise, "old")

			mockStatus.On("SetWindowsUpgradeStatus", mock.Anything, mock.Anything, mock.Anything, nil)

			c.Start(ctx)
			cr.Variant = operator.TigeraSecureEnterprise
			c.UpdateConfig(cr)

			count := func() int {
				return countNodesUpgrading(nodeIndexInformer)
			}
			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu := intstr.FromInt(0)
			cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu
			c.UpdateConfig(cr)

			Eventually(count, 5*time.Second).Should(Equal(1))
			Consistently(count, 5*time.Second).Should(Equal(1))

			mu = intstr.FromInt(2)
			cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu
			c.UpdateConfig(cr)

			Eventually(count, 5*time.Second).Should(Equal(2))
			Consistently(count, 5*time.Second).Should(Equal(2))
		})

		It("should upgrade nodes going from Calico to Enterprise right away, even if max available slots is 0", func() {
			Skip("This test does not yet work since upgrades to Enterprise are not supported yet")

			_ = test.CreateWindowsNode(cs, "node1", operator.Calico, "v3.21.999")
			_ = test.CreateWindowsNode(cs, "node2", operator.Calico, "v3.21.999")
			_ = test.CreateWindowsNode(cs, "node3", operator.Calico, "v3.21.999")

			mockStatus.On("SetWindowsUpgradeStatus", mock.Anything, mock.Anything, mock.Anything, nil)

			c.Start(ctx)
			cr.Variant = operator.TigeraSecureEnterprise
			c.UpdateConfig(cr)

			count := func() int {
				return countNodesUpgrading(nodeIndexInformer)
			}
			// All of the pending nodes should still be upgraded despite max unavailability
			// value.
			Eventually(count, 5*time.Second).Should(Equal(3))
			Consistently(count, 5*time.Second).Should(Equal(3))

		})
	})
})

func countNodesUpgrading(nodeIndexInformer cache.SharedIndexInformer) int {
	count := 0
	for _, obj := range nodeIndexInformer.GetIndexer().List() {
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

// Ensure that SetWindowsUpgradeStatus was eventually called with the given
// arguments for the given status.
func waitForSetWindowsUpgradeStatusCalled(mockStatus *status.MockStatus, arguments ...interface{}) {
	Eventually(func() bool {
		return mockStatus.WasCalled("SetWindowsUpgradeStatus", arguments...)
	}, 5*time.Second).Should(BeTrue())
}

func setNodeVariantAndVersion(c kubernetes.Interface, indexInformer cache.SharedIndexInformer, node *corev1.Node, variant operator.ProductVariant, version string) {
	// Get the existing node.
	n, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
	Expect(err).To(BeNil())

	// Add the variant and version annotations to the node.
	n.Annotations[common.CalicoVariantAnnotation] = string(variant)
	n.Annotations[common.CalicoVersionAnnotation] = version
	_, err = c.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
	Expect(err).To(BeNil())

	Eventually(func() error {
		obj, exists, err := indexInformer.GetIndexer().GetByKey(node.Name)
		if !exists {
			return fmt.Errorf("node doesn't exist, did a test get updated?")
		}
		if err != nil {
			return fmt.Errorf("got an error: %w", err)
		}

		node := obj.(*corev1.Node)
		if node.Annotations[common.CalicoVariantAnnotation] == string(variant) && node.Annotations[common.CalicoVersionAnnotation] == version {
			return nil
		}

		return fmt.Errorf("node does not have expected version yet: %v", version)
	}, 20*time.Second).Should(BeNil())
}
