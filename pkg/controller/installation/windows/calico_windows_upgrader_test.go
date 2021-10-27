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
	"github.com/tigera/operator/pkg/controller/utils/node"

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

		syncPeriodOption = calicoWindowsUpgraderSyncPeriod(2 * time.Second)

		nlw := test.NodeListWatch{cs}
		nodeIndexInformer = node.CreateNodeSharedIndexInformer(nlw)

		ctx, cancel = context.WithCancel(context.TODO())
		go nodeIndexInformer.Run(ctx.Done())
		for !nodeIndexInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}

		c = NewCalicoWindowsUpgrader(cs, client, nodeIndexInformer, mockStatus, syncPeriodOption)
		one := intstr.FromInt(1)
		cr = &operator.InstallationSpec{
			Variant: operator.Calico,
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

	It("should do nothing if the product is Enterprise", func() {
		// We start off Enterprise install
		cr.Variant = operator.TigeraSecureEnterprise

		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateWindowsNode(cs, "node2", cr.Variant, "v3.0.0")
		n3 := test.CreateWindowsNode(cs, "node3", cr.Variant, "v2.0.0")

		// Create the upgrader and start it.
		c.Start(ctx)
		c.UpdateConfig(cr)

		// Nodes should not have changed.
		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1, n2, n3)
		}, 5*time.Second, 100*time.Millisecond).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should ignore linux nodes", func() {
		c.Start(ctx)

		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateNode(cs, "node2", map[string]string{"kubernetes.io/os": "linux"},
			map[string]string{common.CalicoVersionAnnotation: "v2.0.0", common.CalicoVariantAnnotation: string(operator.TigeraSecureEnterprise)})

		c.UpdateConfig(cr)

		Consistently(func() error {
			return test.AssertNodesUnchanged(cs, n1, n2)
		}, 10*time.Second, 100*time.Millisecond).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should upgrade outdated nodes", func() {
		// Only node n2 should be upgraded.
		mockStatus.On("AddWindowsNodeUpgrade", "node2", operator.Calico, operator.Calico, "v3.21.999", components.CalicoRelease)

		n1 := test.CreateNode(cs, "node1", map[string]string{"kubernetes.io/os": "linux"}, nil)
		n2 := test.CreateWindowsNode(cs, "node2", operator.Calico, "v3.21.999")
		n3 := test.CreateWindowsNode(cs, "node3", operator.Calico, components.CalicoRelease)

		c.Start(ctx)
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

		// At this point, we should only have a call to AddWindowsNodeUpgrade.
		mockStatus.AssertExpectations(GinkgoT())

		// Set the latest Calico Windows variant and version like the node service would.
		mockStatus.On("RemoveWindowsNodeUpgrade", "node2")
		setNodeVariantAndVersion(cs, nodeIndexInformer, n2, operator.Calico, components.CalicoRelease)

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
		n1 := test.CreateWindowsNode(cs, "node1", operator.TigeraSecureEnterprise, "v3.11.0")

		mockStatus.On("AddWindowsNodeUpgrade", "node1", operator.TigeraSecureEnterprise, operator.Calico, "v3.11.0", components.CalicoRelease)

		c.Start(ctx)
		c.UpdateConfig(cr)

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
		setNodeVariantAndVersion(cs, nodeIndexInformer, n1, operator.Calico, components.CalicoRelease)

		Eventually(func() error {
			return assertNodesFinishedUpgrade(cs, n1)
		}, 5*time.Second).Should(BeNil())

		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should use maxUnavailable correctly", func() {
		// Create installation with rolling update strategy with 20%
		// maxUnavailable.
		mu := intstr.FromString("20%")
		cr.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &mu

		// Create 5 nodes, all ready to be upgraded.
		_ = test.CreateWindowsNode(cs, "node1", operator.Calico, "v3.21.999")
		_ = test.CreateWindowsNode(cs, "node2", operator.Calico, "v3.21.999")
		_ = test.CreateWindowsNode(cs, "node3", operator.Calico, "v3.21.999")
		_ = test.CreateWindowsNode(cs, "node4", operator.Calico, "v3.21.999")
		_ = test.CreateWindowsNode(cs, "node5", operator.Calico, "v3.21.999")

		// We won't know which nodes will end up being added for upgrade.
		mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, operator.Calico, operator.Calico, "v3.21.999", components.CalicoRelease)

		c.Start(ctx)
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
		It("should count already upgrading nodes against maxUnavailable, for Calico to Calico upgrades", func() {
			_ = test.CreateWindowsNode(cs, "node1", operator.Calico, "v3.21.999")
			_ = test.CreateWindowsNode(cs, "node2", operator.Calico, "v3.21.999")
			_ = test.CreateWindowsNode(cs, "node3", operator.Calico, "v3.21.999")
			mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, operator.Calico, operator.Calico, "v3.21.999", components.CalicoRelease)

			c.Start(ctx)
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

		It("should count already upgrading nodes against maxUnavailable, for Enterprise to Calico upgrades", func() {
			_ = test.CreateWindowsNode(cs, "node1", operator.TigeraSecureEnterprise, "v3.11.0")
			_ = test.CreateWindowsNode(cs, "node2", operator.TigeraSecureEnterprise, "v3.11.0")
			_ = test.CreateWindowsNode(cs, "node3", operator.TigeraSecureEnterprise, "v3.11.0")

			mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, operator.TigeraSecureEnterprise, operator.Calico, "v3.11.0", components.CalicoRelease)

			c.Start(ctx)
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

			mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, operator.TigeraSecureEnterprise, operator.TigeraSecureEnterprise, "old", components.EnterpriseRelease)

			cr.Variant = operator.TigeraSecureEnterprise
			c.Start(ctx)
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

			mockStatus.On("AddWindowsNodeUpgrade", mock.Anything, operator.Calico, operator.TigeraSecureEnterprise, "v3.21.999", components.EnterpriseRelease)

			cr.Variant = operator.TigeraSecureEnterprise
			c.Start(ctx)
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

func setNodeVariantAndVersion(c kubernetes.Interface, indexInformer cache.SharedIndexInformer, node *corev1.Node, variant operator.ProductVariant, version string) {
	// Get the existing node.
	n, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
	Expect(err).To(BeNil())

	// Add the variant annotation to the node.
	n.Annotations[common.CalicoVariantAnnotation] = string(variant)
	_, err = c.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
	Expect(err).To(BeNil())

	// Add the version annotation to the node.
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
