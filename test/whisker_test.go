// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package test

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"sigs.k8s.io/controller-runtime/pkg/client"

	apps "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	operator "github.com/tigera/operator/api/v1"
)

var _ = Describe("Tests for Whisker installation", func() {
	var c client.Client
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	var operatorDone chan struct{}

	BeforeEach(func() {
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable, false, true)

		By("Cleaning up resources before the test")
		cleanupResources(c)

		By("Verifying CRDs are installed")
		verifyCRDsExist(c)

		By("Creating the tigera-operator namespace, if it doesn't exist")
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
			Spec:       corev1.NamespaceSpec{},
		}
		err := c.Create(context.Background(), ns)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		By("Checking no Installation is left over from previous tests")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err = c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance)
		Expect(kerror.IsNotFound(err)).To(BeTrue(), fmt.Sprintf("Expected Installation not to exist, but got: %s", err))
	})

	AfterEach(func() {
		defer func() {
			cancel()
			Eventually(func() error {
				select {
				case <-operatorDone:
					return nil
				default:
					return fmt.Errorf("operator did not shutdown")
				}
			}, 60*time.Second).ShouldNot(HaveOccurred())
		}()

		By("Cleaning up resources after the test")
		cleanupResources(c)

		// Clean up Calico data that might be left behind.
		Eventually(func() error {
			cs := kubernetes.NewForConfigOrDie(mgr.GetConfig())
			nodes, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				return err
			}
			if len(nodes.Items) == 0 {
				return fmt.Errorf("No nodes found")
			}
			for _, n := range nodes.Items {
				for k := range n.ObjectMeta.Annotations {
					if strings.Contains(k, "projectcalico") {
						delete(n.ObjectMeta.Annotations, k)
					}
				}
				_, err = cs.CoreV1().Nodes().Update(context.Background(), &n, metav1.UpdateOptions{})
				if err != nil {
					return err
				}
			}
			return nil
		}, 30*time.Second).Should(BeNil())

		mgr = nil
	})

	It("Should install whisker", func() {
		operatorDone = createInstallation(c, mgr, shutdownContext, nil)
		verifyCalicoHasDeployed(c)

		By("Creating a CRD resource not named default")
		instance := &operator.Whisker{
			TypeMeta:   metav1.TypeMeta{Kind: "Whisker", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			Expect(c.Delete(context.Background(), instance)).ShouldNot(HaveOccurred())
		}()

		By("Verifying resources were created")
		whisker := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "whisker", Namespace: "calico-system"}}
		ExpectResourceCreated(c, whisker)
	})
})
