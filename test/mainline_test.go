// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/operator-framework/operator-sdk/pkg/restmapper"
	"github.com/tigera/operator/pkg/apis"
	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
	"github.com/tigera/operator/pkg/controller"
	apps "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var _ = Describe("Mainline component function tests", func() {
	var c client.Client
	var mgr manager.Manager
	BeforeEach(func() {
		// Create a Kubernetes client.
		cfg, err := config.GetConfig()
		Expect(err).NotTo(HaveOccurred())

		// Create a manager to use in the tests.
		mgr, err = manager.New(cfg, manager.Options{
			Namespace:      "",
			MapperProvider: restmapper.NewDynamicRESTMapper,
		})
		Expect(err).NotTo(HaveOccurred())

		// Setup Scheme for all resources
		err = apis.AddToScheme(mgr.GetScheme())
		Expect(err).NotTo(HaveOccurred())

		// Setup all Controllers
		controller.AddToManager(mgr)
		Expect(err).NotTo(HaveOccurred())

		c = mgr.GetClient()
	})

	AfterEach(func() {
		// Delete any CRD that might have been created by the test.
		instance := &operatorv1alpha1.Core{
			TypeMeta:   metav1.TypeMeta{Kind: "Core", APIVersion: "operator.tigera.io/v1alpha1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err := c.Get(context.Background(), client.ObjectKey{Name: "default"}, instance)
		Expect(err).NotTo(HaveOccurred())
		err = c.Delete(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Should install resources for a CRD with kube-proxy disabled", func() {
		By("Creating a CRD with Spec.KubeProxy.Required=false")
		instance := &operatorv1alpha1.Core{
			TypeMeta:   metav1.TypeMeta{Kind: "Core", APIVersion: "operator.tigera.io/v1alpha1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())

		By("Running the operator")
		stopChan := RunOperator(mgr)
		defer close(stopChan)

		By("Verifying the resources were created")
		ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "kube-system"}}
		ExpectResourceCreated(c, ds)
		kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "kube-system"}}
		ExpectResourceCreated(c, kc)

		By("Verifying the resources are Ready")
		Eventually(func() error {
			err = GetResource(c, ds)
			if err != nil {
				return err
			}
			if ds.Status.NumberAvailable == 0 {
				return fmt.Errorf("No node pods running")
			}
			if ds.Status.NumberAvailable == ds.Status.CurrentNumberScheduled {
				return nil
			}
			return fmt.Errorf("Only %d available replicas", ds.Status.NumberAvailable)
		}, 60*time.Second).Should(BeNil())

		Eventually(func() error {
			err = GetResource(c, kc)
			if err != nil {
				return err
			}
			if kc.Status.AvailableReplicas == 1 {
				return nil
			}
			return fmt.Errorf("kube-controllers not yet ready")
		}, 60*time.Second).Should(BeNil())
	})

	It("Should install resources for a CRD with kube-proxy enabled", func() {
		By("Creating a CRD with Spec.KubeProxy.Required=true")
		instance := &operatorv1alpha1.Core{
			TypeMeta:   metav1.TypeMeta{Kind: "Core", APIVersion: "operator.tigera.io/v1alpha1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1alpha1.CoreSpec{
				KubeProxy: operatorv1alpha1.KubeProxySpec{
					Required:  true,
					APIServer: "https://localhost:6443",
				},
			},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())

		By("Running the operator")
		stopChan := RunOperator(mgr)
		defer close(stopChan)

		By("Verifying the resources were created")
		ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "kube-system"}}
		ExpectResourceCreated(c, ds)
		kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "kube-system"}}
		ExpectResourceCreated(c, kc)
		proxy := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "kube-proxy", Namespace: "kube-system"}}
		ExpectResourceCreated(c, proxy)

		// TODO: We can't verify that the kube-proxy becomes ready and functional in this suite jsut yet, since
		// the k3s cluster we use to test this already has kube-proxy installed. Once we update the test cluster to
		// remove kube-proxy, we can verify that our installation of the proxy is functioning properly. Until then,
		// we can only verify that we successfully create the daemonset.

	})
})
