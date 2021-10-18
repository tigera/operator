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
	"reflect"
	"strings"
	"time"

	kmeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	//"github.com/operator-framework/operator-sdk/pkg/restmapper"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/controllers"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/crds"
)

const (
	ManageCRDsEnable  = true
	ManageCRDsDisable = false
)

var _ = Describe("Mainline component function tests", func() {
	var c client.Client
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	BeforeEach(func() {
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable)
		verifyCRDsExist(c)
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
			Spec:       corev1.NamespaceSpec{},
		}
		err := c.Create(context.Background(), ns)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		//
		Eventually(func() error {
			u := &unstructured.Unstructured{}
			u.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   "operator.tigera.io",
				Version: "v1",
				Kind:    "Installation",
			})

			k := client.ObjectKey{Name: "default"}
			err := c.Get(context.Background(), k, u)
			return err
		}, 20*time.Second).ShouldNot(BeNil())
	})

	AfterEach(func() {
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
				for k, _ := range n.ObjectMeta.Annotations {
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

		// Validate the calico-system namespace is deleted using an unstructured type. This hits the API server
		// directly instead of using the client cache. This should help with flaky tests.
		Eventually(func() error {
			u := &unstructured.Unstructured{}
			u.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Namespace",
			})

			k := client.ObjectKey{Name: "calico-system"}
			err := c.Get(context.Background(), k, u)
			return err
		}, 240*time.Second).ShouldNot(BeNil())
		mgr = nil
	})

	Describe("Installing CRD", func() {
		AfterEach(func() {
			// Delete any CRD that might have been created by the test.
			instance := &operator.Installation{
				TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			}
			err := c.Get(context.Background(), client.ObjectKey{Name: "default"}, instance)
			Expect(err).NotTo(HaveOccurred())
			err = c.Delete(context.Background(), instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("Should install resources for a CRD", func() {
			done := installResourceCRD(c, mgr, shutdownContext, nil)
			defer func() {
				cancel()
				Eventually(func() error {
					select {
					case <-done:
						return nil
					default:
						return fmt.Errorf("operator did not shutdown")
					}
				}, 60*time.Second).Should(BeNil())
			}()
			verifyCalicoHasDeployed(c)

			instance := &operator.Installation{
				TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			}
			By("Checking that the installation status is set correctly")
			Eventually(func() error {
				err := GetResource(c, instance)
				if err != nil {
					return err
				}
				if instance.Status.Variant != operator.Calico {
					return fmt.Errorf("installation status not Calico yet")
				}
				return nil
			}, 60*time.Second).Should(BeNil())

			By("Checking that the installation status does not change")
			Consistently(func() error {
				err := GetResource(c, instance)
				if err != nil {
					return err
				}
				if reflect.DeepEqual(instance.Status, operator.InstallationStatus{}) {
					return fmt.Errorf("installation status is empty: %+v", instance)
				}
				if instance.Status.Variant != operator.Calico {
					return fmt.Errorf("installation status was %+v, expected: %v", instance.Status, operator.Calico)
				}
				return nil
			}, 30*time.Second, 500*time.Millisecond).Should(BeNil())

		})
	})

	Describe("Deleting CR", func() {
		It("Should delete TigeraStatus for deleted CR", func() {
			instance := &operator.Installation{
				TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			}

			done := installResourceCRD(c, mgr, shutdownContext, nil)
			defer func() {
				cancel()
				Eventually(func() error {
					select {
					case <-done:
						return nil
					default:
						return fmt.Errorf("operator did not shutdown")
					}
				}, 60*time.Second).Should(BeNil())
			}()
			verifyCalicoHasDeployed(c)

			By("Deleting CR after its tigera status becomes available")
			err := c.Delete(context.Background(), instance)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the tigera status is removed for deleted CR")
			Eventually(func() error {
				_, err := getTigeraStatus(c, "calico")
				return err
			}, 120*time.Second).ShouldNot(BeNil())
		})
	})
})

var _ = Describe("Mainline component function tests with ignored resource", func() {
	var c client.Client
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	BeforeEach(func() {
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable)
		verifyCRDsExist(c)
	})
	AfterEach(func() {
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
			Spec:       operator.InstallationSpec{},
		}
		err := c.Delete(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Should ignore a CRD resource not named 'default'", func() {
		By("Creating a CRD resource not named default")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
			Spec:       operator.InstallationSpec{},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())

		By("Running the operator")
		done := RunOperator(mgr, shutdownContext)
		defer func() {
			cancel()
			Eventually(func() error {
				select {
				case <-done:
					return nil
				default:
					return fmt.Errorf("operator did not shutdown")
				}
			}, 60*time.Second).Should(BeNil())
		}()

		By("Verifying resources were not created")
		ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}
		ExpectResourceDestroyed(c, ds)
		kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "calico-system"}}
		ExpectResourceDestroyed(c, kc)
	})
})

func getTigeraStatus(client client.Client, name string) (*operator.TigeraStatus, error) {
	ts := &operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: name}}
	err := client.Get(context.TODO(), types.NamespacedName{Name: name}, ts)
	return ts, err
}

func assertAvailable(ts *operator.TigeraStatus) error {
	var available, degraded, progressing bool
	for _, condition := range ts.Status.Conditions {
		if condition.Type == operator.ComponentAvailable {
			available = condition.Status == operator.ConditionTrue
		} else if condition.Type == operator.ComponentDegraded {
			degraded = condition.Status == operator.ConditionTrue
		} else if condition.Type == operator.ComponentProgressing {
			progressing = condition.Status == operator.ConditionTrue
		}
	}

	if progressing {
		return fmt.Errorf("TigeraStatus is still progressing")
	} else if degraded {
		return fmt.Errorf("TigeraStatus is degraded")
	} else if !available {
		return fmt.Errorf("TigeraStatus is not available")
	}
	return nil
}

func setupManager(manageCRDs bool) (client.Client, context.Context, context.CancelFunc, manager.Manager) {
	// Create a Kubernetes client.
	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred())
	// Create a manager to use in the tests.
	mgr, err := manager.New(cfg, manager.Options{
		Namespace: "",
		// Upgrade notes fro v0.14.0 (https://sdk.operatorframework.io/docs/upgrading-sdk-version/version-upgrade-guide/#v014x)
		// say to replace restmapper but the NewDynamicRestMapper did not satisfy the
		// MapperProvider interface
		MapperProvider: func(c *rest.Config) (kmeta.RESTMapper, error) { return apiutil.NewDynamicRESTMapper(c) },
	})
	Expect(err).NotTo(HaveOccurred())
	// Setup Scheme for all resources
	err = apis.AddToScheme(mgr.GetScheme())
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithCancel(context.TODO())
	// Setup all Controllers
	err = controllers.AddToManager(mgr, options.AddOptions{
		DetectedProvider:    operator.ProviderNone,
		EnterpriseCRDExists: true,
		AmazonCRDExists:     true,
		ManageCRDs:          manageCRDs,
		ShutdownContext:     ctx,
	})
	Expect(err).NotTo(HaveOccurred())
	return mgr.GetClient(), ctx, cancel, mgr
}

func installResourceCRD(c client.Client, mgr manager.Manager, ctx context.Context, spec *operator.InstallationSpec) (doneChan chan struct{}) {
	s := operator.InstallationSpec{}
	if spec != nil {
		s = *spec
	}
	By("Creating a CRD")
	instance := &operator.Installation{
		TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       s,
	}
	err := c.Create(context.Background(), instance)
	Expect(err).NotTo(HaveOccurred())

	By("Running the operator")
	return RunOperator(mgr, ctx)
}

func verifyCalicoHasDeployed(c client.Client) {
	By("Verifying the resources were created")
	ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}
	ExpectResourceCreated(c, ds)
	kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "calico-system"}}
	ExpectResourceCreated(c, kc)

	By("Verifying the resources are ready")
	Eventually(func() error {
		err := GetResource(c, ds)
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
	}, 240*time.Second).Should(BeNil())

	Eventually(func() error {
		err := GetResource(c, kc)
		if err != nil {
			return err
		}
		if kc.Status.AvailableReplicas == 1 {
			return nil
		}
		return fmt.Errorf("kube-controllers not yet ready")
	}, 240*time.Second).Should(BeNil())

	By("Verifying the tigera status CRD is updated")
	Eventually(func() error {
		ts, err := getTigeraStatus(c, "calico")
		if err != nil {
			return err
		}
		return assertAvailable(ts)
	}, 60*time.Second).Should(BeNil())
}

func verifyCRDsExist(c client.Client) {
	crdNames := []string{}
	for _, x := range crds.GetCRDs(operator.TigeraSecureEnterprise) {
		crdNames = append(crdNames, fmt.Sprintf("%s.%s", x.Spec.Names.Plural, x.Spec.Group))
	}

	// Eventually all the Enterprise CRDs should be available
	Eventually(func() error {
		for _, n := range crdNames {
			u := &unstructured.Unstructured{}
			u.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   "apiextensions.k8s.io",
				Version: "v1",
				Kind:    "CustomResourceDefinition",
			})

			k := client.ObjectKey{Name: n}
			err := c.Get(context.Background(), k, u)
			// If getting any of the CRDs is an error then the CRDs do not exist
			if err != nil {
				return err
			}
		}
		return nil
	}, 10*time.Second).Should(BeNil())
}
