// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/controllers"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
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
	var operatorDone chan struct{}
	BeforeEach(func() {
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable, false)

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
		Expect(errors.IsNotFound(err)).To(BeTrue(), fmt.Sprintf("Expected Installation not to exist, but got: %s", err))
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

	Describe("Installing CRD", func() {
		It("Should install resources for a CRD", func() {
			operatorDone = createInstallation(c, mgr, shutdownContext, nil)
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

			operatorDone = createInstallation(c, mgr, shutdownContext, nil)
			verifyCalicoHasDeployed(c)

			By("Deleting CR after its tigera status becomes available")
			err := c.Delete(context.Background(), instance)
			Expect(err).NotTo(HaveOccurred())
			ExpectResourceDestroyed(c, instance, 20*time.Second)

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
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable, false)
		verifyCRDsExist(c)
	})

	AfterEach(func() {
		removeInstallation(c, "not-default", context.Background())
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
		ExpectResourceDestroyed(c, ds, 10*time.Second)
		kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "calico-system"}}
		ExpectResourceDestroyed(c, kc, 10*time.Second)
	})
})

var _ = Describe("Mainline component function tests - multi-tenant", func() {
	It("should set up all controllers correctly in multi-tenant mode", func() {
		_, _, cancel, _ := setupManager(ManageCRDsDisable, true)
		cancel()
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

func newNonCachingClient(config *rest.Config, options client.Options) (client.Client, error) {
	options.Cache = nil
	return client.New(config, options)
}

func setupManager(manageCRDs bool, multiTenant bool) (client.Client, context.Context, context.CancelFunc, manager.Manager) {
	// Create a Kubernetes client.
	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred())

	// Create a manager to use in the tests.
	mgr, err := manager.New(cfg, manager.Options{
		MetricsBindAddress: "0",
		// Upgrade notes fro v0.14.0 (https://sdk.operatorframework.io/docs/upgrading-sdk-version/version-upgrade-guide/#v014x)
		// say to replace restmapper but the NewDynamicRestMapper did not satisfy the
		// MapperProvider interface
		MapperProvider: apiutil.NewDynamicRESTMapper,
		// Use a non-caching client because we've had issues with flakes in the past where the cache
		// was not updating and tests were failing as a result of looking at stale cluster state
		NewClient: newNonCachingClient,
		Client:    client.Options{},
	})
	Expect(err).NotTo(HaveOccurred())

	cs, err := kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())

	// Auto-detect whether the cluster supports PSP. Since we use a kind cluster
	// from before v1.25, we expect this to be true. Once we update our kind
	// version >= v1.25, we should instead expect this to return "false".
	usePSP, err := utils.SupportsPodSecurityPolicies(cs)
	Expect(err).NotTo(HaveOccurred())
	Expect(usePSP).To(BeTrue())

	// Setup Scheme for all resources
	err = apis.AddToScheme(mgr.GetScheme())
	Expect(err).NotTo(HaveOccurred())
	err = apiextensionsv1.AddToScheme(mgr.GetScheme())
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithCancel(context.TODO())

	// Setup all Controllers
	err = controllers.AddToManager(mgr, options.AddOptions{
		DetectedProvider:    operator.ProviderNone,
		EnterpriseCRDExists: true,
		ManageCRDs:          manageCRDs,
		ShutdownContext:     ctx,
		UsePSP:              usePSP,
		MultiTenant:         multiTenant,
	})
	Expect(err).NotTo(HaveOccurred())
	return mgr.GetClient(), ctx, cancel, mgr
}

func createAPIServer(c client.Client, mgr manager.Manager, ctx context.Context, spec *operator.APIServerSpec) {
	s := operator.APIServerSpec{}
	if spec != nil {
		s = *spec
	}
	By("Creating an APIServer CRD")
	instance := &operator.APIServer{
		TypeMeta:   metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       s,
	}
	err := c.Create(context.Background(), instance)
	Expect(err).NotTo(HaveOccurred())
}

func removeAPIServer(c client.Client, ctx context.Context) {
	instance := &operator.APIServer{
		TypeMeta:   metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	err := c.Get(ctx, client.ObjectKey{Name: "default"}, instance)
	if err != nil && kerror.IsNotFound(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred())

	By("Deleting the APIServer CRD")
	err = c.Delete(ctx, instance)
	Expect(err).NotTo(HaveOccurred())
}

func createInstallation(c client.Client, mgr manager.Manager, ctx context.Context, spec *operator.InstallationSpec) (doneChan chan struct{}) {
	s := operator.InstallationSpec{}
	if spec != nil {
		s = *spec
	}
	By("Creating an Installation CRD")
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

func removeInstallation(c client.Client, name string, ctx context.Context) {
	// Delete any CRD that might have been created by the test.
	instance := &operator.Installation{
		TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	err := c.Get(ctx, client.ObjectKey{Name: name}, instance)
	if err != nil && kerror.IsNotFound(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred())

	By("Deleting the Installation CRD")
	err = c.Delete(ctx, instance)
	Expect(err).NotTo(HaveOccurred())

	// Need to wait here for Installation resource to be fully deleted prior to cancelling the context
	// which will in turn terminate the operator. Race conditions can occur otherwise that will leave the
	// Installation resource intact while the operator is no longer running which will result in test failures
	// that try to create an Installation resource of their own
	By("Waiting for the Installation CR to be removed")
	Eventually(func() error {
		err := c.Get(ctx, client.ObjectKey{Name: name}, instance)
		if kerror.IsNotFound(err) {
			return nil
		} else if err != nil {
			return err
		}
		return fmt.Errorf("Installation still exists")
	}, 120*time.Second).ShouldNot(HaveOccurred())
}

func verifyAPIServerHasDeployed(c client.Client) {
	By("Verifying API server was created")
	apiserver := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-apiserver"}}
	ExpectResourceCreated(c, apiserver)

	By("Verifying the API server resources are ready")
	Eventually(func() error {
		err := GetResource(c, apiserver)
		if err != nil {
			return err
		}
		if apiserver.Status.AvailableReplicas >= 1 {
			return nil
		}
		return fmt.Errorf("apiserver not yet ready")
	}, 240*time.Second).Should(BeNil())

	By("Verifying the apiserver tigera status CRD is updated")
	Eventually(func() error {
		ts, err := getTigeraStatus(c, "apiserver")
		if err != nil {
			return err
		}
		return assertAvailable(ts)
	}, 120*time.Second).Should(BeNil())
}

func verifyCalicoHasDeployed(c client.Client) {
	By("Verifying calico-system resources were created")
	ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}
	ExpectResourceCreated(c, ds)
	kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "calico-system"}}
	ExpectResourceCreated(c, kc)

	By("Verifying calico-system resources are ready")
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

	By("Verifying the calico tigera status CRD is updated")
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
			crd := &apiextensionsv1.CustomResourceDefinition{
				TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition", APIVersion: "apiextensions.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: n},
			}
			err := GetResource(c, crd)
			// If getting any of the CRDs is an error then the CRDs do not exist
			if err != nil {
				return err
			}
		}
		return nil
	}, 10*time.Second).Should(BeNil())
}

func waitForProductTeardown(c client.Client) {
	Eventually(func() error {
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
		}
		err := GetResource(c, ns)
		if err == nil {
			return fmt.Errorf("Calico namespace still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		crb := &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-node"},
		}
		err = GetResource(c, crb)
		if err == nil {
			return fmt.Errorf("Node CRB still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		defaultInstallation := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err = GetResource(c, defaultInstallation)
		if err == nil {
			return fmt.Errorf("default Installation still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		return nil
	}, 240*time.Second).ShouldNot(HaveOccurred())
}

func cleanupIPPools(c client.Client) {
	By("Cleaning up IP pools")
	Eventually(func() error {
		ipPools := &crdv1.IPPoolList{}
		err := c.List(context.Background(), ipPools)
		if err != nil {
			return err
		}

		for _, p := range ipPools.Items {
			By(fmt.Sprintf("Deleting IP pool %s with CIDR %s (%s)", p.Name, p.Spec.CIDR, p.UID))
			err = c.Delete(context.Background(), &p)
			if err != nil {
				return err
			}
		}
		return nil
	}, 30*time.Second).ShouldNot(HaveOccurred())
}

func cleanupResources(c client.Client) {
	removeAPIServer(c, context.Background())
	removeInstallation(c, "default", context.Background())
	cleanupIPPools(c)
	waitForProductTeardown(c)
}
