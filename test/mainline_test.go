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
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"k8s.io/apimachinery/pkg/util/intstr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/operator-framework/operator-sdk/pkg/restmapper"
	"github.com/tigera/operator/pkg/apis"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var _ = Describe("Mainline component function tests", func() {
	var c client.Client
	var mgr manager.Manager
	BeforeEach(func() {
		c, mgr = setupManager()
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
			Spec:       corev1.NamespaceSpec{},
		}
		err := c.Create(context.Background(), ns)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

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

		// Clean up Calico data that might be left behind.
		Eventually(func() error {
			cs := kubernetes.NewForConfigOrDie(mgr.GetConfig())
			nodes, err := cs.CoreV1().Nodes().List(metav1.ListOptions{})
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
				err = c.Update(context.Background(), &n)
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
	})

	It("Should install resources for a CRD", func() {
		By("Creating a CRD")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())

		By("Running the operator")
		stopChan := RunOperator(mgr)
		defer close(stopChan)

		By("Verifying the resources were created")
		ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}
		ExpectResourceCreated(c, ds)
		kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "calico-system"}}
		ExpectResourceCreated(c, kc)

		By("Verifying the resources are ready")
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
		}, 240*time.Second).Should(BeNil())

		Eventually(func() error {
			err = GetResource(c, kc)
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
			ts, err := getTigeraStatus(c, "network")
			if err != nil {
				return err
			}
			return assertAvailable(ts)
		}, 60*time.Second).Should(BeNil())
	})

	It("Should install resources for a CRD with node overrides", func() {
		By("Creating a CRD with overrides")

		toleration := corev1.Toleration{
			Key:      "somekey",
			Operator: corev1.TolerationOpEqual,
			Value:    "somevalue",
			Effect:   corev1.TaintEffectNoSchedule,
		}
		volume := corev1.Volume{
			Name: "extravol",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		}
		volumeMount := corev1.VolumeMount{
			Name:      "extravol",
			MountPath: "/test/calico/kubecontrollers",
		}
		envVar := corev1.EnvVar{
			Name:  "env1",
			Value: "env1-value",
		}
		resourceRequirements := corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1m"),
				corev1.ResourceMemory: resource.MustParse("1Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1500m"),
				corev1.ResourceMemory: resource.MustParse("2500Mi"),
			},
		}

		maxUnavailable := intstr.FromInt(2)
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				Components: operator.ComponentsSpec{
					Node: operator.NodeSpec{
						MaxUnavailable:    &maxUnavailable,
						ExtraEnv:          []corev1.EnvVar{envVar},
						ExtraVolumes:      []corev1.Volume{volume},
						ExtraVolumeMounts: []corev1.VolumeMount{volumeMount},
						Tolerations:       []corev1.Toleration{toleration},
						Resources:         resourceRequirements,
					},
				},
			},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())

		By("Running the operator")
		stopChan := RunOperator(mgr)
		defer close(stopChan)

		By("Verifying the resources were created")
		ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}
		ExpectResourceCreated(c, ds)
		kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "calico-system"}}
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
		}, 240*time.Second).Should(BeNil())

		Eventually(func() error {
			err = GetResource(c, kc)
			if err != nil {
				return err
			}
			if kc.Status.AvailableReplicas == 1 {
				return nil
			}
			return fmt.Errorf("kube-controllers not yet ready: %#v", kc.Status)
		}, 240*time.Second).Should(BeNil())

		By("Verifying the tigera status CRD is updated")
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "network")
			if err != nil {
				return err
			}
			return assertAvailable(ts)
		}, 60*time.Second).Should(BeNil())

		By("Verifying the daemonset has the overrides")
		err = GetResource(c, ds)
		Expect(err).To(BeNil())
		Expect(ds.Spec.Template.Spec.Tolerations).To(ContainElement(toleration))
		Expect(ds.Spec.Template.Spec.Volumes).To(ContainElement(volume))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(envVar))
		Expect(ds.Spec.Template.Spec.Containers[0].Resources).To(Equal(resourceRequirements))
	})
})

var _ = Describe("Mainline component function tests with ignored resource", func() {
	var c client.Client
	var mgr manager.Manager
	BeforeEach(func() {
		c, mgr = setupManager()
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
		stopChan := RunOperator(mgr)
		defer close(stopChan)

		By("Verifying resources were not created")
		ds := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}
		ExpectResourceDestroyed(c, ds)
		kc := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-kube-controllers", Namespace: "calico-system"}}
		ExpectResourceDestroyed(c, kc)
		proxy := &apps.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "kube-proxy", Namespace: "kube-system"}}
		ExpectResourceDestroyed(c, proxy)
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

func setupManager() (client.Client, manager.Manager) {
	// Create a Kubernetes client.
	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred())
	// Create a manager to use in the tests.
	mgr, err := manager.New(cfg, manager.Options{
		Namespace:      "",
		MapperProvider: restmapper.NewDynamicRESTMapper,
	})
	Expect(err).NotTo(HaveOccurred())
	// Setup Scheme for all resources
	err = apis.AddToScheme(mgr.GetScheme())
	Expect(err).NotTo(HaveOccurred())
	// Setup all Controllers
	runTSEEControllers := true
	err = controller.AddToManager(mgr, operator.ProviderNone, runTSEEControllers)
	Expect(err).NotTo(HaveOccurred())
	return mgr.GetClient(), mgr
}
