// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	ocsv1 "github.com/openshift/api/security/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	restMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	fakeComponentAnnotationKey   = "tigera.io/annotation-should-be"
	fakeComponentAnnotationValue = "present"
	fakeComponentLabelKey        = "tigera.io/label-should-be"
	fakeComponentLabelValue      = "labelvalue"
)

var _ = Describe("Component handler tests", func() {

	var (
		c        client.Client
		instance *operatorv1.Manager
		ctx      context.Context
		scheme   *runtime.Scheme
		sm       status.StatusManager
		handler  ComponentHandler
	)

	BeforeEach(func() {
		log := logf.Log.WithName("test_utils_logger")

		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx = context.Background()
		sm = status.New(c, "fake-component", &common.VersionInfo{Major: 1, Minor: 19})

		// We need to provide something to handler even though it seems to be unused..
		instance = &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		handler = NewComponentHandler(log, c, scheme, instance)
	})

	It("adds Owner references when Custom Resource is provided", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ds",
					Namespace: "default",
				},
				Spec: apps.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								fakeComponentAnnotationKey: fakeComponentAnnotationValue,
							},
						},
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		dsKey := client.ObjectKey{
			Name:      "test-ds",
			Namespace: "default",
		}
		ds := &apps.DaemonSet{}
		_ = c.Get(ctx, dsKey, ds)
		Expect(ds.OwnerReferences).To(HaveLen(1))
		t := true
		expectOR := metav1.OwnerReference{
			APIVersion:         "operator.tigera.io/v1",
			Kind:               "Manager",
			Name:               "tigera-secure",
			Controller:         &t,
			BlockOwnerDeletion: &t,
		}
		Expect(ds.OwnerReferences[0]).To(Equal(expectOR))
	})

	It("merges daemonset template annotations and reconciles only operator added annotations", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ds",
					Namespace: "default",
				},
				Spec: apps.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								fakeComponentAnnotationKey: fakeComponentAnnotationValue,
							},
						},
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("checking that the daemonset is created and desired annotations are present")
		expectedAnnotations := map[string]string{
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		dsKey := client.ObjectKey{
			Name:      "test-ds",
			Namespace: "default",
		}
		ds := &apps.DaemonSet{}
		_ = c.Get(ctx, dsKey, ds)
		Expect(ds.Spec.Template.GetAnnotations()).To(Equal(expectedAnnotations))

		By("add a new annotation, simulating a rolling restart request")
		annotations := map[string]string{
			fakeComponentAnnotationKey:          fakeComponentAnnotationValue,
			"kubectl.kubernetes.io/restartedAt": "some-time",
		}
		ds.Spec.Template.Annotations = annotations
		Expect(c.Update(ctx, ds)).NotTo(HaveOccurred())

		By("checking that the object is updated with the annotation")
		ds = &apps.DaemonSet{}
		err = c.Get(ctx, dsKey, ds)
		Expect(err).To(BeNil())
		Expect(ds.Spec.Template.GetAnnotations()).To(Equal(annotations))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&apps.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ds",
					Namespace: "default",
				},
				Spec: apps.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								fakeComponentAnnotationKey: fakeComponentAnnotationValue,
							},
						},
					},
				},
			}},
		}

		By("initiating a merge")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the daemonset and checking that both current and desired annotations are still present")
		expectedAnnotations = map[string]string{
			fakeComponentAnnotationKey:          fakeComponentAnnotationValue,
			"kubectl.kubernetes.io/restartedAt": "some-time",
		}
		ds = &apps.DaemonSet{}
		err = c.Get(ctx, dsKey, ds)
		Expect(err).To(BeNil())
		Expect(ds.Spec.Template.GetAnnotations()).To(Equal(expectedAnnotations))
	})

	It("merges annotations and reconciles only operator added annotations", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Annotations: map[string]string{
						fakeComponentAnnotationKey: fakeComponentAnnotationValue,
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("checking that the namespace is created and desired annotations is present")
		expectedAnnotations := map[string]string{
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		nsKey := client.ObjectKey{
			Name: "test-namespace",
		}
		ns := &corev1.Namespace{}
		_ = c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("ovewriting the namespace with SCC annotations")
		annotations := map[string]string{
			ocsv1.UIDRangeAnnotation: "1-65535",
		}
		ns.Annotations = annotations
		Expect(c.Update(ctx, ns)).NotTo(HaveOccurred())

		By("checking that the namespace is updated with SCC annotation")
		expectedAnnotations = map[string]string{
			ocsv1.UIDRangeAnnotation: "1-65535",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Annotations: map[string]string{
						fakeComponentAnnotationKey: fakeComponentAnnotationValue,
					},
				},
			}},
		}

		By("initiating a merge with Openshift SCC annotations")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that both current and desired annotations are still present")
		expectedAnnotations = map[string]string{
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("changing a desired annotation")
		annotations = map[string]string{
			ocsv1.UIDRangeAnnotation:   "1-65535",
			"cattle-not-pets":          "indeed",
			fakeComponentAnnotationKey: "not-present",
		}
		ns.Annotations = annotations
		err = c.Update(ctx, ns)
		Expect(err).To(BeNil())

		By("checking that the namespace is updated with new modified annotation")
		expectedAnnotations = map[string]string{
			"cattle-not-pets":          "indeed",
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: "not-present",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Annotations: map[string]string{
						fakeComponentAnnotationKey: fakeComponentAnnotationValue,
					},
				},
			}},
		}

		By("initiating a merge with namespace containing modified desired annotation")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that desired annotation is reconciled, everything else is left as-is")
		expectedAnnotations = map[string]string{
			"cattle-not-pets":          "indeed",
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))
	})

	It("merges UISettings leaving owners unchanged", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&v3.UISettings{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test.test-settings",
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "projectcalico.org/v3",
						Kind:       "UISettingsGroup",
						Name:       "owner",
						UID:        "abcde",
					}},
				},
				Spec: v3.UISettingsSpec{
					Group:       "test",
					Description: "just a test",
					Layer: &v3.UIGraphLayer{
						Nodes: []v3.UIGraphNode{},
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("checking that the UISettings is created and ownerref is not modified")
		uiKey := client.ObjectKey{
			Name: "test.test-settings",
		}
		ui := &v3.UISettings{}
		err = c.Get(ctx, uiKey, ui)
		Expect(err).To(BeNil())
		Expect(ui.OwnerReferences).To(HaveLen(1))
		Expect(ui.OwnerReferences[0].Name).To(Equal("owner"))

		By("overwriting the description and updating the owner.")
		ui.Spec.Description = "another test"
		ui.OwnerReferences[0].Name = "differentowner"
		fc.objs = []client.Object{ui}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("checking that the uisettings is updated with description, but ownerref is not modified")
		ui = &v3.UISettings{}
		err = c.Get(ctx, uiKey, ui)
		Expect(err).To(BeNil())
		Expect(ui.OwnerReferences).To(HaveLen(1))
		Expect(ui.OwnerReferences[0].Name).To(Equal("owner"))
		Expect(ui.Spec.Description).To(Equal("another test"))
	})

	It("merges labels and reconciles only operator added labels", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						fakeComponentLabelKey: fakeComponentLabelValue,
					},
				},
			}},
		}

		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("checking that the namespace is created and desired label is present")
		expectedLabels := map[string]string{
			fakeComponentLabelKey: fakeComponentLabelValue,
		}
		nsKey := client.ObjectKey{
			Name: "test-namespace",
		}
		ns := &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))

		By("ovewriting the namespace with extra label")
		labels := map[string]string{
			"extra": "extra-value",
		}
		ns.ObjectMeta.Labels = labels
		Expect(c.Update(ctx, ns)).NotTo(HaveOccurred())

		By("checking that the namespace is updated with extra label")
		expectedLabels = map[string]string{
			"extra": "extra-value",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						fakeComponentLabelKey: fakeComponentLabelValue,
					},
				},
			}},
		}

		By("initiating a merge with extra label")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that both current and desired labels are still present")
		expectedLabels = map[string]string{
			"extra":               "extra-value",
			fakeComponentLabelKey: fakeComponentLabelValue,
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))

		By("changing a desired label")
		labels = map[string]string{
			"extra":               "extra-value",
			"cattle-not-pets":     "indeed",
			fakeComponentLabelKey: "not-present",
		}
		ns.ObjectMeta.Labels = labels
		err = c.Update(ctx, ns)
		Expect(err).To(BeNil())

		By("checking that the namespace is updated with new modified label")
		expectedLabels = map[string]string{
			"cattle-not-pets":     "indeed",
			"extra":               "extra-value",
			fakeComponentLabelKey: "not-present",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						fakeComponentLabelKey: fakeComponentLabelValue,
					},
				},
			}},
		}

		By("initiating a merge with namespace containing modified desired label")
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that desired label is reconciled, everything else is left as-is")
		expectedLabels = map[string]string{
			"cattle-not-pets":     "indeed",
			"extra":               "extra-value",
			fakeComponentLabelKey: fakeComponentLabelValue,
		}
		ns = &corev1.Namespace{}
		err = c.Get(ctx, nsKey, ns)
		Expect(err).To(BeNil())
		Expect(ns.GetLabels()).To(Equal(expectedLabels))
	})

	DescribeTable("ensuring ImagePullPolicy is set", func(obj client.Object) {
		modifyPodSpec(obj, setImagePullPolicy)

		switch o := obj.(type) {
		case *apps.Deployment:
			for _, c := range o.Spec.Template.Spec.Containers {
				Expect(c.ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
			}
		case *apps.DaemonSet:
			for _, c := range o.Spec.Template.Spec.Containers {
				Expect(c.ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
			}
		default:
			Expect(true).To(Equal(false), "Unexpected kind in test")
		}

	},
		TableEntry{
			Description: "set ImagePullPolicy on a DaemonSet",
			Parameters: []interface{}{
				&apps.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
					Spec: apps.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{},
								Containers: []corev1.Container{
									{Image: "foo"},
									{Image: "bar"},
								},
							},
						},
					},
				},
			},
		},
		TableEntry{
			Description: "set ImagePullPolicy on a Deployment",
			Parameters: []interface{}{
				&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{},
								Containers: []corev1.Container{
									{Image: "foo"},
									{Image: "bar"},
								},
							},
						},
					},
				},
			},
		},
	)

	DescribeTable("ensuring os node selectors", func(component render.Component, key client.ObjectKey, obj client.Object, expectedNodeSelectors map[string]string) {
		Expect(handler.CreateOrUpdateOrDelete(ctx, component, sm)).ShouldNot(HaveOccurred())
		Expect(c.Get(ctx, key, obj)).ShouldNot(HaveOccurred())

		var nodeSelectors map[string]string
		switch x := obj.(type) {
		case *corev1.PodTemplate:
			nodeSelectors = x.Template.Spec.NodeSelector
		case *apps.Deployment:
			nodeSelectors = x.Spec.Template.Spec.NodeSelector
		case *apps.DaemonSet:
			nodeSelectors = x.Spec.Template.Spec.NodeSelector
		case *apps.StatefulSet:
			nodeSelectors = x.Spec.Template.Spec.NodeSelector
		case *batchv1.CronJob:
			nodeSelectors = x.Spec.JobTemplate.Spec.Template.Spec.NodeSelector
		case *batchv1.Job:
			nodeSelectors = x.Spec.Template.Spec.NodeSelector
		case *kbv1.Kibana:
			nodeSelectors = x.Spec.PodTemplate.Spec.NodeSelector
		case *esv1.Elasticsearch:
			// elasticsearch resource describes multiple nodeSets which each have a nodeSelector.
			nodeSets := x.Spec.NodeSets
			for _, ns := range nodeSets {
				Expect(ns.PodTemplate.Spec.NodeSelector).Should(Equal(expectedNodeSelectors))
			}
			return
		case *monitoringv1.Alertmanager:
			nodeSelectors = x.Spec.NodeSelector
		case *monitoringv1.Prometheus:
			nodeSelectors = x.Spec.NodeSelector
		default:
			Expect(fmt.Errorf("unexpected type passed to test")).ToNot(HaveOccurred())
		}

		Expect(nodeSelectors).Should(Equal(expectedNodeSelectors))
	},
		TableEntry{
			Description: "linux - sets the required annotations for a podtemplate when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&corev1.PodTemplate{
						ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{},
							},
						},
					}},
				}, client.ObjectKey{Name: "test-podtemplate"}, &corev1.PodTemplate{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "windows - sets the required annotations for a podtemplate when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeWindows,
					objs: []client.Object{&corev1.PodTemplate{
						ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								NodeSelector: map[string]string{},
							},
						},
					}},
				}, client.ObjectKey{Name: "test-podtemplate"}, &corev1.PodTemplate{},
				map[string]string{
					"kubernetes.io/os": "windows",
				},
			},
		},
		TableEntry{
			Description: "linux - sets the required annotations for a deployment when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{Name: "test-deployment"},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-deployment"}, &apps.Deployment{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "windows - sets the required annotations for a deployment when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeWindows,
					objs: []client.Object{&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{Name: "test-deployment"},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-deployment"}, &apps.Deployment{},
				map[string]string{
					"kubernetes.io/os": "windows",
				},
			},
		},
		TableEntry{
			Description: "linux - sets the required annotations for a daemonset when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&apps.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test-daemonset"},
						Spec: apps.DaemonSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-daemonset"}, &apps.DaemonSet{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "windows - sets the required annotations for a daemonset when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeWindows,
					objs: []client.Object{&apps.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test-daemonset"},
						Spec: apps.DaemonSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-daemonset"}, &apps.DaemonSet{},
				map[string]string{
					"kubernetes.io/os": "windows",
				},
			},
		},
		TableEntry{
			Description: "linux - sets the required annotations for a statefulset when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&apps.StatefulSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test-statefulset"},
						Spec: apps.StatefulSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-statefulset"}, &apps.StatefulSet{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "windows - sets the required annotations for a statefulset when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeWindows,
					objs: []client.Object{&apps.StatefulSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test-statefulset"},
						Spec: apps.StatefulSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-statefulset"}, &apps.StatefulSet{},
				map[string]string{
					"kubernetes.io/os": "windows",
				},
			},
		},
		TableEntry{
			Description: "linux - sets the required annotations for a cronjob when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&batchv1.CronJob{
						ObjectMeta: metav1.ObjectMeta{Name: "test-cronjob"},
						Spec: batchv1.CronJobSpec{
							JobTemplate: batchv1.JobTemplateSpec{
								Spec: batchv1.JobSpec{
									Template: corev1.PodTemplateSpec{
										Spec: corev1.PodSpec{
											NodeSelector: map[string]string{},
										},
									},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-cronjob"}, &batchv1.CronJob{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "windows - sets the required annotations for a cronjob when they're not set",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeWindows,
					objs: []client.Object{&batchv1.CronJob{
						ObjectMeta: metav1.ObjectMeta{Name: "test-cronjob"},
						Spec: batchv1.CronJobSpec{
							JobTemplate: batchv1.JobTemplateSpec{
								Spec: batchv1.JobSpec{
									Template: corev1.PodTemplateSpec{
										Spec: corev1.PodSpec{
											NodeSelector: map[string]string{},
										},
									},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-cronjob"}, &batchv1.CronJob{},
				map[string]string{
					"kubernetes.io/os": "windows",
				},
			},
		},
		TableEntry{
			Description: "linux - sets the required annotations for a job",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&batchv1.Job{
						ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
						Spec: batchv1.JobSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					}},
				},
				client.ObjectKey{Name: "test-job"}, &batchv1.Job{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "windows - sets the required annotations for a job",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeWindows,
					objs: []client.Object{&batchv1.Job{
						ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
						Spec: batchv1.JobSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					}},
				},
				client.ObjectKey{Name: "test-job"}, &batchv1.Job{},
				map[string]string{
					"kubernetes.io/os": "windows",
				},
			},
		},
		TableEntry{
			Description: "sets the required annotations for kibana",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&kbv1.Kibana{
						ObjectMeta: metav1.ObjectMeta{Name: "test-kibana"},
						Spec: kbv1.KibanaSpec{
							PodTemplate: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{},
								},
							},
						},
					}},
				},
				client.ObjectKey{Name: "test-kibana"}, &kbv1.Kibana{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "sets the required annotations for an elasticsearch nodeset",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&esv1.Elasticsearch{
						ObjectMeta: metav1.ObjectMeta{Name: "test-elasticsearch"},
						Spec: esv1.ElasticsearchSpec{
							NodeSets: []esv1.NodeSet{
								{
									PodTemplate: corev1.PodTemplateSpec{
										Spec: corev1.PodSpec{
											NodeSelector: map[string]string{},
										},
									},
								},
								{
									PodTemplate: corev1.PodTemplateSpec{
										Spec: corev1.PodSpec{
											NodeSelector: nil,
										},
									},
								},
							},
						},
					}},
				},
				client.ObjectKey{Name: "test-elasticsearch"}, &esv1.Elasticsearch{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "linux - leaves other annotations alone and sets the required ones",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{Name: "test-deployment"},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{
										"kubernetes.io/foo": "bar",
									},
								},
							},
						},
					}},
				}, client.ObjectKey{Name: "test-deployment"}, &apps.Deployment{},
				map[string]string{
					"kubernetes.io/foo": "bar",
					"kubernetes.io/os":  "linux",
				},
			},
		},
		TableEntry{
			Description: "windows - leaves other annotations alone and sets the required ones",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeWindows,
					objs: []client.Object{&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{Name: "test-deployment"},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									NodeSelector: map[string]string{
										"kubernetes.io/foo": "bar",
									},
								},
							},
						},
					}},
				}, client.ObjectKey{Name: "test-deployment"}, &apps.Deployment{},
				map[string]string{
					"kubernetes.io/foo": "bar",
					"kubernetes.io/os":  "windows",
				},
			},
		},
		TableEntry{
			Description: "linux - sets the required annotations for Prometheus Alertmanager nodes",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&monitoringv1.Alertmanager{
						ObjectMeta: metav1.ObjectMeta{Name: "test-alertmanager"},
						Spec: monitoringv1.AlertmanagerSpec{
							NodeSelector: map[string]string{
								"kubernetes.io/a": "b",
							},
						},
					}},
				}, client.ObjectKey{Name: "test-alertmanager"}, &monitoringv1.Alertmanager{},
				map[string]string{
					"kubernetes.io/a":  "b",
					"kubernetes.io/os": "linux",
				},
			},
		},
		TableEntry{
			Description: "linux - sets the required annotations for Prometheus nodes",
			Parameters: []interface{}{
				&fakeComponent{
					supportedOSType: rmeta.OSTypeLinux,
					objs: []client.Object{&monitoringv1.Prometheus{
						ObjectMeta: metav1.ObjectMeta{Name: "test-prometheus"},
						Spec: monitoringv1.PrometheusSpec{
							CommonPrometheusFields: monitoringv1.CommonPrometheusFields{
								NodeSelector: map[string]string{
									"kubernetes.io/a": "b",
								},
							},
						},
					}},
				}, client.ObjectKey{Name: "test-prometheus"}, &monitoringv1.Prometheus{},
				map[string]string{
					"kubernetes.io/a":  "b",
					"kubernetes.io/os": "linux",
				},
			},
		},
	)

	It("recreates a service if its ClusterIP is removed", func() {
		// Simulate creation of a service by earlier version of operator that includes a ClusterIP.
		svcWithIP := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-service",
				Labels: map[string]string{
					"old": "should-be-preserved",
				},
			},
			Spec: corev1.ServiceSpec{
				ClusterIP: "10.96.0.1",
			},
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				svcWithIP,
			},
		}
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-service"}, svcWithIP)).NotTo(HaveOccurred())
		Expect(svcWithIP.Spec.ClusterIP).To(Equal("10.96.0.1"))
		Expect(svcWithIP.Labels).To(Equal(map[string]string{
			"old": "should-be-preserved",
		}))

		// Now pretend we're the new operator version, wanting to remove the cluster IP.
		svcNoIP := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-service",
				Labels: map[string]string{
					"new": "should-be-added",
				},
			},
			Spec: corev1.ServiceSpec{
				ClusterIP: "None",
			},
		}
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				svcNoIP,
			},
		}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-service"}, svcNoIP)).NotTo(HaveOccurred())
		Expect(svcNoIP.Spec.ClusterIP).To(Equal("None"))
		Expect(svcNoIP.Labels).To(Equal(map[string]string{
			"old": "should-be-preserved",
			"new": "should-be-added",
		}))

		// The fake client resets the resource version to 1 on create.
		Expect(svcNoIP.ObjectMeta.ResourceVersion).To(Equal("1"),
			"Expected recreation of Service to reset resourceVersion to 1")

		// Finally, make a normal change, this should result in an update.
		svcNoIP.Labels = map[string]string{"newer": "should-be-added"}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-service"}, svcNoIP)).NotTo(HaveOccurred())
		Expect(svcNoIP.Labels).To(Equal(map[string]string{
			"old":   "should-be-preserved",
			"new":   "should-be-added",
			"newer": "should-be-added",
		}))
		Expect(svcNoIP.ObjectMeta.ResourceVersion).To(Equal("2"),
			"Expected update to rev ResourceVersion")
	})

	It("allows you to replace a secret if the types change", func() {
		// Please note that a fake client does not behave exactly as it would on K8s:
		// - A secret without a type in a real cluster automatically becomes type Opaque
		// - An update where the secret type changes would be rejected in a real cluster, yet the fake client accepts it.
		// This test serves to purpose of at least verifying that an update of a secret type works without error.
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-secret"},
			Type:       corev1.SecretTypeOpaque,
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				secret,
			},
		}
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-secret"}, secret)).NotTo(HaveOccurred())
		Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))
		secret.Type = corev1.SecretTypeTLS
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-secret"}, secret)).NotTo(HaveOccurred())
		Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
	})

	It("recreates a RoleBinding if roleRef changes", func() {
		// In a real cluster we get an error if we attempt to update an existing RoleBinding's RoleRef field because
		// it is immutable. We can't properly check that update isn't called here because the fake client we use
		// doesn't contain validation logic like that, so it will happily perform an update that would be rejected in
		// a real cluster. As an indirect way to check that we're running our code that performs a delete/create instead
		// of an update, we check the resource version of the RoleBinding after the create. If it's 1, we know it was
		// deleted and recreated
		rbOldRoleRef := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-rolebinding",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "old-roleref",
			},
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				rbOldRoleRef,
			},
		}
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-rolebinding"}, rbOldRoleRef)).NotTo(HaveOccurred())
		Expect(rbOldRoleRef.RoleRef.Name).To(Equal("old-roleref"))

		// Now pretend we're the new operator version, wanting to change the name of the roleRef.
		rbNewRoleRef := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-rolebinding",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "new-roleref",
			},
		}
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				rbNewRoleRef,
			},
		}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-rolebinding"}, rbNewRoleRef)).NotTo(HaveOccurred())
		Expect(rbNewRoleRef.RoleRef.Name).To(Equal("new-roleref"))

		// The fake client resets the resource version to 1 on create.
		Expect(rbNewRoleRef.ObjectMeta.ResourceVersion).To(Equal("1"),
			"Expected recreation of RoleBinding to reset resourceVersion to 1")

		// Finally, make a normal change, this should result in an update rather than a delete/create
		rbNewRoleRef.Labels = map[string]string{"new": "should-be-added"}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-rolebinding"}, rbNewRoleRef)).NotTo(HaveOccurred())
		Expect(rbNewRoleRef.ObjectMeta.ResourceVersion).To(Equal("2"),
			"Expected update of RoleBinding to rev resourceversion to 2")
	})

	It("recreates a ClusterRoleBinding if roleRef changes", func() {
		// In a real cluster we get an error if we attempt to update an existing ClusterRoleBinding's RoleRef field because
		// it is immutable. We can't properly check that update isn't called here because the fake client we use
		// doesn't contain validation logic like that, so it will happily perform an update that would be rejected in
		// a real cluster. As an indirect way to check that we're running our code that performs a delete/create instead
		// of an update, we check the resource version of the ClusterRoleBinding after the create. If it's 1, we know it was
		// deleted and recreated
		crbOldRoleRef := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-clusterrolebinding",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "old-roleref",
			},
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				crbOldRoleRef,
			},
		}
		err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-clusterrolebinding"}, crbOldRoleRef)).NotTo(HaveOccurred())
		Expect(crbOldRoleRef.RoleRef.Name).To(Equal("old-roleref"))

		// Now pretend we're the new operator version, wanting to change the name of the roleRef.
		crbNewRoleRef := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-clusterrolebinding",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "new-roleref",
			},
		}
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{
				crbNewRoleRef,
			},
		}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-clusterrolebinding"}, crbNewRoleRef)).NotTo(HaveOccurred())
		Expect(crbNewRoleRef.RoleRef.Name).To(Equal("new-roleref"))

		// The fake client resets the resource version to 1 on create.
		Expect(crbNewRoleRef.ObjectMeta.ResourceVersion).To(Equal("1"),
			"Expected recreation of ClusterRoleBinding to reset resourceVersion to 1")

		// Finally, make a normal change, this should result in an update rather than a delete/create
		crbNewRoleRef.Labels = map[string]string{"new": "should-be-added"}
		err = handler.CreateOrUpdateOrDelete(ctx, fc, sm)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Get(ctx, client.ObjectKey{Name: "my-clusterrolebinding"}, crbNewRoleRef)).NotTo(HaveOccurred())
		Expect(crbNewRoleRef.ObjectMeta.ResourceVersion).To(Equal("2"),
			"Expected update of ClusterRoleBinding to rev resourceversion to 2")
	})

	Context("liveness and readiness probes", func() {
		It("updates liveness and readiness probe default values", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-deployment",
							Namespace: "test-namespace",
						},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:           "test-deployment-container",
											LivenessProbe:  &corev1.Probe{},
											ReadinessProbe: &corev1.Probe{},
										},
									},
								},
							},
						},
					},
					&apps.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-daemonset",
							Namespace: "test-namespace",
						},
						Spec: apps.DaemonSetSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:           "test-daemonset-container",
											LivenessProbe:  &corev1.Probe{},
											ReadinessProbe: &corev1.Probe{},
										},
									},
								},
							},
						},
					},
					&esv1.Elasticsearch{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-elasticsearch",
							Namespace: "test-namespace",
						},
						Spec: esv1.ElasticsearchSpec{
							NodeSets: []esv1.NodeSet{
								{
									PodTemplate: corev1.PodTemplateSpec{
										Spec: corev1.PodSpec{
											Containers: []corev1.Container{
												{
													Name:           "test-elasticsearch-container",
													LivenessProbe:  &corev1.Probe{},
													ReadinessProbe: &corev1.Probe{},
												},
											},
										},
									},
								},
							},
						},
					},
					&kbv1.Kibana{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-kibana",
							Namespace: "test-namespace",
						},
						Spec: kbv1.KibanaSpec{
							PodTemplate: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:           "test-kibana-container",
											LivenessProbe:  &corev1.Probe{},
											ReadinessProbe: &corev1.Probe{},
										},
									},
								},
							},
						},
					},
					&monitoringv1.Prometheus{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-prometheus",
							Namespace: "test-namespace",
						},
						Spec: monitoringv1.PrometheusSpec{
							CommonPrometheusFields: monitoringv1.CommonPrometheusFields{
								Containers: []corev1.Container{
									{
										Name:           "test-prometheus-container",
										LivenessProbe:  &corev1.Probe{},
										ReadinessProbe: &corev1.Probe{},
									},
								},
							},
						},
					},
				},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).NotTo(HaveOccurred())

			By("checking that liveness and readiness probe default values are set")
			var containers []corev1.Container

			var deploy apps.Deployment
			err = c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, &deploy)
			Expect(err).NotTo(HaveOccurred())
			containers = append(containers, deploy.Spec.Template.Spec.Containers...)

			var ds apps.DaemonSet
			err = c.Get(ctx, client.ObjectKey{Name: "test-daemonset", Namespace: "test-namespace"}, &ds)
			Expect(err).NotTo(HaveOccurred())
			containers = append(containers, ds.Spec.Template.Spec.Containers...)

			var es esv1.Elasticsearch
			err = c.Get(ctx, client.ObjectKey{Name: "test-elasticsearch", Namespace: "test-namespace"}, &es)
			Expect(err).NotTo(HaveOccurred())
			for _, nodeset := range es.Spec.NodeSets {
				containers = append(containers, nodeset.PodTemplate.Spec.Containers...)
			}

			var kb kbv1.Kibana
			err = c.Get(ctx, client.ObjectKey{Name: "test-kibana", Namespace: "test-namespace"}, &kb)
			Expect(err).NotTo(HaveOccurred())
			containers = append(containers, kb.Spec.PodTemplate.Spec.Containers...)

			var prom monitoringv1.Prometheus
			err = c.Get(ctx, client.ObjectKey{Name: "test-prometheus", Namespace: "test-namespace"}, &prom)
			Expect(err).NotTo(HaveOccurred())
			containers = append(containers, prom.Spec.Containers...)

			Expect(containers).To(HaveLen(5))
			for _, c := range containers {
				Expect(c.LivenessProbe.FailureThreshold).To(BeEquivalentTo(3))
				Expect(c.LivenessProbe.PeriodSeconds).To(BeEquivalentTo(60))
				Expect(c.LivenessProbe.SuccessThreshold).To(BeEquivalentTo(1))
				Expect(c.LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(5))

				Expect(c.ReadinessProbe.FailureThreshold).To(BeEquivalentTo(3))
				Expect(c.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(30))
				Expect(c.ReadinessProbe.SuccessThreshold).To(BeEquivalentTo(1))
				Expect(c.ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(5))
			}
		})

		It("should not modify liveness and readiness probes when values are set", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-deployment",
							Namespace: "test-namespace",
						},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name: "test-deployment-container",
											LivenessProbe: &corev1.Probe{
												FailureThreshold: 2,
												PeriodSeconds:    3,
												SuccessThreshold: 5,
												TimeoutSeconds:   7,
											},
											ReadinessProbe: &corev1.Probe{
												FailureThreshold: 11,
												PeriodSeconds:    13,
												SuccessThreshold: 17,
												TimeoutSeconds:   19,
											},
										},
									},
								},
							},
						},
					},
				},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).NotTo(HaveOccurred())

			By("checking that liveness and readiness probe values are not changed")
			var deploy apps.Deployment
			err = c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, &deploy)
			Expect(err).NotTo(HaveOccurred())
			containers := deploy.Spec.Template.Spec.Containers

			Expect(containers).To(HaveLen(1))
			Expect(containers[0].LivenessProbe.FailureThreshold).To(BeEquivalentTo(2))
			Expect(containers[0].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(3))
			Expect(containers[0].LivenessProbe.SuccessThreshold).To(BeEquivalentTo(5))
			Expect(containers[0].LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(7))
			Expect(containers[0].ReadinessProbe.FailureThreshold).To(BeEquivalentTo(11))
			Expect(containers[0].ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(13))
			Expect(containers[0].ReadinessProbe.SuccessThreshold).To(BeEquivalentTo(17))
			Expect(containers[0].ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(19))
		})

		It("should not modify liveness and readiness probes when nil", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{
					&apps.Deployment{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-deployment",
							Namespace: "test-namespace",
						},
						Spec: apps.DeploymentSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name: "test-deployment-container",
										},
									},
								},
							},
						},
					},
				},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).NotTo(HaveOccurred())

			By("checking that liveness and readiness probes are still nil")
			var deploy apps.Deployment
			err = c.Get(ctx, client.ObjectKey{Name: "test-deployment", Namespace: "test-namespace"}, &deploy)
			Expect(err).NotTo(HaveOccurred())
			containers := deploy.Spec.Template.Spec.Containers

			Expect(containers).To(HaveLen(1))
			Expect(containers[0].LivenessProbe).To(BeNil())
			Expect(containers[0].ReadinessProbe).To(BeNil())
		})
	})

	Context("common labels and labelselector", func() {
		It("updates daemonsets", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-daemonset",
						Namespace: "test-namespace",
					},
					Spec: apps.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).To(BeNil())

			By("checking that the daemonset is created and labels are added")
			expectedLabels := map[string]string{
				"k8s-app":                "test-daemonset",
				"app.kubernetes.io/name": "test-daemonset",
			}
			expectedSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "test-daemonset"},
			}
			key := client.ObjectKey{
				Name:      "test-daemonset",
				Namespace: "test-namespace",
			}
			ds := &apps.DaemonSet{}
			Expect(c.Get(ctx, key, ds)).NotTo(HaveOccurred())
			Expect(ds.Spec.Template.GetLabels()).To(Equal(expectedLabels))
			Expect(*ds.Spec.Selector).To(Equal(expectedSelector))
		})
		It("does not change LabelSelector on daemonsets", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-daemonset",
						Namespace: "test-namespace",
					},
					Spec: apps.DaemonSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"preset-key": "preset-value",
							},
						},
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).To(BeNil())

			expectedLabels := map[string]string{
				"k8s-app":                "test-daemonset",
				"app.kubernetes.io/name": "test-daemonset",
			}
			expectedSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"preset-key": "preset-value"},
			}
			key := client.ObjectKey{
				Name:      "test-daemonset",
				Namespace: "test-namespace",
			}
			ds := &apps.DaemonSet{}
			Expect(c.Get(ctx, key, ds)).NotTo(HaveOccurred())
			Expect(ds.Spec.Template.GetLabels()).To(Equal(expectedLabels))
			Expect(*ds.Spec.Selector).To(Equal(expectedSelector))
		})
		It("updates deployments", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-deployment",
						Namespace: "test-namespace",
					},
					Spec: apps.DeploymentSpec{
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).To(BeNil())

			expectedLabels := map[string]string{
				"k8s-app":                "test-deployment",
				"app.kubernetes.io/name": "test-deployment",
			}
			expectedSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "test-deployment"},
			}
			key := client.ObjectKey{
				Name:      "test-deployment",
				Namespace: "test-namespace",
			}
			d := &apps.Deployment{}
			Expect(c.Get(ctx, key, d)).NotTo(HaveOccurred())
			Expect(d.GetLabels()).To(Equal(expectedLabels))
			Expect(d.Spec.Template.GetLabels()).To(Equal(expectedLabels))
			Expect(*d.Spec.Selector).To(Equal(expectedSelector))
		})
		It("does not change LabelSelector on deployments", func() {
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs: []client.Object{&apps.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-deployment",
						Namespace: "test-namespace",
					},
					Spec: apps.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"preset-key": "preset-value",
							},
						},
						Template: corev1.PodTemplateSpec{},
					},
				}},
			}

			err := handler.CreateOrUpdateOrDelete(ctx, fc, sm)
			Expect(err).To(BeNil())

			expectedLabels := map[string]string{
				"k8s-app":                "test-deployment",
				"app.kubernetes.io/name": "test-deployment",
			}
			expectedSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{"preset-key": "preset-value"},
			}
			key := client.ObjectKey{
				Name:      "test-deployment",
				Namespace: "test-namespace",
			}
			d := &apps.Deployment{}
			Expect(c.Get(ctx, key, d)).To(BeNil())
			Expect(d.GetLabels()).To(Equal(expectedLabels))
			Expect(d.Spec.Template.GetLabels()).To(Equal(expectedLabels))
			Expect(*d.Spec.Selector).To(Equal(expectedSelector))
		})
	})
	Context("services account updates should not result in removal of data", func() {
		It("preserves secrets and image pull secrets that were present before object updates", func() {
			sa := &corev1.ServiceAccount{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "a",
					Namespace: "a",
				},
				Secrets:                      []corev1.ObjectReference{{Name: "a"}},
				ImagePullSecrets:             []corev1.LocalObjectReference{{Name: "a"}},
				AutomountServiceAccountToken: nil,
			}
			Expect(c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "a"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, sa)).NotTo(HaveOccurred())

			sa.Secrets = nil
			sa.ImagePullSecrets = nil
			fc := &fakeComponent{
				supportedOSType: rmeta.OSTypeLinux,
				objs:            []client.Object{sa},
			}

			Expect(handler.CreateOrUpdateOrDelete(ctx, fc, sm)).NotTo(HaveOccurred())
			Expect(c.Get(ctx, client.ObjectKey{Name: "a", Namespace: "a"}, sa)).NotTo(HaveOccurred())
			Expect(sa.Secrets).To(HaveLen(1))
			Expect(sa.ImagePullSecrets).To(HaveLen(1))
		})
	})
})

var _ = Describe("Mocked client Component handler tests", func() {

	var (
		c       client.Client
		mc      mockClient
		ctx     context.Context
		handler ComponentHandler
	)

	BeforeEach(func() {
		log := logf.Log.WithName("test_utils_logger")

		mc = mockClient{Info: make([]mockReturn, 0)}
		c = &mc
		ctx = context.Background()

		handler = NewComponentHandler(log, c, runtime.NewScheme(), nil)
	})

	Context("Resource conflicts", func() {
		ds := apps.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ds",
				Namespace: "default",
			},
			Spec: apps.DaemonSetSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							fakeComponentAnnotationKey: fakeComponentAnnotationValue,
						},
					},
				},
			},
		}
		setToDS := func(object client.Object) {
			dsToSet := object.(*apps.DaemonSet)
			ds.DeepCopyInto(dsToSet)
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{&ds},
		}

		It("if Updating a resource conflicts try the update again", func() {
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToDS,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method: "Update",
				Return: errors.NewConflict(schema.GroupResource{}, "error name", fmt.Errorf("test error message")),
			})
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToDS,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Update",
				Return:       nil,
				InputMutator: setToDS,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())

			Expect(mc.Index).To(Equal(4))
		})

		It("if Updating a resource conflicts try the update again", func() {
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToDS,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method: "Update",
				Return: errors.NewConflict(schema.GroupResource{}, "error name", fmt.Errorf("test error message")),
			})
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToDS,
			})
			mc.Info = append(mc.Info, mockReturn{
				Method: "Update",
				Return: errors.NewConflict(schema.GroupResource{}, "error name", fmt.Errorf("test error message")),
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).NotTo(BeNil())

			Expect(mc.Index).To(Equal(4))
		})
	})

	Context("Network Policy updates", func() {
		baseNP := &v3.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "NetworkPolicy",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-tigera.test-policy",
				Namespace: "tigera-namespace",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "allow-tigera",
				Selector: "k8s-app == 'tigera-component'",
				Egress: []v3.Rule{
					{
						Action: "Allow",
					},
				},
				Types: []v3.PolicyType{"Egress"},
			},
		}
		setToBaseNP := func(object client.Object) {
			npToSet := object.(*v3.NetworkPolicy)
			baseNP.DeepCopyInto(npToSet)
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{baseNP},
		}

		It("NetworkPolicy updates are omitted if there is no change", func() {
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToBaseNP,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())
			Expect(mc.Index).To(Equal(1))
		})

		It("NetworkPolicy updates are applied if there is a change", func() {
			modifiedNP := baseNP.DeepCopy()
			modifiedNP.Spec.Selector = "k8s-app == 'invalid-component'"
			setToModifiedNP := func(object client.Object) {
				npToSet := object.(*v3.NetworkPolicy)
				modifiedNP.DeepCopyInto(npToSet)
			}

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToModifiedNP,
			})

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Update",
				Return:       nil,
				InputMutator: setToBaseNP,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())
			Expect(mc.Index).To(Equal(2))
		})
	})

	Context("Tier updates", func() {
		order := 9000.0
		baseTier := &v3.Tier{
			TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{Name: "test-tier"},
			Spec:       v3.TierSpec{Order: &order},
		}
		setToBaseTier := func(object client.Object) {
			tierToSet := object.(*v3.Tier)
			baseTier.DeepCopyInto(tierToSet)
		}
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs:            []client.Object{baseTier},
		}

		It("Tier updates are omitted if there is no change", func() {
			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToBaseTier,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())
			Expect(mc.Index).To(Equal(1))
		})

		It("Tier updates are applied if there is a change", func() {
			over9000 := 9001.0
			modifiedTier := baseTier.DeepCopy()
			modifiedTier.Spec.Order = &over9000
			setToModifiedTier := func(object client.Object) {
				tierToSet := object.(*v3.Tier)
				modifiedTier.DeepCopyInto(tierToSet)
			}

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Get",
				Return:       nil,
				InputMutator: setToModifiedTier,
			})

			mc.Info = append(mc.Info, mockReturn{
				Method:       "Update",
				Return:       nil,
				InputMutator: setToBaseTier,
			})

			err := handler.CreateOrUpdateOrDelete(ctx, fc, nil)
			Expect(err).To(BeNil())
			Expect(mc.Index).To(Equal(2))
		})
	})
})

// A fake component that only returns ready and always creates the "test-namespace" Namespace.
type fakeComponent struct {
	objs            []client.Object
	supportedOSType rmeta.OSType
}

func (c *fakeComponent) Ready() bool {
	return true
}

func (c *fakeComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (c *fakeComponent) Objects() ([]client.Object, []client.Object) {
	return c.objs, nil
}

func (c *fakeComponent) SupportedOSType() rmeta.OSType {
	return c.supportedOSType
}

type mockReturn struct {
	Method       string
	Return       interface{}
	InputMutator func(object client.Object)
}

type mockClient struct {
	Info  []mockReturn
	Index int
}

func (mc *mockClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	defer func() { mc.Index++ }()
	funcName := "Get"
	if len(mc.Info) <= mc.Index {
		panic(fmt.Sprintf("mockClient Info doesn't have enough entries for %s %v", funcName, key))
	}
	if mc.Info[mc.Index].Method != funcName {
		panic(fmt.Sprintf("mockClient current (%d) call is for %v, not %s", mc.Index, mc.Info[mc.Index].Method, funcName))
	}
	if mc.Info[mc.Index].Return == nil {
		if mc.Info[mc.Index].InputMutator != nil {
			mc.Info[mc.Index].InputMutator(obj)
		}
		return nil
	}

	v, ok := mc.Info[mc.Index].Return.(error)
	if !ok {
		panic(fmt.Sprintf("mockClient Info didn't have right type for entry %d for %s %v", mc.Index, funcName, key))
	}

	return v
}

func (mc *mockClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	panic("List not implemented in mockClient")
}
func (mc *mockClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	panic("Create not implemented in mockClient")
}
func (mc *mockClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	panic("Delete not implemented in mockClient")
}

func (mc *mockClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	defer func() { mc.Index++ }()
	funcName := "Update"
	if len(mc.Info) <= mc.Index {
		panic(fmt.Sprintf("mockClient Info doesn't have enough entries for %s %v", funcName, client.ObjectKeyFromObject(obj)))
	}
	if mc.Info[mc.Index].Method != funcName {
		panic(fmt.Sprintf("mockClient current (%d) call is for %v, not %s", mc.Index, mc.Info[mc.Index].Method, funcName))
	}
	if mc.Info[mc.Index].Return == nil {
		if mc.Info[mc.Index].InputMutator != nil {
			mc.Info[mc.Index].InputMutator(obj)
		}
		return nil
	}

	v, ok := mc.Info[mc.Index].Return.(error)
	if !ok {
		panic(fmt.Sprintf("mockClient Info didn't have right type for entry %d for %s %v", mc.Index, funcName, client.ObjectKeyFromObject(obj)))
	}

	return v
}
func (mc *mockClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	panic("Patch not implemented in mockClient")
}
func (mc *mockClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	panic("DeleteAll not implemented in mockClient")
}

func (mc *mockClient) Status() client.StatusWriter {
	panic("Status not implemented in mockClient")
}
func (mc *mockClient) Scheme() *runtime.Scheme {
	panic("Scheme not implemented in mockClient")
}
func (mc *mockClient) RESTMapper() restMeta.RESTMapper {
	panic("RESTMapper not implemented in mockClient")
}

func (mc *mockClient) SubResource(subResource string) client.SubResourceClient {
	panic("SubResource not implemented in mockClient")
}
