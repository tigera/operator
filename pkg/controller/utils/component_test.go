// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package utils_test

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/common"

	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	ocsv1 "github.com/openshift/api/security/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

const (
	fakeComponentAnnotationKey   = "tigera.io/annotation-should-be"
	fakeComponentAnnotationValue = "present"
)

var log = logf.Log.WithName("test_utils_logger")

var _ = Describe("Component handler tests", func() {
	var (
		c        client.Client
		instance *operatorv1.Manager
		ctx      context.Context
		scheme   *runtime.Scheme
		sm       status.StatusManager
		handler  utils.ComponentHandler
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		Expect(v1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1beta.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()
		sm = status.New(c, "fake-component", &common.VersionInfo{Major: 1, Minor: 19})

		// We need to provide something to handler even though it seems to be unused..
		instance = &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		handler = utils.NewComponentHandler(log, c, scheme, instance)
	})

	It("merges annotations and reconciles only operator added annotations", func() {
		fc := &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&v1.Namespace{
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
		ns := &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
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
		ns = &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&v1.Namespace{
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
		ns = &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("changing a desired annotation")
		annotations = map[string]string{
			ocsv1.UIDRangeAnnotation:   "1-65535",
			"cattle-not-pets":          "indeed",
			fakeComponentAnnotationKey: "not-present",
		}
		ns.Annotations = annotations
		c.Update(ctx, ns)

		By("checking that the namespace is updated with new modified annotation")
		expectedAnnotations = map[string]string{
			"cattle-not-pets":          "indeed",
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: "not-present",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		// Re-initialize the fake component. Object metadata gets modified as part of CreateOrUpdate, leading
		// to resource update conflicts.
		fc = &fakeComponent{
			supportedOSType: rmeta.OSTypeLinux,
			objs: []client.Object{&v1.Namespace{
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
		ns = &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))
	})

	DescribeTable("ensuring os node selectors", func(component render.Component, key client.ObjectKey, obj client.Object, expectedNodeSelectors map[string]string) {
		Expect(handler.CreateOrUpdateOrDelete(ctx, component, sm)).ShouldNot(HaveOccurred())
		Expect(c.Get(ctx, key, obj)).ShouldNot(HaveOccurred())

		var nodeSelectors map[string]string
		switch obj.(type) {
		case *v1.PodTemplate:
			nodeSelectors = obj.(*v1.PodTemplate).Template.Spec.NodeSelector
		case *apps.Deployment:
			nodeSelectors = obj.(*apps.Deployment).Spec.Template.Spec.NodeSelector
		case *apps.DaemonSet:
			nodeSelectors = obj.(*apps.DaemonSet).Spec.Template.Spec.NodeSelector
		case *apps.StatefulSet:
			nodeSelectors = obj.(*apps.StatefulSet).Spec.Template.Spec.NodeSelector
		case *batchv1beta.CronJob:
			nodeSelectors = obj.(*batchv1beta.CronJob).Spec.JobTemplate.Spec.Template.Spec.NodeSelector
		case *batchv1.Job:
			nodeSelectors = obj.(*batchv1.Job).Spec.Template.Spec.NodeSelector
		case *kbv1.Kibana:
			nodeSelectors = obj.(*kbv1.Kibana).Spec.PodTemplate.Spec.NodeSelector
		case *esv1.Elasticsearch:
			// elasticsearch resource describes multiple nodeSets which each have a nodeSelector.
			nodeSets := obj.(*esv1.Elasticsearch).Spec.NodeSets
			for _, ns := range nodeSets {
				Expect(ns.PodTemplate.Spec.NodeSelector).Should(Equal(expectedNodeSelectors))
			}
			return
		case *monitoringv1.Alertmanager:
			nodeSelectors = obj.(*monitoringv1.Alertmanager).Spec.NodeSelector
		case *monitoringv1.Prometheus:
			nodeSelectors = obj.(*monitoringv1.Prometheus).Spec.NodeSelector
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
					objs: []client.Object{&v1.PodTemplate{
						ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
						Template: v1.PodTemplateSpec{
							Spec: v1.PodSpec{
								NodeSelector: map[string]string{},
							},
						},
					}},
				}, client.ObjectKey{Name: "test-podtemplate"}, &v1.PodTemplate{},
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
					objs: []client.Object{&v1.PodTemplate{
						ObjectMeta: metav1.ObjectMeta{Name: "test-podtemplate"},
						Template: v1.PodTemplateSpec{
							Spec: v1.PodSpec{
								NodeSelector: map[string]string{},
							},
						},
					}},
				}, client.ObjectKey{Name: "test-podtemplate"}, &v1.PodTemplate{},
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
					objs: []client.Object{&batchv1beta.CronJob{
						ObjectMeta: metav1.ObjectMeta{Name: "test-cronjob"},
						Spec: batchv1beta.CronJobSpec{
							JobTemplate: batchv1beta.JobTemplateSpec{
								Spec: batchv1.JobSpec{
									Template: v1.PodTemplateSpec{
										Spec: v1.PodSpec{
											NodeSelector: map[string]string{},
										},
									},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-cronjob"}, &batchv1beta.CronJob{},
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
					objs: []client.Object{&batchv1beta.CronJob{
						ObjectMeta: metav1.ObjectMeta{Name: "test-cronjob"},
						Spec: batchv1beta.CronJobSpec{
							JobTemplate: batchv1beta.JobTemplateSpec{
								Spec: batchv1.JobSpec{
									Template: v1.PodTemplateSpec{
										Spec: v1.PodSpec{
											NodeSelector: map[string]string{},
										},
									},
								},
							},
						}},
					},
				}, client.ObjectKey{Name: "test-cronjob"}, &batchv1beta.CronJob{},
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							PodTemplate: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
									PodTemplate: v1.PodTemplateSpec{
										Spec: v1.PodSpec{
											NodeSelector: map[string]string{},
										},
									},
								},
								{
									PodTemplate: v1.PodTemplateSpec{
										Spec: v1.PodSpec{
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							Template: v1.PodTemplateSpec{
								Spec: v1.PodSpec{
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
							NodeSelector: map[string]string{},
						},
					}},
				}, client.ObjectKey{Name: "test-alertmanager"}, &monitoringv1.Alertmanager{},
				map[string]string{
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
							NodeSelector: map[string]string{},
						},
					}},
				}, client.ObjectKey{Name: "test-prometheus"}, &monitoringv1.Prometheus{},
				map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
	)
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
