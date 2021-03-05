// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logcollector

import (
	"context"
	"fmt"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/test"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("LogCollector controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileLogCollector
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileLogCollector{
			client:          c,
			scheme:          scheme,
			provider:        operatorv1.ProviderNone,
			status:          mockStatus,
			ready:           make(chan bool),
			wg:              sync.WaitGroup{},
			hasLicenseWatch: false,
		}

		// We start off with a 'standard' installation, with nothing special
		Expect(c.Create(
			ctx,
			&operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.InstallationSpec{
					Variant:  operatorv1.TigeraSecureEnterprise,
					Registry: "some.registry.org/",
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.TigeraSecureEnterprise,
					Computed: &operatorv1.InstallationSpec{
						Registry: "my-reg",
						// The test is provider agnostic.
						KubernetesProvider: operatorv1.ProviderNone,
					},
				},
			})).NotTo(HaveOccurred())

		// Create resources LogCollector depends on
		Expect(c.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      relasticsearch.PublicCertSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchLogCollectorUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchEksLogForwarderUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())

		// Apply the logcollector CR to the fake cluster.
		Expect(c.Create(ctx, &operatorv1.LogCollector{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())

		go func(r *ReconcileLogCollector) {
			r.ready <- true
		}(&r)
	})

	Context("image reconciliation", func() {
		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fluentd-node",
					Namespace: render.LogCollectorNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			node := ds.Spec.Template.Spec.Containers[0]
			Expect(node).ToNot(BeNil())
			Expect(node.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentFluentd.Image,
					components.ComponentFluentd.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/fluentd", Digest: "sha256:fluentdhash"},
						{Image: "tigera/fluentd-windows", Digest: "sha256:fluentdwindowshash"},
					},
				},
			})).ToNot(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "windows-node",
					Labels: map[string]string{
						"kubernetes.io/os": "windows",
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fluentd-node",
					Namespace: render.LogCollectorNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			node := ds.Spec.Template.Spec.Containers[0]
			Expect(node).ToNot(BeNil())
			Expect(node.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentFluentd.Image,
					"sha256:fluentdhash")))

			ds.Name = "fluentd-node-windows"
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			node = ds.Spec.Template.Spec.Containers[0]
			Expect(node).ToNot(BeNil())
			Expect(node.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentFluentdWindows.Image,
					"sha256:fluentdwindowshash")))
		})

		Context("Forward to S3", func() {

			var s3Vars = []corev1.EnvVar{
				{
					Name:  "AWS_KEY_ID",
					Value: "",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "log-collector-s3-credentials",
							},
							Key: "key-id",
						},
					},
				},
				{
					Name:  "AWS_SECRET_KEY",
					Value: "",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "log-collector-s3-credentials",
							},
							Key: "key-secret",
						},
					},
				},
				{Name: "S3_STORAGE", Value: "true"},
				{Name: "S3_BUCKET_NAME", Value: "s3Bucket"},
				{Name: "AWS_REGION", Value: "s3Region"},
				{Name: "S3_BUCKET_PATH", Value: "s3Path"},
				{Name: "S3_FLUSH_INTERVAL", Value: "5s"}}

			BeforeEach(func() {
				By("Specify s3 log storage")
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec: operatorv1.LogCollectorSpec{
						AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
							S3: &operatorv1.S3StoreSpec{
								BucketName: "s3Bucket",
								Region:     "s3Region",
								BucketPath: "s3Path",
							},
						},
					},
				})).NotTo(HaveOccurred())
				By("Setting the license to export logs")
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
				By("Creating the s3 secret")
				Expect(c.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "log-collector-s3-credentials",
						Namespace: "tigera-operator"},
					Data: map[string][]byte{
						"key-secret": []byte("secret"),
						"key-id":     []byte("id"),
					},
				})).NotTo(HaveOccurred())

			})

			It("should forward logs to s3", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				ds := appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fluentd-node",
						Namespace: render.LogCollectorNamespace,
					},
				}
				Expect(test.GetResource(c, &ds)).To(BeNil())
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				node := ds.Spec.Template.Spec.Containers[0]
				Expect(node).ToNot(BeNil())
				Expect(node.Env).To(ContainElements(s3Vars))
			})

			Context("Disable feature via license", func() {
				BeforeEach(func() {
					By("Deleting the previous license")
					Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
					By("Creating a new license that does not contain export logs as a feature")
					Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				})

				It("should not forward logs to s3", func() {
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "fluentd-node",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).To(BeNil())
					Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
					node := ds.Spec.Template.Spec.Containers[0]
					Expect(node).ToNot(BeNil())
					Expect(node.Env).NotTo(ContainElements(s3Vars))
				})
			})

			AfterEach(func() {
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
			})
		})

		Context("Forward to Splunk", func() {

			var splunkVars = []corev1.EnvVar{
				{Name: "SPLUNK_HEC_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "logcollector-splunk-credentials",
							},
							Key: "token",
						},
					}},
				{Name: "SPLUNK_FLOW_LOG", Value: "true"},
				{Name: "SPLUNK_AUDIT_LOG", Value: "true"},
				{Name: "SPLUNK_DNS_LOG", Value: "true"},
				{Name: "SPLUNK_HEC_HOST", Value: "localhost"},
				{Name: "SPLUNK_HEC_PORT", Value: "1234"},
				{Name: "SPLUNK_PROTOCOL", Value: "https"},
				{Name: "SPLUNK_FLUSH_INTERVAL", Value: "5s"}}

			BeforeEach(func() {
				By("Specify splunk log storage")
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec: operatorv1.LogCollectorSpec{
						AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
							Splunk: &operatorv1.SplunkStoreSpec{
								Endpoint: "https://localhost:1234",
							},
						},
					},
				})).NotTo(HaveOccurred())
				By("Setting the license to export logs")
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
				By("Creating the splunk secret")
				Expect(c.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "logcollector-splunk-credentials",
						Namespace: "tigera-operator"},
					Data: map[string][]byte{
						"token": []byte("token"),
					},
				})).NotTo(HaveOccurred())

			})

			It("should forward logs to splunk", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				ds := appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fluentd-node",
						Namespace: render.LogCollectorNamespace,
					},
				}
				Expect(test.GetResource(c, &ds)).To(BeNil())
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				node := ds.Spec.Template.Spec.Containers[0]
				Expect(node).ToNot(BeNil())
				Expect(node.Env).To(ContainElements(splunkVars))
			})

			Context("Disable feature via license", func() {
				BeforeEach(func() {
					By("Deleting the previous license")
					Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
					By("Creating a new license that does not contain export logs as a feature")
					Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				})

				It("should not forward logs to splunk", func() {
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "fluentd-node",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).To(BeNil())
					Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
					node := ds.Spec.Template.Spec.Containers[0]
					Expect(node).ToNot(BeNil())
					Expect(node.Env).NotTo(ContainElements(splunkVars))
				})
			})

			AfterEach(func() {
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
			})
		})

		Context("Forward to Syslog", func() {

			var syslogVars = []corev1.EnvVar{
				{Name: "SYSLOG_HOST", Value: "localhost"},
				{Name: "SYSLOG_PORT", Value: "1234"},
				{Name: "SYSLOG_PROTOCOL", Value: "https"},
				{Name: "SYSLOG_FLUSH_INTERVAL", Value: "5s"},
				{Name: "SYSLOG_HOSTNAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "spec.nodeName",
						},
					},
				},
				{
					Name:  "SYSLOG_PACKET_SIZE",
					Value: "0",
				},
				{Name: "SYSLOG_AUDIT_EE_LOG", Value: "true"},
				{Name: "SYSLOG_AUDIT_KUBE_LOG", Value: "true"},
				{Name: "SYSLOG_DNS_LOG", Value: "true"},
				{Name: "SYSLOG_FLOW_LOG", Value: "true"},
				{Name: "SYSLOG_IDS_EVENT_LOG", Value: "true"},
			}

			BeforeEach(func() {
				By("Specify splunk log storage")
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec: operatorv1.LogCollectorSpec{
						AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
							Syslog: &operatorv1.SyslogStoreSpec{
								Endpoint:   "https://localhost:1234",
								PacketSize: new(int32),
								LogTypes: []operatorv1.SyslogLogType{
									operatorv1.SyslogLogAudit,
									operatorv1.SyslogLogDNS,
									operatorv1.SyslogLogFlows,
									operatorv1.SyslogLogL7,
									operatorv1.SyslogLogIDSEvents,
								},
							},
						},
					},
				})).NotTo(HaveOccurred())
				By("Setting the license to export logs")
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
			})

			It("should forward logs to syslog", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				ds := appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fluentd-node",
						Namespace: render.LogCollectorNamespace,
					},
				}
				Expect(test.GetResource(c, &ds)).To(BeNil())
				Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
				node := ds.Spec.Template.Spec.Containers[0]
				Expect(node).ToNot(BeNil())
				Expect(node.Env).To(ContainElements(syslogVars))
			})

			Context("Disable feature via license", func() {
				BeforeEach(func() {
					By("Deleting the previous license")
					Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ExportLogsFeature}}})).NotTo(HaveOccurred())
					By("Creating a new license that does not contain export logs as a feature")
					Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
				})

				It("should not forward logs to syslog", func() {
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "fluentd-node",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).To(BeNil())
					Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
					node := ds.Spec.Template.Spec.Containers[0]
					Expect(node).ToNot(BeNil())
					Expect(node.Env).NotTo(ContainElements(syslogVars))
				})
			})

			AfterEach(func() {
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
			})
		})
	})
})
