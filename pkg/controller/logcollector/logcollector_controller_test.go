// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/test"
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
		c = fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx = context.Background()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("AddCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileLogCollector{
			client:          c,
			scheme:          scheme,
			provider:        operatorv1.ProviderNone,
			status:          mockStatus,
			licenseAPIReady: &utils.ReadyFlag{},
			tierWatchReady:  &utils.ReadyFlag{},
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
		Expect(c.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
		certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		kibanaTLS, err := certificateManager.GetOrCreateKeyPair(c, relasticsearch.PublicCertSecret, common.OperatorNamespace(), []string{relasticsearch.PublicCertSecret})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, kibanaTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchLogCollectorUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchEksLogForwarderUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusTLSSecretName})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Apply the logcollector CR to the fake cluster.
		Expect(c.Create(ctx, &operatorv1.LogCollector{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())

		// Mark that watches were successful.
		r.licenseAPIReady.MarkAsReady()
		r.tierWatchReady.MarkAsReady()
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
					mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: export-logs", mock.Anything, mock.Anything).Return()
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "fluentd-node",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).Should(HaveOccurred())
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
					mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: export-logs", mock.Anything, mock.Anything).Return()

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "fluentd-node",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).Should(HaveOccurred())
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
					mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: export-logs", mock.Anything, mock.Anything).Return()

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					ds := appsv1.DaemonSet{
						TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "fluentd-node",
							Namespace: render.LogCollectorNamespace,
						},
					}
					Expect(test.GetResource(c, &ds)).Should(HaveOccurred())
				})
			})

			AfterEach(func() {
				Expect(c.Delete(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
			})
		})
		Context("reconcile for Status condition update from tigerastatus", func() {
			generation := int64(2)
			It("should reconcile with one item ", func() {
				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "log-collector"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status: operatorv1.TigeraStatusStatus{
						Conditions: []operatorv1.TigeraStatusCondition{
							{
								Type:               operatorv1.ComponentAvailable,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.AllObjectsAvailable),
								Message:            "All Objects are available",
								ObservedGeneration: generation,
							},
						},
					},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "log-collector",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := GetLogCollector(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(1))
				Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
				Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
				Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
				Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
			})
			It("should reconcile with empty tigerastatus conditions", func() {
				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "log-collector"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status:     operatorv1.TigeraStatusStatus{},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "log-collector",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := GetLogCollector(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(0))
			})
			It("should reconcile with creating new status condition  with multiple conditions as true", func() {
				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "log-collector"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status: operatorv1.TigeraStatusStatus{
						Conditions: []operatorv1.TigeraStatusCondition{
							{
								Type:               operatorv1.ComponentAvailable,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.AllObjectsAvailable),
								Message:            "All Objects are available",
								ObservedGeneration: generation,
							},
							{
								Type:               operatorv1.ComponentProgressing,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.ResourceNotReady),
								Message:            "Progressing Installation.operatorv1.tigera.io",
								ObservedGeneration: generation,
							},
							{
								Type:               operatorv1.ComponentDegraded,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.ResourceUpdateError),
								Message:            "Error resolving ImageSet for components",
								ObservedGeneration: generation,
							},
						},
					},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "log-collector",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := GetLogCollector(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(3))
				Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
				Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
				Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
				Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

				Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
				Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.ResourceNotReady)))
				Expect(instance.Status.Conditions[1].Message).To(Equal("Progressing Installation.operatorv1.tigera.io"))
				Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

				Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
				Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.ResourceUpdateError)))
				Expect(instance.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
				Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
			})
			It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "log-collector"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status: operatorv1.TigeraStatusStatus{
						Conditions: []operatorv1.TigeraStatusCondition{
							{
								Type:               operatorv1.ComponentAvailable,
								Status:             operatorv1.ConditionTrue,
								Reason:             string(operatorv1.AllObjectsAvailable),
								Message:            "All Objects are available",
								ObservedGeneration: generation,
							},
							{
								Type:               operatorv1.ComponentProgressing,
								Status:             operatorv1.ConditionFalse,
								Reason:             string(operatorv1.NotApplicable),
								Message:            "Not Applicable",
								ObservedGeneration: generation,
							},
							{
								Type:               operatorv1.ComponentDegraded,
								Status:             operatorv1.ConditionFalse,
								Reason:             string(operatorv1.NotApplicable),
								Message:            "Not Applicable",
								ObservedGeneration: generation,
							},
						},
					},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "log-collector",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := GetLogCollector(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(3))
				Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
				Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
				Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
				Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

				Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
				Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionFalse)))
				Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.NotApplicable)))
				Expect(instance.Status.Conditions[1].Message).To(Equal("Not Applicable"))
				Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

				Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
				Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionFalse)))
				Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.NotApplicable)))
				Expect(instance.Status.Conditions[2].Message).To(Equal("Not Applicable"))
				Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
			})
		})
	})

	Context("allow-tigera reconciliation", func() {
		var readyFlag *utils.ReadyFlag

		BeforeEach(func() {
			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("SetMetaData", mock.Anything).Return()

			readyFlag = &utils.ReadyFlag{}
			readyFlag.MarkAsReady()
			r = ReconcileLogCollector{
				client:          c,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				status:          mockStatus,
				licenseAPIReady: readyFlag,
				tierWatchReady:  readyFlag,
			}
		})

		It("should wait if allow-tigera tier is unavailable", func() {
			utils.DeleteAllowTigeraTierAndExpectWait(ctx, c, &r, mockStatus)
		})

		It("should wait if tier watch is not ready", func() {
			r.tierWatchReady = &utils.ReadyFlag{}
			utils.ExpectWaitForTierWatch(ctx, &r, mockStatus)
		})
	})

	Context("should test fillDefaults for logCollector", func() {
		It("should set default values for CollectProcessPath, syslog types", func() {
			logCollector := operatorv1.LogCollector{Spec: operatorv1.LogCollectorSpec{AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
				Syslog: &operatorv1.SyslogStoreSpec{}}}}
			modifiedFields := fillDefaults(&logCollector)
			expectedFields := []string{"CollectProcessPath", "AdditionalStores.Syslog.LogTypes", "AdditionalStores.Syslog.Encryption"}
			expectedLogTypes := []operatorv1.SyslogLogType{
				operatorv1.SyslogLogAudit,
				operatorv1.SyslogLogDNS,
				operatorv1.SyslogLogFlows,
			}

			Expect(len(modifiedFields)).To(Equal(3))
			Expect(modifiedFields).To(ConsistOf(expectedFields))
			Expect(*logCollector.Spec.CollectProcessPath).To(Equal(operatorv1.CollectProcessPathEnable))
			Expect(logCollector.Spec.AdditionalStores.Syslog.LogTypes).To(Equal(expectedLogTypes))
		})
		It("CollectProcessPath,syslog types should not be changed if set already", func() {
			logCollector := operatorv1.LogCollector{Spec: operatorv1.LogCollectorSpec{AdditionalStores: &operatorv1.AdditionalLogStoreSpec{
				Syslog: &operatorv1.SyslogStoreSpec{}}}}

			processPath := operatorv1.CollectProcessPathDisable
			logCollector.Spec.CollectProcessPath = &processPath
			logCollector.Spec.AdditionalStores.Syslog.LogTypes = []operatorv1.SyslogLogType{operatorv1.SyslogLogAudit}
			logCollector.Spec.AdditionalStores.Syslog.Encryption = operatorv1.EncryptionNone
			modifiedFields := fillDefaults(&logCollector)
			Expect(*logCollector.Spec.CollectProcessPath).To(Equal(operatorv1.CollectProcessPathDisable))
			expectedLogTypes := []operatorv1.SyslogLogType{
				operatorv1.SyslogLogAudit}
			Expect(len(modifiedFields)).To(Equal(0))
			Expect(logCollector.Spec.AdditionalStores.Syslog.LogTypes).To(Equal(expectedLogTypes))
		})
	})
})
