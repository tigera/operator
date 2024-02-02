// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

package monitor

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/monitor"
)

var _ = Describe("Monitor controller tests", func() {
	var cli client.Client
	var ctx context.Context
	var mockStatus *status.MockStatus
	var r ReconcileMonitor
	var scheme *runtime.Scheme
	var installation *operatorv1.Installation
	var monitorCR *operatorv1.Monitor

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		ctx = context.Background()
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		// Create an object we can use throughout the test to do the monitor reconcile loops.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("AddDaemonsets", mock.Anything)
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything)
		mockStatus.On("ClearDegraded")
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("RemoveDeployments", mock.Anything)
		mockStatus.On("RemoveCertificateSigningRequests", common.TigeraPrometheusNamespace)
		mockStatus.On("SetMetaData", mock.Anything).Return()

		// Create an object we can use throughout the test to do the monitor reconcile loops.
		r = ReconcileMonitor{
			client:          cli,
			scheme:          scheme,
			provider:        operatorv1.ProviderNone,
			status:          mockStatus,
			prometheusReady: &utils.ReadyFlag{},
			tierWatchReady:  &utils.ReadyFlag{},
		}

		// We start off with a 'standard' installation, with nothing special
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Generation: 2,
			},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Computed: &operatorv1.InstallationSpec{},
			},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Registry: "some.registry.org/",
			},
		}
		Expect(cli.Create(ctx, installation)).To(BeNil())

		// Apply the Monitor CR to the fake cluster.
		monitorCR = &operatorv1.Monitor{
			TypeMeta:   metav1.TypeMeta{Kind: "Monitor", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(cli.Create(ctx, monitorCR)).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, render.CreateCertificateConfigMap("test", render.TyphaCAConfigMapName, common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

		// Create a certificate manager and provision the CA to unblock the controller. Generally this would be done by
		// the cluster CA controller and is a prerequisite for the monitor controller to function.
		cm, err := certificatemanager.Create(cli, &installation.Spec, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Mark that watches were successful.
		r.prometheusReady.MarkAsReady()
		r.tierWatchReady.MarkAsReady()
	})

	Context("controller reconciliation", func() {
		var (
			am = &monitoringv1.Alertmanager{}
			p  = &monitoringv1.Prometheus{}
			pr = &monitoringv1.PrometheusRule{}
			sm = &monitoringv1.ServiceMonitor{}
		)

		BeforeEach(func() {
			// Prometheus related objects should not exist.
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.TigeraPrometheusDPRate, Namespace: common.TigeraPrometheusNamespace}, pr)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
		})

		It("should create Prometheus related resources", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			// Prometheus related objects should be rendered after reconciliation.
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.TigeraPrometheusDPRate, Namespace: common.TigeraPrometheusNamespace}, pr)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
		})

		It("should render allow-tigera policy when tier and policy watch are ready", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(6))
			Expect(policies.Items[0].Name).To(Equal("allow-tigera.calico-node-alertmanager"))
			Expect(policies.Items[1].Name).To(Equal("allow-tigera.calico-node-alertmanager-mesh"))
			Expect(policies.Items[2].Name).To(Equal("allow-tigera.default-deny"))
			Expect(policies.Items[3].Name).To(Equal("allow-tigera.prometheus"))
			Expect(policies.Items[4].Name).To(Equal("allow-tigera.prometheus-operator"))
			Expect(policies.Items[5].Name).To(Equal("allow-tigera.tigera-prometheus-api"))
		})

		It("should omit allow-tigera policy and not degrade when tier is not ready", func() {
			Expect(cli.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should degrade and wait if tier is ready but tier watch is not ready", func() {
			r.tierWatchReady = &utils.ReadyFlag{}
			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
			mockStatus.On("SetMetaData", mock.Anything).Return()
			r.status = mockStatus

			utils.ExpectWaitForTierWatch(ctx, &r, mockStatus)

			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		Context("controller reconciliation with external monitoring configuration", func() {
			It("should create Prometheus related resources", func() {
				Expect(r.client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "external-prometheus"}})).NotTo(HaveOccurred())
				monitorCR.Spec.ExternalPrometheus = &operatorv1.ExternalPrometheus{
					ServiceMonitor: &operatorv1.ServiceMonitor{},
					Namespace:      "external-prometheus",
				}
				Expect(r.client.Update(ctx, monitorCR)).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).NotTo(HaveOccurred())

				// Prometheus related objects should be rendered after reconciliation.
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.TigeraPrometheusDPRate, Namespace: common.TigeraPrometheusNamespace}, pr)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())

				// External Prometheus related objects should be rendered after reconciliation.
				serviceMonitor := &monitoringv1.ServiceMonitor{}
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, serviceMonitor)).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &corev1.ConfigMap{})).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &corev1.Secret{})).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &corev1.ServiceAccount{})).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &rbacv1.ClusterRole{})).NotTo(HaveOccurred())
				Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-external-prometheus", Namespace: "external-prometheus"}, &rbacv1.ClusterRoleBinding{})).NotTo(HaveOccurred())

				Expect(serviceMonitor.Spec.Endpoints).To(HaveLen(1))
				// Verify that the default settings are propagated.
				Expect(serviceMonitor.Labels).To(Equal(map[string]string{render.AppLabelName: monitor.TigeraExternalPrometheus}))
				Expect(serviceMonitor.Spec.Endpoints[0]).To(Equal(monitoringv1.Endpoint{
					Params: map[string][]string{"match[]": {"{__name__=~\".+\"}"}},
					Port:   "web",
					Path:   "/federate",
					Scheme: "https",
					TLSConfig: &monitoringv1.TLSConfig{
						SafeTLSConfig: monitoringv1.SafeTLSConfig{
							CA: monitoringv1.SecretOrConfigMap{
								ConfigMap: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tigera-external-prometheus",
									},
									Key: corev1.TLSCertKey,
								},
							},
						},
					},
					BearerTokenSecret: corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: monitor.TigeraExternalPrometheus,
						},
						Key: "token",
					},
				}))
			})
		})
	})

	Context("Alertmanager Configuration secrets", func() {
		var secretOperator *corev1.Secret
		var secretPrometheus *corev1.Secret

		BeforeEach(func() {
			secretOperator = &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte("Alertmanager secret in tigera-operator namespace"),
				},
			}
			secretPrometheus = &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.TigeraPrometheusNamespace,
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte("Alertmanager secret in tigera-prometheus namespace"),
				},
			}
		})

		AfterEach(func() {
			Expect(cli.Delete(ctx, secretOperator)).To(BeNil())
			Expect(cli.Delete(ctx, secretPrometheus)).To(BeNil())
		})

		It("should create the Alertmanager secret for new install", func() {
			s := &corev1.Secret{}
			// Make sure Alertmanager secrets don't exist in either Operator or Prometheus namespace.
			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).To(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			var ownerRefs []metav1.OwnerReference

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).NotTo(HaveOccurred())
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))
		})

		It("should read Alertmanager secret from the Operator namespace if exists", func() {
			Expect(cli.Create(ctx, secretOperator)).To(BeNil())
			Expect(cli.Create(ctx, secretPrometheus)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			s := &corev1.Secret{}
			var ownerRefs []metav1.OwnerReference

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-operator namespace")))
			Expect(ownerRefs).To(HaveLen(0))

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-operator namespace")))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))
		})

		It("should copy back the Alertmanager secret when upgrading and take ownership if it is unmodified", func() {
			secretPrometheus := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.TigeraPrometheusNamespace,
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte(alertmanagerConfig),
				},
			}
			Expect(cli.Create(ctx, secretPrometheus)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			s := &corev1.Secret{}
			var ownerRefs []metav1.OwnerReference

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))
		})

		It("should copy back the Alertmanager secret when upgrading and won't take ownership if it is modified", func() {
			Expect(cli.Create(ctx, secretPrometheus)).To(BeNil())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			s := &corev1.Secret{}
			var ownerRefs []metav1.OwnerReference

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretOperator), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-prometheus namespace")))
			Expect(ownerRefs).To(HaveLen(0))

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(secretPrometheus), s)).NotTo(HaveOccurred())
			ownerRefs = s.GetObjectMeta().GetOwnerReferences()
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-prometheus namespace")))
			Expect(ownerRefs).To(HaveLen(1))
			Expect(ownerRefs[0].APIVersion).To(Equal("operator.tigera.io/v1"))
		})
	})

	Context("Reconcile for Condition status", func() {
		generation := int64(2)
		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
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
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "monitor",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := r.getMonitor(ctx)
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
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "monitor",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := r.getMonitor(ctx)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(0))
		})

		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
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
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "monitor",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := r.getMonitor(ctx)
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
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
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
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "monitor",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			instance, err := r.getMonitor(ctx)
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
