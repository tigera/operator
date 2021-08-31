// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render/monitor"
)

var _ = Describe("Monitor controller tests", func() {
	var cli client.Client
	var ctx context.Context
	var mockStatus *status.MockStatus
	var r ReconcileMonitor
	var scheme *runtime.Scheme

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

		// Create an object we can use throughout the test to do the monitor reconcile loops.
		r = ReconcileMonitor{
			client:          cli,
			scheme:          scheme,
			provider:        operatorv1.ProviderNone,
			status:          mockStatus,
			prometheusReady: &utils.ReadyFlag{},
		}

		// We start off with a 'standard' installation, with nothing special
		Expect(cli.Create(ctx, &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Computed: &operatorv1.InstallationSpec{},
			},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Registry: "some.registry.org/",
			},
		})).To(BeNil())

		// Apply the Monitor CR to the fake cluster.
		Expect(cli.Create(ctx, &operatorv1.Monitor{
			TypeMeta:   metav1.TypeMeta{Kind: "Monitor", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())

		// Mark that the watch for prometheus resources was successful
		r.prometheusReady.MarkAsReady()
	})

	Context("controller reconciliation", func() {
		var (
			am = &monitoringv1.Alertmanager{}
			p  = &monitoringv1.Prometheus{}
			pm = &monitoringv1.PodMonitor{}
			pr = &monitoringv1.PrometheusRule{}
			sm = &monitoringv1.ServiceMonitor{}
		)

		BeforeEach(func() {
			// Prometheus related objects should not exist.
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}, pm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.TigeraPrometheusDPRate, Namespace: common.TigeraPrometheusNamespace}, pr)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
		})

		It("should create Prometheus related resources", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			// Prometheus related objects should be rendered after reconciliation.
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}, pm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.TigeraPrometheusDPRate, Namespace: common.TigeraPrometheusNamespace}, pr)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
		})
	})

	Context("Alertmanager Configuration secrets", func() {
		It("should create the Alertmanager secret for new install", func() {
			// Make sure Alertmanager secrets don't exist in either Operator or Prometheus namespace.
			var s = &corev1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.AlertmanagerConfigSecret, Namespace: common.OperatorNamespace()}, s)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.AlertmanagerConfigSecret, Namespace: common.TigeraPrometheusNamespace}, s)).To(HaveOccurred())

			s, setOwner, err := r.readOrCreateAlertmanagerConfigSecret(ctx)
			Expect(err).To(BeNil())
			Expect(setOwner).To(BeTrue())
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))
			Expect(cli.Get(ctx, client.ObjectKey{Name: monitor.AlertmanagerConfigSecret, Namespace: common.OperatorNamespace()}, s)).NotTo(HaveOccurred())
		})

		It("should read Alertmanager secret from the Operator namespace if exists", func() {
			secretOperator := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte("Alertmanager secret in tigera-operator"),
				},
			}
			secretPrometheus := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.TigeraPrometheusNamespace,
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte("Alertmanager secret in tigera-prometheus"),
				},
			}

			Expect(cli.Create(ctx, secretOperator)).To(BeNil())
			Expect(cli.Create(ctx, secretPrometheus)).To(BeNil())

			s, setOwner, err := r.readOrCreateAlertmanagerConfigSecret(ctx)
			Expect(err).To(BeNil())
			Expect(setOwner).To(BeFalse())
			Expect(s).NotTo(BeNil())

			Expect(s.GetName()).To(Equal(monitor.AlertmanagerConfigSecret))
			Expect(s.GetNamespace()).To(Equal(common.OperatorNamespace()))
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-operator")))

			Expect(cli.Delete(ctx, secretOperator)).To(BeNil())
			Expect(cli.Delete(ctx, secretPrometheus)).To(BeNil())
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

			s, setOwner, err := r.readOrCreateAlertmanagerConfigSecret(ctx)
			Expect(err).To(BeNil())
			Expect(setOwner).To(BeTrue())
			Expect(s).NotTo(BeNil())

			Expect(s.GetName()).To(Equal(monitor.AlertmanagerConfigSecret))
			Expect(s.GetNamespace()).To(Equal(common.OperatorNamespace()))
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte(alertmanagerConfig)))

			Expect(cli.Delete(ctx, secretPrometheus)).To(BeNil())
		})

		It("should copy back the Alertmanager secret when upgrading and won't take ownership if it is modified", func() {
			secretPrometheus := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      monitor.AlertmanagerConfigSecret,
					Namespace: common.TigeraPrometheusNamespace,
				},
				Data: map[string][]byte{
					"alertmanager.yaml": []byte("Alertmanager secret in tigera-prometheus namespace"),
				},
			}

			Expect(cli.Create(ctx, secretPrometheus)).To(BeNil())

			s, setOwner, err := r.readOrCreateAlertmanagerConfigSecret(ctx)
			Expect(err).To(BeNil())
			Expect(setOwner).To(BeFalse())
			Expect(s).NotTo(BeNil())

			Expect(s.GetName()).To(Equal(monitor.AlertmanagerConfigSecret))
			Expect(s.GetNamespace()).To(Equal(common.OperatorNamespace()))
			Expect(s.Data).To(HaveKeyWithValue("alertmanager.yaml", []byte("Alertmanager secret in tigera-prometheus namespace")))

			Expect(cli.Delete(ctx, secretPrometheus)).To(BeNil())
		})
	})
})
