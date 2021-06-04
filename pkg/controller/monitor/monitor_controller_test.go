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
	"github.com/tigera/operator/pkg/render"
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

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("AddDaemonsets", mock.Anything)
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything)
		mockStatus.On("ClearDegraded")
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		r = ReconcileMonitor{
			client:   cli,
			scheme:   scheme,
			provider: operatorv1.ProviderNone,
			status:   mockStatus,
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
	})

	Context("image reconciliation", func() {
		It("should create Prometheus related resources", func() {
			am := &monitoringv1.Alertmanager{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).To(HaveOccurred())
			p := &monitoringv1.Prometheus{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).To(HaveOccurred())
			pm := &monitoringv1.PodMonitor{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}, pm)).To(HaveOccurred())
			pr := &monitoringv1.PrometheusRule{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.TigeraPrometheusDPRate, Namespace: common.TigeraPrometheusNamespace}, pr)).To(HaveOccurred())
			sm := &monitoringv1.ServiceMonitor{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).To(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			Expect(cli.Get(ctx, client.ObjectKey{Name: render.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace}, am)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace}, p)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.FluentdMetrics, Namespace: common.TigeraPrometheusNamespace}, pm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.TigeraPrometheusDPRate, Namespace: common.TigeraPrometheusNamespace}, pr)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
			Expect(cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace}, sm)).NotTo(HaveOccurred())
		})
	})
})
