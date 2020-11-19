// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package compliance

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/controller/utils"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Compliance controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileCompliance
	var scheme *runtime.Scheme

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileCompliance{
			client:   c,
			scheme:   scheme,
			provider: operatorv1.ProviderNone,
			status:   status.New(c, "compliance"),
		}

		// We start off with a 'standard' installation, with nothing special
		Expect(c.Create(
			ctx,
			&operatorv1.Installation{
				Status: operatorv1.InstallationStatus{
					Computed: &operatorv1.InstallationSpec{
						Registry: "my-reg",
						// The test is provider agnostic.
						KubernetesProvider: operatorv1.ProviderNone,
					},
				},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			})).NotTo(HaveOccurred())

		// The compliance reconcile loop depends on a ton of objects that should be available in your client as
		// prerequisites. Without them, compliance will not even start creating objects. Let's create them now.
		Expect(c.Create(ctx, &operatorv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}, Status: operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchConfigMapName, Namespace: render.OperatorNamespace()},
			Data: map[string]string{
				"clusterName": "cluster",
				"shards":      "2",
				"replicas":    "1",
				"flowShards":  "2",
			}})).NotTo(HaveOccurred())

		// Create a bunch of empty secrets, such that the reconcile loop will make it to the render functionality.
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchComplianceBenchmarkerUserSecret, Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchComplianceControllerUserSecret, Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchComplianceReporterUserSecret, Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchComplianceSnapshotterUserSecret, Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchComplianceServerUserSecret, Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchPublicCertSecret, Namespace: "tigera-operator"}})).NotTo(HaveOccurred())

		// Apply the compliance CR to the fake cluster.
		Expect(c.Create(ctx, &operatorv1.Compliance{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
	})

	It("should create resources for standalone clusters", func() {

		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())

		dpl := appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{},
		}

		By("creating 3 deployments for compliance")
		Expect(c.Get(ctx, client.ObjectKey{Name: render.ComplianceServerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceServerName))

		dpl = appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{}}
		Expect(c.Get(ctx, client.ObjectKey{Name: render.ComplianceSnapshotterName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceSnapshotterName))

		dpl = appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{}}
		Expect(c.Get(ctx, client.ObjectKey{Name: render.ComplianceControllerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceControllerName))

	})

	It("should remove the compliance server in managed clusters", func() {

		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())

		By("creating a compliance-server deployment")
		dpl := appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{},
		}
		Expect(c.Get(ctx, client.ObjectKey{Name: render.ComplianceServerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceServerName))

		Expect(c.Create(
			ctx,
			&operatorv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
			})).NotTo(HaveOccurred())

		By("reconciling after the cluster type changes")
		_, err = r.Reconcile(reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		By("removing one unnecessary deployment")

		// The server should be removed...
		err = c.Get(ctx, client.ObjectKey{Name: render.ComplianceServerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)
		Expect(err).To(HaveOccurred())
		Expect(errors.IsNotFound(err)).To(BeTrue())

		// ... while the snapshotter and the controller are still there.
		Expect(c.Get(ctx, client.ObjectKey{Name: render.ComplianceSnapshotterName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceSnapshotterName))

		Expect(c.Get(ctx, client.ObjectKey{Name: render.ComplianceControllerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceControllerName))
	})
})
