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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/test"

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
		result, err := r.Reconcile(ctx, reconcile.Request{})
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
		result, err := r.Reconcile(ctx, reconcile.Request{})
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
		_, err = r.Reconcile(ctx, reconcile.Request{})
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

	Context("image reconciliation", func() {
		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			//components.ComponentComplianceBenchmarker
			//components.ComponentComplianceSnapshotter
			//components.ComponentComplianceServer
			//components.ComponentComplianceController
			//components.ComponentComplianceReporter
			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceControllerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceControllerName)
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentComplianceController.Image,
					components.ComponentComplianceController.Version)))

			pt := corev1.PodTemplate{
				TypeMeta: metav1.TypeMeta{Kind: "PodTemplate", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera.io.report",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &pt)).To(BeNil())
			Expect(pt.Template.Spec.Containers).To(HaveLen(1))
			reporter := test.GetContainer(pt.Template.Spec.Containers, "reporter")
			Expect(reporter).ToNot(BeNil())
			Expect(reporter.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentComplianceReporter.Image,
					components.ComponentComplianceReporter.Version)))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceSnapshotterName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			snap := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceSnapshotterName)
			Expect(snap).ToNot(BeNil())
			Expect(snap.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentComplianceSnapshotter.Image,
					components.ComponentComplianceSnapshotter.Version)))

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "compliance-benchmarker",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			bench := test.GetContainer(ds.Spec.Template.Spec.Containers, "compliance-benchmarker")
			Expect(bench).ToNot(BeNil())
			Expect(bench.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentComplianceBenchmarker.Image,
					components.ComponentComplianceBenchmarker.Version)))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			server := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceServerName)
			Expect(server).ToNot(BeNil())
			Expect(server.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentComplianceServer.Image,
					components.ComponentComplianceServer.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/compliance-benchmarker", Digest: "sha256:benchmarkerhash"},
						{Image: "tigera/compliance-controller", Digest: "sha256:controllerhash"},
						{Image: "tigera/compliance-reporter", Digest: "sha256:reporterhash"},
						{Image: "tigera/compliance-server", Digest: "sha256:serverhash"},
						{Image: "tigera/compliance-snapshotter", Digest: "sha256:snapshotterhash"},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceControllerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceControllerName)
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentComplianceController.Image,
					"sha256:controllerhash")))

			pt := corev1.PodTemplate{
				TypeMeta: metav1.TypeMeta{Kind: "PodTemplate", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera.io.report",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &pt)).To(BeNil())
			Expect(pt.Template.Spec.Containers).To(HaveLen(1))
			reporter := test.GetContainer(pt.Template.Spec.Containers, "reporter")
			Expect(reporter).ToNot(BeNil())
			Expect(reporter.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentComplianceReporter.Image,
					"sha256:reporterhash")))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceSnapshotterName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			snap := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceSnapshotterName)
			Expect(snap).ToNot(BeNil())
			Expect(snap.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentComplianceSnapshotter.Image,
					"sha256:snapshotterhash")))

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "compliance-benchmarker",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			bench := test.GetContainer(ds.Spec.Template.Spec.Containers, "compliance-benchmarker")
			Expect(bench).ToNot(BeNil())
			Expect(bench.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentComplianceBenchmarker.Image,
					"sha256:benchmarkerhash")))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			server := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceServerName)
			Expect(server).ToNot(BeNil())
			Expect(server.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentComplianceServer.Image,
					"sha256:serverhash")))
		})
	})
})
