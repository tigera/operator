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

package compliance

import (
	"context"
	"fmt"
	"time"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
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
	var cr *operatorv1.Compliance
	var r ReconcileCompliance
	var mockStatus *status.MockStatus
	var scheme *runtime.Scheme

	expectedDNSNames := dns.GetServiceDNSNames(render.ComplianceServiceName, render.ComplianceNamespace, dns.DefaultClusterDomain)
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

		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDaemonsets", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileCompliance{
			client:        c,
			scheme:        scheme,
			provider:      operatorv1.ProviderNone,
			status:        mockStatus,
			clusterDomain: dns.DefaultClusterDomain,
			ready:         make(chan bool),
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
		Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ComplianceFeature}}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: rmeta.OperatorNamespace()},
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
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: "tigera-operator"}})).NotTo(HaveOccurred())

		// Apply the compliance CR to the fake cluster.
		cr = &operatorv1.Compliance{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
		Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

		// mark that the watch for license key was successful
		r.markAsReady()
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

	It("should create a new compliance server cert if the cert is owned by compliance and has the wrong DNS names", func() {
		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())

		By("creating the compliance server cert secret")
		assertExpectedCertDNSNames(c, expectedDNSNames...)

		By("replacing the cert with one that has the wrong DNS names")
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceServerCertSecret,
			Namespace: rmeta.OperatorNamespace()}})).NotTo(HaveOccurred())

		oldDNSName := "compliance.tigera-compliance.svc"
		newSecret, err := secret.CreateTLSSecret(nil,
			render.ComplianceServerCertSecret, rmeta.OperatorNamespace(), render.ComplianceServerKeyName,
			render.ComplianceServerCertName, rmeta.DefaultCertificateDuration, nil, oldDNSName,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		By("replacing the invalid cert")
		result, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())

		assertExpectedCertDNSNames(c, expectedDNSNames...)
	})

	It("should reconcile if the compliance server cert is user-supplied", func() {
		// This test just validates that user-provided certs reconcile and do
		// not overwrite the certs.
		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())

		By("replacing the server certs with user-supplied certs")
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceServerCertSecret,
			Namespace: rmeta.OperatorNamespace()}})).NotTo(HaveOccurred())
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceServerCertSecret,
			Namespace: render.ComplianceNamespace}})).NotTo(HaveOccurred())

		oldDNSNames := []string{"compliance.example.com", "compliance.tigera-compliance.svc"}
		testCA := test.MakeTestCA("compliance-test")
		newSecret, err := secret.CreateTLSSecret(testCA,
			render.ComplianceServerCertSecret, rmeta.OperatorNamespace(), render.ComplianceServerKeyName,
			render.ComplianceServerCertName, rmeta.DefaultCertificateDuration, nil, oldDNSNames...,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		newSecret = secret.CopyToNamespace(render.ComplianceNamespace, newSecret)[0]
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		assertExpectedCertDNSNames(c, oldDNSNames...)

		By("checking that an error occurred and the cert didn't change")
		result, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())
		assertExpectedCertDNSNames(c, oldDNSNames...)
	})

	It("should reconcile if the compliance server cert is user-supplied and has the expected DNS names", func() {
		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())

		By("replacing the server certs with ones that include the expected DNS names")
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceServerCertSecret,
			Namespace: rmeta.OperatorNamespace()}})).NotTo(HaveOccurred())
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceServerCertSecret,
			Namespace: render.ComplianceNamespace}})).NotTo(HaveOccurred())

		// Custom cert has the compliance svc DNS names as well as other DNS names
		dnsNames := append(expectedDNSNames, "compliance.example.com", "192.168.10.13")
		newSecret, err := secret.CreateTLSSecret(nil,
			render.ComplianceServerCertSecret, rmeta.OperatorNamespace(), render.ComplianceServerKeyName,
			render.ComplianceServerCertName, rmeta.DefaultCertificateDuration, nil, dnsNames...,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		newSecret = secret.CopyToNamespace(render.ComplianceNamespace, newSecret)[0]
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		assertExpectedCertDNSNames(c, dnsNames...)

		By("checking that an error occurred and the cert didn't change")
		result, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())
		assertExpectedCertDNSNames(c, dnsNames...)
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

	Context("Feature compliance not active", func() {
		BeforeEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ComplianceFeature}}})).NotTo(HaveOccurred())
			By("Creating a new license that does not contain compliance as a feature")
			Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})

		It("should not create resources", func() {
			mockStatus.On("SetDegraded", "Feature is not active", "License does not support this feature").Return()

			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceControllerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).NotTo(BeNil())

			controller := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceControllerName)
			Expect(controller).To(BeNil())

			pt := corev1.PodTemplate{
				TypeMeta: metav1.TypeMeta{Kind: "PodTemplate", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera.io.report",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &pt)).NotTo(BeNil())

			reporter := test.GetContainer(pt.Template.Spec.Containers, "reporter")
			Expect(reporter).To(BeNil())

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceSnapshotterName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).NotTo(BeNil())

			snap := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceSnapshotterName)
			Expect(snap).To(BeNil())

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "compliance-benchmarker",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).NotTo(BeNil())
			bench := test.GetContainer(ds.Spec.Template.Spec.Containers, "compliance-benchmarker")

			Expect(bench).To(BeNil())
			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).NotTo(BeNil())

			server := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceServerName)
			Expect(server).To(BeNil())
		})

		AfterEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})
	})
})

func assertExpectedCertDNSNames(c client.Client, expectedDNSNames ...string) {
	ctx := context.Background()
	secret := &corev1.Secret{}

	Expect(c.Get(ctx, client.ObjectKey{Name: render.ComplianceServerCertSecret,
		Namespace: rmeta.OperatorNamespace(),
	}, secret)).NotTo(HaveOccurred())
	test.VerifyCertSANs(secret.Data[render.ComplianceServerCertName], expectedDNSNames...)

	Expect(c.Get(ctx, client.ObjectKey{Name: render.ComplianceServerCertSecret,
		Namespace: render.ComplianceNamespace,
	}, secret)).NotTo(HaveOccurred())
	test.VerifyCertSANs(secret.Data[render.ComplianceServerCertName], expectedDNSNames...)
}
