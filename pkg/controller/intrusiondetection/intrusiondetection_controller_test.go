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

package intrusiondetection

import (
	"context"
	"fmt"
	"time"

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
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

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

var _ = Describe("IntrusionDetection controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileIntrusionDetection
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
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything).Return()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileIntrusionDetection{
			client:   c,
			scheme:   scheme,
			provider: operatorv1.ProviderNone,
			status:   mockStatus,
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
		Expect(c.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status:     v3.LicenseKeyStatus{Features: []string{common.ThreatDefenseFeature}}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.LogCollector{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      relasticsearch.PublicCertSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchIntrusionDetectionUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchIntrusionDetectionJobUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchADJobUserSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.KibanaPublicCertSecret,
				Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ECKLicenseConfigMapName,
				Namespace: render.ECKOperatorNamespace,
			},
			Data: map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterpriseTrial)},
		})).NotTo(HaveOccurred())

		// Apply the intrusiondetection CR to the fake cluster.
		Expect(c.Create(ctx, &operatorv1.IntrusionDetection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())
	})

	Context("image reconciliation", func() {
		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "intrusion-detection-controller",
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "controller")
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentIntrusionDetectionController.Image,
					components.ComponentIntrusionDetectionController.Version)))

			j := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.IntrusionDetectionInstallerJobName,
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &j)).To(BeNil())
			Expect(j.Spec.Template.Spec.Containers).To(HaveLen(1))
			installer := test.GetContainer(j.Spec.Template.Spec.Containers, "elasticsearch-job-installer")
			Expect(installer).ToNot(BeNil())
			Expect(installer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentElasticTseeInstaller.Image,
					components.ComponentElasticTseeInstaller.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/intrusion-detection-job-installer", Digest: "sha256:intrusiondetectionjobinstallerhash"},
						{Image: "tigera/intrusion-detection-controller", Digest: "sha256:intrusiondetectioncontrollerhash"},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "intrusion-detection-controller",
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "controller")
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentIntrusionDetectionController.Image,
					"sha256:intrusiondetectioncontrollerhash")))

			j := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.IntrusionDetectionInstallerJobName,
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &j)).To(BeNil())
			Expect(j.Spec.Template.Spec.Containers).To(HaveLen(1))
			installer := test.GetContainer(j.Spec.Template.Spec.Containers, "elasticsearch-job-installer")
			Expect(installer).ToNot(BeNil())
			Expect(installer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentElasticTseeInstaller.Image,
					"sha256:intrusiondetectionjobinstallerhash")))
		})
		It("should not register intrusion-detection-job-installer image when cluster is managed", func() {
			Expect(c.Create(ctx, &operatorv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ManagementClusterConnectionSpec{
					ManagementClusterAddr: "127.0.0.1:12345",
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			j := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.IntrusionDetectionInstallerJobName,
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			// Shouldn't be able to find the job in a managed cluster.
			Expect(test.GetResource(c, &j)).NotTo(BeNil())
		})
		It("should register intrusion-detection-job-installer image when in a management cluster", func() {
			Expect(c.Create(ctx, &operatorv1.ManagementCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ManagementClusterSpec{
					Address: "127.0.0.1:12345",
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			j := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.IntrusionDetectionInstallerJobName,
					Namespace: render.IntrusionDetectionNamespace,
				},
			}
			Expect(test.GetResource(c, &j)).To(BeNil())
		})
	})

	Context("secret availability", func() {
		It("should not wait on tigera-ee-installer-elasticsearch-access secret when cluster is managed", func() {
			Expect(c.Create(ctx, &operatorv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ManagementClusterConnectionSpec{
					ManagementClusterAddr: "127.0.0.1:12345",
				},
			})).ToNot(HaveOccurred())

			// Delete the secret to ensure that utils.ElasticSearch correctly looks for secrets relevant to managed
			// clusters only and doesn't attempt to find the IDS job secret.
			idsSecret := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ElasticsearchIntrusionDetectionJobUserSecret,
					Namespace: rmeta.OperatorNamespace(),
				},
			}
			err := c.Delete(ctx, idsSecret)
			Expect(err).ShouldNot(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(nil, "SetDegraded", 0)).To(BeTrue())
		})

		It("should wait on tigera-ee-installer-elasticsearch-access secret when in a management cluster", func() {
			Expect(c.Create(ctx, &operatorv1.ManagementCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ManagementClusterSpec{
					Address: "127.0.0.1:12345",
				},
			})).ToNot(HaveOccurred())

			// Delete the secret to force utils.ElasticSearch to return a NotFound error, which in turn degrades the status and exists the reconcile loop.
			// This tells us that the secret was expected but not found, therefore we are correctly waiting on the secret in a management cluster.
			idsSecret := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ElasticsearchIntrusionDetectionJobUserSecret,
					Namespace: rmeta.OperatorNamespace(),
				},
			}
			err := c.Delete(ctx, idsSecret)
			Expect(err).ShouldNot(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(nil, "SetDegraded", 1)).To(BeTrue())
		})
	})

	Context("Feature intrusion detection not active", func() {
		BeforeEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ThreatDefenseFeature}}})).NotTo(HaveOccurred())
			By("Creating a new license that does not contain intrusion detection as a feature")
			Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})

		It("should not create resources", func() {
			mockStatus.On("SetDegraded", "Feature is not active", "License does not support this feature").Return()

			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(10 * time.Second))
		})

		AfterEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})
	})
})
