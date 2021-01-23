// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package manager

import (
	"context"
	"fmt"

	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/test"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Manager controller tests", func() {
	var c client.Client
	var scheme *runtime.Scheme
	var instance *operatorv1.Manager
	var ctx context.Context

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()
	})

	It("should query a default manager instance", func() {
		By("Creating a CRD")
		instance = &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		err := c.Create(ctx, instance)
		Expect(err).NotTo(HaveOccurred())
		instance, err = GetManager(ctx, c)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("image reconciliation", func() {
		var r ReconcileManager
		var mockStatus *status.MockStatus
		BeforeEach(func() {
			// Create an object we can use throughout the test to do the compliance reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			r = ReconcileManager{
				client:   c,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			Expect(c.Create(ctx, &operatorv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Status: operatorv1.APIServerStatus{
					State: operatorv1.TigeraStatusReady,
				},
			})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			})).NotTo(HaveOccurred())
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
							Registry: "some.registry.org/",
							// The test is provider agnostic.
							KubernetesProvider: operatorv1.ProviderNone,
						},
					},
				},
			)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &operatorv1.Compliance{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Status: operatorv1.ComplianceStatus{
					State: operatorv1.TigeraStatusReady,
				},
			})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: common.TigeraPrometheusNamespace},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, render.NewElasticsearchClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ElasticsearchPublicCertSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ElasticsearchManagerUserSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.KibanaPublicCertSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerCertSecret,
					Namespace: render.OperatorNamespace(),
				},
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				Data: map[string][]byte{
					"tls.crt": []byte("crt"),
					"tls.key": []byte("crt"),
				},
			})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ECKLicenseConfigMapName,
					Namespace: render.ECKOperatorNamespace,
				},
				Data: map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterpriseTrial)},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &operatorv1.Manager{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
			})).NotTo(HaveOccurred())
		})
		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-manager",
					Namespace: render.ManagerNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(3))
			mgr := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-manager")
			Expect(mgr).ToNot(BeNil())
			Expect(mgr.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentManager.Image,
					components.ComponentManager.Version)))
			esproxy := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-es-proxy")
			Expect(esproxy).ToNot(BeNil())
			Expect(esproxy.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentEsProxy.Image,
					components.ComponentEsProxy.Version)))
			vltrn := test.GetContainer(d.Spec.Template.Spec.Containers, render.VoltronName)
			Expect(vltrn).ToNot(BeNil())
			Expect(vltrn.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentManagerProxy.Image,
					components.ComponentManagerProxy.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/cnx-manager", Digest: "sha256:cnxmanagerhash"},
						{Image: "tigera/es-proxy", Digest: "sha256:esproxyhash"},
						{Image: "tigera/voltron", Digest: "sha256:voltronhash"},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-manager",
					Namespace: render.ManagerNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(3))
			mgr := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-manager")
			Expect(mgr).ToNot(BeNil())
			Expect(mgr.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentManager.Image,
					"sha256:cnxmanagerhash")))
			esproxy := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-es-proxy")
			Expect(esproxy).ToNot(BeNil())
			Expect(esproxy.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentEsProxy.Image,
					"sha256:esproxyhash")))
			vltrn := test.GetContainer(d.Spec.Template.Spec.Containers, render.VoltronName)
			Expect(vltrn).ToNot(BeNil())
			Expect(vltrn.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentManagerProxy.Image,
					"sha256:voltronhash")))
		})
	})
})
