// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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

	Context("cert tests", func() {
		var r ReconcileManager
		var cr *operatorv1.Manager
		var mockStatus *status.MockStatus

		clusterDomain := "some.domain"
		expectedDNSNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, clusterDomain)
		expectedDNSNames = append(expectedDNSNames, "localhost")

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
			mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
			mockStatus.On("ReadyToMonitor")

			r = ReconcileManager{
				client:          c,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				status:          mockStatus,
				clusterDomain:   clusterDomain,
				licenseAPIReady: &utils.ReadyFlag{},
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

			Expect(c.Create(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      esgateway.EsGatewayElasticPublicCertSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ElasticsearchManagerUserSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      esgateway.EsGatewayKibanaPublicCertSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerCertSecret,
					Namespace: rmeta.OperatorNamespace(),
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

			cr = &operatorv1.Manager{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
			}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			// mark that the watch for license key was successful
			r.licenseAPIReady.MarkAsReady()
		})

		It("should render a new manager cert if existing cert has invalid DNS names and the cert is operator managed", func() {
			// Create a manager cert managed by the operator.
			ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
			Expect(err).ShouldNot(HaveOccurred())
			oldCert, err := secret.CreateTLSSecret(
				ca, render.ManagerTLSSecretName, rmeta.OperatorNamespace(), render.ManagerSecretKeyName,
				render.ManagerSecretCertName, rmeta.DefaultCertificateDuration, nil, "tigera-manager.tigera-manager.svc")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, oldCert)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			// Verify that certs now have expected DNS names.
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: rmeta.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, render.ManagerSecretKeyName, render.ManagerSecretCertName, expectedDNSNames...)

			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: render.ManagerNamespace}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, render.ManagerSecretKeyName, render.ManagerSecretCertName, expectedDNSNames...)
		})

		It("should reconcile if user supplied a manager TLS cert", func() {
			// Create a manager cert secret.
			dnsNames := []string{"manager.example.com", "192.168.10.22"}
			testCA := test.MakeTestCA("manager-test")
			userSecret, err := secret.CreateTLSSecret(
				testCA, render.ManagerTLSSecretName, rmeta.OperatorNamespace(), render.ManagerSecretKeyName,
				render.ManagerSecretCertName, rmeta.DefaultCertificateDuration, nil, dnsNames...)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, userSecret)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify that the existing cert didn't change
			secret := &corev1.Secret{}
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: rmeta.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.Data).To(Equal(userSecret.Data))

			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: render.ManagerNamespace}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.Data).To(Equal(userSecret.Data))
		})

		It("should reconcile if operator-managed cert exists and user replaces it with a custom cert", func() {
			// Reconcile and check that the operator managed cert was created
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			// Verify that the operator managed cert secrets exist. These cert
			// secrets should have the manager service DNS names plus localhost only.
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: rmeta.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, render.ManagerSecretKeyName, render.ManagerSecretCertName, expectedDNSNames...)

			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: render.ManagerNamespace}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, render.ManagerSecretKeyName, render.ManagerSecretCertName, expectedDNSNames...)

			// Create a custom manager cert secret.
			dnsNames := []string{"manager.example.com", "192.168.10.22"}
			testCA := test.MakeTestCA("manager-test")
			customSecret, err := rsecret.CreateTLSSecret(
				testCA, render.ManagerTLSSecretName, rmeta.OperatorNamespace(), render.ManagerSecretKeyName,
				render.ManagerSecretCertName, rmeta.DefaultCertificateDuration, nil, dnsNames...)
			Expect(err).ShouldNot(HaveOccurred())

			// Update the existing operator managed cert secret with bytes from
			// the custom manager cert secret.
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: rmeta.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			secret.Data[render.ManagerSecretCertName] = customSecret.Data[render.ManagerSecretCertName]
			secret.Data[render.ManagerSecretKeyName] = customSecret.Data[render.ManagerSecretKeyName]
			Expect(c.Update(ctx, secret)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify that the existing certs have changed - check that the
			// certs have the DNS names in the user-supplied cert.
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: rmeta.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, render.ManagerSecretKeyName, render.ManagerSecretCertName, dnsNames...)

			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: render.ManagerNamespace}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, render.ManagerSecretKeyName, render.ManagerSecretCertName, dnsNames...)
		})

		DescribeTable("test combinations with certificate management and BYO tls", func(certificateManagementEnabled, byoTLS, expectDegraded bool) {
			if byoTLS {
				dnsNames := []string{"manager.example.com", "192.168.10.22"}
				testCA := test.MakeTestCA("manager-test")
				userSecret, err := secret.CreateTLSSecret(
					testCA, render.ManagerTLSSecretName, rmeta.OperatorNamespace(), render.ManagerSecretKeyName,
					render.ManagerSecretCertName, rmeta.DefaultCertificateDuration, nil, dnsNames...)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(c.Create(ctx, userSecret)).NotTo(HaveOccurred())
			}
			if certificateManagementEnabled {
				installation := &operatorv1.Installation{}
				Expect(c.Get(ctx, types.NamespacedName{Name: "default", Namespace: ""}, installation))
				installation.Spec.CertificateManagement = &operatorv1.CertificateManagement{}
				Expect(c.Update(ctx, installation)).NotTo(HaveOccurred())
			}
			if expectDegraded {
				mockStatus.On("SetDegraded", mock.Anything, mock.Anything).Return().Once()
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).Should(HaveOccurred())
			} else {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				deploy := &appsv1.Deployment{}
				Expect(c.Get(ctx, types.NamespacedName{Name: "tigera-manager", Namespace: render.ManagerNamespace}, deploy)).ShouldNot(HaveOccurred())

				if certificateManagementEnabled {
					Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
				} else {
					Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(0))
				}
			}
		},
			Entry("Regular flow", false, false, false),
			Entry("Certificate management flow", true, false, false),
			Entry("Self provided TLS", false, true, false),
			Entry("Self provided TLS & certificate management", true, true, true))
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
			mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
			mockStatus.On("ReadyToMonitor")

			r = ReconcileManager{
				client:          c,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				status:          mockStatus,
				licenseAPIReady: &utils.ReadyFlag{},
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

			Expect(c.Create(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      esgateway.EsGatewayElasticPublicCertSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ElasticsearchManagerUserSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      esgateway.EsGatewayKibanaPublicCertSecret,
					Namespace: "tigera-operator"}})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerCertSecret,
					Namespace: rmeta.OperatorNamespace(),
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

			// mark that the watch for license key was successful
			r.licenseAPIReady.MarkAsReady()
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
