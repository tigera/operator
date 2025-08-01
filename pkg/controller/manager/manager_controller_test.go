// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/secret"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/monitor"
	tigeratls "github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var _ = Describe("Manager controller tests", func() {
	var c client.Client
	var scheme *runtime.Scheme
	var instance *operatorv1.Manager
	var ctx context.Context
	var replicas int32

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
		replicas = 2
		Expect(c.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}))
	})

	It("should query a default manager instance", func() {
		By("Creating a CRD")
		instance = &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		err := c.Create(ctx, instance)
		Expect(err).NotTo(HaveOccurred())
		instance, err = GetManager(ctx, c, false, "")
		Expect(err).NotTo(HaveOccurred())
	})

	// This test uses a mock client, so ultimately we're just testing that a namespaced `GetManager` call
	// functions correctly
	It("should create and query multiple tenant manager instances", func() {
		tenantANamespace := "tenant-a"
		instanceA := &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure", Namespace: tenantANamespace},
		}
		err := c.Create(ctx, instanceA)
		Expect(err).NotTo(HaveOccurred())
		instance, err = GetManager(ctx, c, true, tenantANamespace)
		Expect(err).NotTo(HaveOccurred())

		tenantBNamespace := "tenant-b"
		instanceB := &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure", Namespace: tenantBNamespace},
		}
		err = c.Create(ctx, instanceB)
		Expect(err).NotTo(HaveOccurred())
		instance, err = GetManager(ctx, c, true, tenantBNamespace)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should return expected error when querying namespace that does not contain a manager instance", func() {
		nsWithoutManager := "non-manager-ns"
		instance, err := GetManager(ctx, c, true, nsWithoutManager)
		Expect(kerror.IsNotFound(err)).To(BeTrue())
		Expect(instance).To(BeNil())
	})

	Context("cert tests", func() {
		var r ReconcileManager
		var cr *operatorv1.Manager
		var mockStatus *status.MockStatus
		var certificateManager certificatemanager.CertificateManager

		clusterDomain := "some.domain"
		expectedDNSNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, clusterDomain)
		expectedDNSNames = append(expectedDNSNames, "localhost")

		BeforeEach(func() {
			// Create an object we can use throughout the test to do the compliance reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCertificateSigningRequests", mock.Anything).Return()
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for secret 'tigera-packetcapture-server-tls' to become available", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for secret 'tigera-secure-linseed-cert' to become available", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for secret 'calico-node-prometheus-tls' to become available", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for secret internal-manager-tls in namespace tigera-operator to be available", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetMetaData", mock.Anything).Return()

			r = ReconcileManager{
				client:          c,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				status:          mockStatus,
				clusterDomain:   clusterDomain,
				licenseAPIReady: &utils.ReadyFlag{},
				tierWatchReady:  &utils.ReadyFlag{},
			}

			Expect(c.Create(ctx, &operatorv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Status: operatorv1.APIServerStatus{
					State: operatorv1.TigeraStatusReady,
				},
			})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
			})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
			})).NotTo(HaveOccurred())
			Expect(c.Create(
				ctx,
				&operatorv1.Installation{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec: operatorv1.InstallationSpec{
						ControlPlaneReplicas: &replicas,
						Variant:              operatorv1.TigeraSecureEnterprise,
						Registry:             "some.registry.org/",
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

			// Provision certificates that the controller will query as part of the test.
			var err error
			certificateManager, err = certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			caSecret := certificateManager.KeyPair().Secret(common.OperatorNamespace())
			Expect(c.Create(ctx, caSecret)).NotTo(HaveOccurred())
			complianceKp, err := certificateManager.GetOrCreateKeyPair(c, render.ComplianceServerCertSecret, common.OperatorNamespace(), []string{render.ComplianceServerCertSecret})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, complianceKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			pcapKp, err := certificateManager.GetOrCreateKeyPair(c, render.PacketCaptureServerCert, common.OperatorNamespace(), []string{render.PacketCaptureServerCert})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, pcapKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			promKp, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusServerTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, promKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			linseedKp, err := certificateManager.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, common.OperatorNamespace(), []string{render.TigeraLinseedSecret})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, linseedKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			queryServerKp, err := certificateManager.GetOrCreateKeyPair(c, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), []string{render.CalicoAPIServerTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, queryServerKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			internalKp, err := certificateManager.GetOrCreateKeyPair(c, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), expectedDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, internalKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      eck.LicenseConfigMapName,
					Namespace: eck.OperatorNamespace,
				},
				Data: map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterpriseTrial)},
			})).NotTo(HaveOccurred())

			cr = &operatorv1.Manager{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
			}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			// Mark that watches were successful.
			r.licenseAPIReady.MarkAsReady()
			r.tierWatchReady.MarkAsReady()
		})

		It("should create an internal manager TLS cert secret", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			internalManagerTLSSecret := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ManagerInternalTLSSecretName,
					Namespace: common.OperatorNamespace(),
				},
			}
			dnsNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, clusterDomain)
			dnsNames = append(dnsNames, "localhost")
			Expect(test.GetResource(c, internalManagerTLSSecret)).To(BeNil())
			test.VerifyCert(internalManagerTLSSecret, dnsNames...)
		})

		It("should replace the internal manager TLS cert secret if its DNS names are invalid", func() {
			// Update the internal manager TLS secret with old DNS name.
			oldKp, err := certificateManager.GetOrCreateKeyPair(c, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{"tigera-manager.tigera-manager.svc"})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Update(ctx, oldKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			internalManagerTLSSecret := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ManagerInternalTLSSecretName,
					Namespace: common.OperatorNamespace(),
				},
			}

			dnsNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, clusterDomain)
			dnsNames = append(dnsNames, "localhost")
			Expect(test.GetResource(c, internalManagerTLSSecret)).To(BeNil())
			test.VerifyCert(internalManagerTLSSecret, dnsNames...)
		})

		It("should reconcile if user supplied a manager TLS cert", func() {
			// Create a manager cert secret.
			dnsNames := []string{"manager.example.com", "192.168.10.22"}
			testCA := test.MakeTestCA("manager-test")
			userSecret, err := secret.CreateTLSSecret(
				testCA, render.ManagerTLSSecretName, common.OperatorNamespace(), corev1.TLSPrivateKeyKey, corev1.TLSCertKey, tigeratls.DefaultCertificateDuration, nil, dnsNames...)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, userSecret)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify that the existing cert didn't change
			secret := &corev1.Secret{}
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.Data).To(Equal(userSecret.Data))

			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: render.ManagerNamespace}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.Data).To(Equal(userSecret.Data))

			// Check that the internal secret was copied over to the manager namespace
			internalSecret := &corev1.Secret{}
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerInternalTLSSecretName, Namespace: render.ManagerNamespace}, internalSecret)).ShouldNot(HaveOccurred())
		})

		It("should create a manager TLS cert secret if not provided and add an OwnerReference to it", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

			// Check that the internal secret was copied over to the manager namespace
			internalSecret := &corev1.Secret{}
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerInternalTLSSecretName, Namespace: render.ManagerNamespace}, internalSecret)).ShouldNot(HaveOccurred())
		})

		It("should not add OwnerReference to an user supplied manager TLS cert", func() {
			// Create a manager cert secret.
			dnsNames := []string{"manager.example.com", "192.168.10.22"}
			testCA := test.MakeTestCA("manager-test")
			userSecret, err := secret.CreateTLSSecret(
				testCA, render.ManagerTLSSecretName, common.OperatorNamespace(), corev1.TLSPrivateKeyKey, corev1.TLSCertKey, tigeratls.DefaultCertificateDuration, nil, dnsNames...)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, userSecret)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify that the existing cert didn't get an owner reference
			secret := &corev1.Secret{}
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(0))

			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: render.ManagerNamespace}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

			// Check that the internal secret was copied over to the manager namespace
			internalSecret := &corev1.Secret{}
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerInternalTLSSecretName, Namespace: render.ManagerNamespace}, internalSecret)).ShouldNot(HaveOccurred())
		})

		It("should reconcile if operator-managed cert exists and user replaces it with a custom cert", func() {
			// Reconcile and check that the operator managed cert was created
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			// Verify that the operator managed cert secrets exist. These cert
			// secrets should have the manager service DNS names plus localhost only.
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, []string{"localhost"}...)

			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: render.ManagerNamespace}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, []string{"localhost"}...)

			// Check that the internal secret was copied over to the manager namespace
			internalSecret := &corev1.Secret{}
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerInternalTLSSecretName, Namespace: render.ManagerNamespace}, internalSecret)).ShouldNot(HaveOccurred())

			// Create a custom manager cert secret.
			dnsNames := []string{"manager.example.com", "192.168.10.22"}
			testCA := test.MakeTestCA("manager-test")
			customSecret, err := rsecret.CreateTLSSecret(
				testCA, render.ManagerTLSSecretName, common.OperatorNamespace(), corev1.TLSPrivateKeyKey, corev1.TLSCertKey, tigeratls.DefaultCertificateDuration, nil, dnsNames...)
			Expect(err).ShouldNot(HaveOccurred())

			// Update the existing operator managed cert secret with bytes from
			// the custom manager cert secret.
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			secret.Data[corev1.TLSCertKey] = customSecret.Data[corev1.TLSCertKey]
			secret.Data[corev1.TLSPrivateKeyKey] = customSecret.Data[corev1.TLSPrivateKeyKey]
			Expect(c.Update(ctx, secret)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Verify that the existing certs have changed - check that the
			// certs have the DNS names in the user-supplied cert.
			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, dnsNames...)

			Expect(c.Get(ctx, types.NamespacedName{Name: render.ManagerTLSSecretName, Namespace: render.ManagerNamespace}, secret)).ShouldNot(HaveOccurred())
			test.VerifyCert(secret, dnsNames...)
		})

		It("should replace the internal manager TLS cert secret if its DNS names are invalid", func() {
			internalTLS := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ManagerInternalTLSSecretName,
					Namespace: common.OperatorNamespace(),
				},
			}
			Expect(c.Delete(ctx, internalTLS)).NotTo(HaveOccurred())
			// Create a internal manager TLS secret with old DNS name.
			oldKp, err := certificateManager.GetOrCreateKeyPair(c, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{"tigera-manager.tigera-manager.svc"})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, oldKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			dnsNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, clusterDomain)
			Expect(test.GetResource(c, internalTLS)).To(BeNil())
			test.VerifyCert(internalTLS, dnsNames...)
		})
	})

	Context("reconciliation", func() {
		var r ReconcileManager
		var mockStatus *status.MockStatus
		var licenseKey *v3.LicenseKey
		var compliance *operatorv1.Compliance
		var certificateManager certificatemanager.CertificateManager
		var installation *operatorv1.Installation

		BeforeEach(func() {
			// Create an object we can use throughout the test to do the compliance reconcile loops.
			mockStatus = &status.MockStatus{}

			r = ReconcileManager{
				client:          c,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				status:          mockStatus,
				licenseAPIReady: &utils.ReadyFlag{},
				tierWatchReady:  &utils.ReadyFlag{},
			}

			Expect(c.Create(ctx, &operatorv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Status: operatorv1.APIServerStatus{
					State: operatorv1.TigeraStatusReady,
				},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
			})).NotTo(HaveOccurred())

			licenseKey = &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status: v3.LicenseKeyStatus{
					Features: []string{
						common.ComplianceFeature,
					},
				},
			}
			Expect(c.Create(ctx, licenseKey)).NotTo(HaveOccurred())

			installation = &operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.InstallationSpec{
					ControlPlaneReplicas: &replicas,
					Variant:              operatorv1.TigeraSecureEnterprise,
					Registry:             "some.registry.org/",
					ImagePullSecrets: []corev1.LocalObjectReference{{
						Name: "tigera-pull-secret",
					}},
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.TigeraSecureEnterprise,
					Computed: &operatorv1.InstallationSpec{
						Registry: "some.registry.org/",
						// The test is provider agnostic.
						KubernetesProvider: operatorv1.ProviderNone,
						ImagePullSecrets: []corev1.LocalObjectReference{{
							Name: "tigera-pull-secret",
						}},
					},
				},
			}
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			pullSecrets := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()}}
			Expect(c.Create(ctx, pullSecrets)).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: common.TigeraPrometheusNamespace},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      eck.LicenseConfigMapName,
					Namespace: eck.OperatorNamespace,
				},
				Data: map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterpriseTrial)},
			})).NotTo(HaveOccurred())
		})

		Context("single-tenant", func() {
			BeforeEach(func() {
				mockStatus.On("AddDaemonsets", mock.Anything).Return()
				mockStatus.On("AddDeployments", mock.Anything).Return()
				mockStatus.On("AddStatefulSets", mock.Anything).Return()
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("IsAvailable").Return(true)
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("ClearDegraded")
				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", mock.Anything, mock.Anything).Return().Maybe()
				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for secret 'calico-node-prometheus-tls' to become available", mock.Anything, mock.Anything).Return().Maybe()
				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for secret 'tigera-packetcapture-server-tls' to become available", mock.Anything, mock.Anything).Return().Maybe()
				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for secret 'tigera-secure-linseed-cert' to become available", mock.Anything, mock.Anything).Return().Maybe()
				mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for secret internal-manager-tls in namespace tigera-operator to be available", mock.Anything, mock.Anything).Return().Maybe()
				mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
				mockStatus.On("ReadyToMonitor")
				mockStatus.On("SetMetaData", mock.Anything).Return()

				compliance = &operatorv1.Compliance{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Status: operatorv1.ComplianceStatus{
						State: operatorv1.TigeraStatusReady,
					},
				}
				Expect(c.Create(ctx, compliance)).NotTo(HaveOccurred())

				// Provision certificates that the controller will query as part of the test.
				var err error
				certificateManager, err = certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
				Expect(err).NotTo(HaveOccurred())
				caSecret := certificateManager.KeyPair().Secret(common.OperatorNamespace())
				Expect(c.Create(ctx, caSecret)).NotTo(HaveOccurred())
				complianceKp, err := certificateManager.GetOrCreateKeyPair(c, render.ComplianceServerCertSecret, common.OperatorNamespace(), []string{render.ComplianceServerCertSecret})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, complianceKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
				pcapKp, err := certificateManager.GetOrCreateKeyPair(c, render.PacketCaptureServerCert, common.OperatorNamespace(), []string{render.PacketCaptureServerCert})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, pcapKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
				promKp, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusServerTLSSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, promKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
				linseedKp, err := certificateManager.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, common.OperatorNamespace(), []string{render.TigeraLinseedSecret})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, linseedKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
				queryServerKp, err := certificateManager.GetOrCreateKeyPair(c, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), []string{render.CalicoAPIServerTLSSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, queryServerKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
				internalCertKp, err := certificateManager.GetOrCreateKeyPair(c, render.ManagerInternalTLSSecretName, common.OperatorNamespace(), []string{render.ManagerInternalTLSSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, internalCertKp.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

				Expect(c.Create(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())

				Expect(c.Create(ctx, &operatorv1.Manager{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
				})).NotTo(HaveOccurred())

				// Mark that watches were successful.
				r.licenseAPIReady.MarkAsReady()
				r.tierWatchReady.MarkAsReady()
			})

			It("should reconcile manager namespace, role bindings and pull secrets", func() {
				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(0 * time.Second))

				namespace := corev1.Namespace{
					TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
				}
				Expect(c.Get(ctx, client.ObjectKey{
					Name: render.ManagerNamespace,
				}, &namespace)).NotTo(HaveOccurred())
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("restricted"))
				Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

				// Expect operator rolebinding to be created
				rb := rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{},
				}
				Expect(c.Get(ctx, client.ObjectKey{
					Name:      render.TigeraOperatorSecrets,
					Namespace: render.ManagerNamespace,
				}, &rb)).NotTo(HaveOccurred())
				Expect(rb.OwnerReferences).To(HaveLen(1))
				ownerRoleBinding := rb.OwnerReferences[0]
				Expect(ownerRoleBinding.Kind).To(Equal("Manager"))

				// Expect pull secrets to be created
				pullSecrets := corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				}
				Expect(c.Get(ctx, client.ObjectKey{
					Name:      "tigera-pull-secret",
					Namespace: render.ManagerNamespace,
				}, &pullSecrets)).NotTo(HaveOccurred())
				Expect(pullSecrets.OwnerReferences).To(HaveLen(1))
				pullSecret := pullSecrets.OwnerReferences[0]
				Expect(pullSecret.Kind).To(Equal("Manager"))
			})

			Context("image reconciliation", func() {
				It("should use builtin images", func() {
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
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
					uiAPIContainer := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-ui-apis")
					Expect(uiAPIContainer).ToNot(BeNil())
					Expect(uiAPIContainer.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s:%s",
							components.ComponentUIAPIs.Image,
							components.ComponentUIAPIs.Version)))
					vltrn := test.GetContainer(d.Spec.Template.Spec.Containers, render.VoltronName)
					Expect(vltrn).ToNot(BeNil())
					Expect(vltrn.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s:%s",
							components.ComponentManagerProxy.Image,
							components.ComponentManagerProxy.Version)))
				})
				It("should use images from imageset", func() {
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
					Expect(c.Create(ctx, &operatorv1.ImageSet{
						ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
						Spec: operatorv1.ImageSetSpec{
							Images: []operatorv1.Image{
								{Image: "tigera/manager", Digest: "sha256:managerhash"},
								{Image: "tigera/ui-apis", Digest: "sha256:uiapihash"},
								{Image: "tigera/voltron", Digest: "sha256:voltronhash"},
								{Image: "tigera/key-cert-provisioner", Digest: "sha256:deadbeef0123456789"},
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
							"sha256:managerhash")))
					uiAPIContainer := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-ui-apis")
					Expect(uiAPIContainer).ToNot(BeNil())
					Expect(uiAPIContainer.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s@%s",
							components.ComponentUIAPIs.Image,
							"sha256:uiapihash")))
					vltrn := test.GetContainer(d.Spec.Template.Spec.Containers, render.VoltronName)
					Expect(vltrn).ToNot(BeNil())
					Expect(vltrn.Image).To(Equal(
						fmt.Sprintf("some.registry.org/%s@%s",
							components.ComponentManagerProxy.Image,
							"sha256:voltronhash")))
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
					r = ReconcileManager{
						client:          c,
						scheme:          scheme,
						provider:        operatorv1.ProviderNone,
						status:          mockStatus,
						licenseAPIReady: readyFlag,
						tierWatchReady:  readyFlag,
					}
				})

				It("should wait if allow-tigera tier is unavailable", func() {
					test.DeleteAllowTigeraTierAndExpectWait(ctx, c, &r, mockStatus)
				})

				It("should wait if tier watch is not ready", func() {
					r.tierWatchReady = &utils.ReadyFlag{}
					test.ExpectWaitForTierWatch(ctx, &r, mockStatus)
				})
			})

			Context("manager reconciliation", func() {
				It("should degrade if license is not present", func() {
					Expect(c.Delete(ctx, licenseKey)).NotTo(HaveOccurred())
					mockStatus = &status.MockStatus{}
					mockStatus.On("OnCRFound").Return()
					mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, "License not found", "licensekeies.projectcalico.org \"default\" not found", mock.Anything).Return()
					mockStatus.On("SetMetaData", mock.Anything).Return()
					r.status = mockStatus

					_, err := r.Reconcile(ctx, reconcile.Request{})

					Expect(err).NotTo(HaveOccurred())
					mockStatus.AssertExpectations(GinkgoT())
				})

				It("should degrade if compliance CR and compliance-enabled license is present, but compliance is not ready", func() {
					compliance.Status.State = ""
					Expect(c.Status().Update(ctx, compliance)).NotTo(HaveOccurred())
					mockStatus = &status.MockStatus{}
					mockStatus.On("OnCRFound").Return()
					mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Compliance is not ready", mock.Anything, mock.Anything).Return()
					mockStatus.On("SetMetaData", mock.Anything).Return()
					r.status = mockStatus

					_, err := r.Reconcile(ctx, reconcile.Request{})

					Expect(err).NotTo(HaveOccurred())
					mockStatus.AssertExpectations(GinkgoT())
				})

				DescribeTable("should not degrade when compliance CR or compliance license feature is not present/active", func(crPresent, licenseFeatureActive bool) {
					mockStatus = &status.MockStatus{}
					mockStatus.On("IsAvailable").Return(true)
					mockStatus.On("OnCRFound").Return()
					mockStatus.On("AddDeployments", mock.Anything)
					mockStatus.On("ClearDegraded")
					mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Compliance is not ready", mock.Anything, mock.Anything).Return().Maybe()
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
					mockStatus.On("ReadyToMonitor")
					mockStatus.On("SetMetaData", mock.Anything).Return()
					r.status = mockStatus

					if !crPresent {
						Expect(c.Delete(ctx, compliance)).NotTo(HaveOccurred())
					}
					if !licenseFeatureActive {
						licenseKey.Status.Features = []string{}
						Expect(c.Update(ctx, licenseKey)).NotTo(HaveOccurred())
					}

					_, err := r.Reconcile(ctx, reconcile.Request{})

					// Expect no error, and no degraded status from compliance
					Expect(err).NotTo(HaveOccurred())
					mockStatus.AssertExpectations(GinkgoT())
				},
					Entry("CR and license feature not present/active", false, false),
					Entry("CR not present, license feature active", false, true),
					Entry("CR present, license feature inactive", true, false),
				)
			})

			Context("Reconcile for Condition status", func() {
				generation := int64(2)
				It("should reconcile with creating new status condition with one item", func() {
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
					ts := &operatorv1.TigeraStatus{
						ObjectMeta: metav1.ObjectMeta{Name: "manager"},
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
						Name:      "manager",
						Namespace: "",
					}})
					Expect(err).ShouldNot(HaveOccurred())
					instance, err := GetManager(ctx, r.client, false, "")
					Expect(err).ShouldNot(HaveOccurred())

					Expect(instance.Status.Conditions).To(HaveLen(1))
					Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
					Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
					Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
					Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
					Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
				})
				It("should reconcile with empty tigerastatus conditions ", func() {
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
					ts := &operatorv1.TigeraStatus{
						ObjectMeta: metav1.ObjectMeta{Name: "manager"},
						Spec:       operatorv1.TigeraStatusSpec{},
						Status:     operatorv1.TigeraStatusStatus{},
					}
					Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

					_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
						Name:      "manager",
						Namespace: "",
					}})
					Expect(err).ShouldNot(HaveOccurred())
					instance, err := GetManager(ctx, r.client, false, "")
					Expect(err).ShouldNot(HaveOccurred())

					Expect(instance.Status.Conditions).To(HaveLen(0))
				})

				It("should reconcile with creating new status condition  with multiple conditions as true", func() {
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
					ts := &operatorv1.TigeraStatus{
						ObjectMeta: metav1.ObjectMeta{Name: "manager"},
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
						Name:      "manager",
						Namespace: "",
					}})
					Expect(err).ShouldNot(HaveOccurred())
					instance, err := GetManager(ctx, r.client, false, "")
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
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
					ts := &operatorv1.TigeraStatus{
						ObjectMeta: metav1.ObjectMeta{Name: "manager"},
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
						Name:      "manager",
						Namespace: "",
					}})
					Expect(err).ShouldNot(HaveOccurred())
					instance, err := GetManager(ctx, r.client, false, "")
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

			Context("Multi-cluster reconciliation", func() {
				It("Should reconcile multi-cluster setup for a management cluster for a single tenant", func() {
					// Create the ManagementCluster CR needed to configure
					// a management cluster for a multi-cluster setup
					managementCluster := &operatorv1.ManagementCluster{
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
						},
					}
					Expect(c.Create(ctx, managementCluster)).NotTo(HaveOccurred())

					// Create the Manager CR needed to jumpstart the reconciliation
					// for the manager
					err := c.Create(ctx, &operatorv1.Manager{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "tigera-secure",
							Namespace: common.OperatorNamespace(),
						},
					})
					Expect(err).NotTo(HaveOccurred())

					// Reconcile Manager
					_, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					deployment := appsv1.Deployment{
						TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "tigera-manager",
							Namespace: render.ManagerNamespace,
						},
					}
					clusterConnection := corev1.Secret{
						TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.VoltronTunnelSecretName,
							Namespace: common.OperatorNamespace(),
						},
					}
					clusterConnectionInManagerNs := corev1.Secret{
						TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.VoltronTunnelSecretName,
							Namespace: render.ManagerNamespace,
						},
					}

					// Ensure a deployment was created for the manager
					err = test.GetResource(c, &deployment)
					Expect(kerror.IsNotFound(err)).Should(BeFalse())

					// Ensure the secret was created in tigera-operator namespace
					// and that it configures voltron as a Subject Alternate Name
					err = test.GetResource(c, &clusterConnection)
					Expect(kerror.IsNotFound(err)).Should(BeFalse())
					assertSANs(&clusterConnection, "voltron")

					// Ensure the secret was created in tigera-manager namespace
					// and that it configures voltron as a Subject Alternate Name
					err = test.GetResource(c, &clusterConnectionInManagerNs)
					Expect(kerror.IsNotFound(err)).Should(BeFalse())
					assertSANs(&clusterConnectionInManagerNs, "voltron")
				})

				It("should upgrade a Voltron tunnel secret if previously owned by a different controller", func() {
					// Older versions of the tigera-operator controlled this secret from the API server controller.
					// However, only a single controller is allowed as an owner, so we need to properly clear the old
					// one before setting the Manager CR as the new owner.
					clusterConnection := corev1.Secret{
						TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      render.VoltronTunnelSecretName,
							Namespace: common.OperatorNamespace(),
						},
					}
					clusterConnectionInManagerNs := clusterConnection
					clusterConnectionInManagerNs.Namespace = render.ManagerNamespace

					apiserver := &operatorv1.APIServer{
						TypeMeta: metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
							UID:  "1234",
						},
					}
					err := controllerutil.SetControllerReference(apiserver, &clusterConnection, scheme)
					Expect(err).NotTo(HaveOccurred())
					err = controllerutil.SetControllerReference(apiserver, &clusterConnectionInManagerNs, scheme)
					Expect(err).NotTo(HaveOccurred())
					Expect(c.Create(ctx, &clusterConnection)).NotTo(HaveOccurred())
					Expect(c.Create(ctx, &clusterConnectionInManagerNs)).NotTo(HaveOccurred())

					// Run the controller. It should update the secret to be owned by the Manager CR.
					// Create the ManagementCluster CR needed to configure
					// a management cluster for a multi-cluster setup
					managementCluster := &operatorv1.ManagementCluster{
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
						},
					}
					Expect(c.Create(ctx, managementCluster)).NotTo(HaveOccurred())

					// Create the Manager CR needed to jumpstart the reconciliation
					// for the manager
					manager := &operatorv1.Manager{
						TypeMeta: metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "tigera-secure",
							Namespace: common.OperatorNamespace(),
						},
					}
					err = c.Create(ctx, manager)
					Expect(err).NotTo(HaveOccurred())

					// Reconcile Manager
					_, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					// Check the owner reference on the secret has updated.
					Expect(c.Get(ctx, types.NamespacedName{Name: render.VoltronTunnelSecretName, Namespace: common.OperatorNamespace()}, &clusterConnection)).NotTo(HaveOccurred())
					Expect(len(clusterConnection.OwnerReferences)).To(Equal(1))
					Expect(clusterConnection.OwnerReferences[0].Kind).To(Equal("Manager"))
				})
			})

			Context("FIPS reconciliation", func() {
				BeforeEach(func() {
					fipsEnabled := operatorv1.FIPSModeEnabled
					installation.Spec.FIPSMode = &fipsEnabled
					Expect(c.Update(
						ctx,
						installation,
					)).NotTo(HaveOccurred())
				})
				It("should not require presence of ElasticSearch ConfigMap", func() {
					Expect(c.Delete(ctx, relasticsearch.NewClusterConfig("cluster", 1, 1, 1).ConfigMap())).NotTo(HaveOccurred())
					elasticConfigMapKey := client.ObjectKey{
						Name:      relasticsearch.ClusterConfigConfigMapName,
						Namespace: common.OperatorNamespace(),
					}
					elasticConfigMap := corev1.ConfigMap{}
					Expect(c.Get(ctx, elasticConfigMapKey, &elasticConfigMap)).To(HaveOccurred())

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("non-cluster host", func() {
				It("should read NonClusterHost resource", func() {
					nonclusterhost := &operatorv1.NonClusterHost{
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
						},
						Spec: operatorv1.NonClusterHostSpec{
							Endpoint: "https://1.2.3.4:5678",
						},
					}
					Expect(c.Create(ctx, nonclusterhost)).NotTo(HaveOccurred())

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).NotTo(HaveOccurred())

					d := appsv1.Deployment{
						TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "tigera-manager",
							Namespace: render.ManagerNamespace,
						},
					}
					Expect(test.GetResource(c, &d)).To(BeNil())
					Expect(d.Spec.Template.Spec.Containers).To(HaveLen(3))
					voltron := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-voltron")
					Expect(voltron).NotTo(BeNil())
					Expect(voltron.Env).To(ContainElement(corev1.EnvVar{Name: "VOLTRON_ENABLE_NONCLUSTER_HOST", Value: "true"}))
				})

				It("should return error when endpoint is invalid", func() {
					mockStatus.On("SetDegraded", operatorv1.ResourceReadError, "Failed to read parse endpoint from NonClusterHost resource", mock.Anything, mock.Anything).Return().Maybe()

					nonclusterhost := &operatorv1.NonClusterHost{
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
						},
						Spec: operatorv1.NonClusterHostSpec{
							Endpoint: "invalid-endpoint-url",
						},
					}
					Expect(c.Create(ctx, nonclusterhost)).NotTo(HaveOccurred())

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).To(HaveOccurred())
				})

				It("should return error when spec is missing from the NonClusterHost resource", func() {
					mockStatus.On("SetDegraded", operatorv1.ResourceReadError, "Failed to read parse endpoint from NonClusterHost resource", mock.Anything, mock.Anything).Return().Maybe()

					nonclusterhost := &operatorv1.NonClusterHost{
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
						},
					}
					Expect(c.Create(ctx, nonclusterhost)).NotTo(HaveOccurred())

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).To(HaveOccurred())
				})
			})
		})

		Context("multi-tenant", func() {
			tenantANamespace := "tenant-a"
			tenantBNamespace := "tenant-b"

			BeforeEach(func() {
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("SetMetaData", mock.Anything).Return()
				mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
				mockStatus.On("AddDeployments", mock.Anything).Return()
				mockStatus.On("ReadyToMonitor")
				mockStatus.On("ClearDegraded")
				mockStatus.On("IsAvailable").Return(true)

				r.multiTenant = true
				r.licenseAPIReady.MarkAsReady()
				r.tierWatchReady.MarkAsReady()

				// Create the Tenant resources for tenant-a and tenant-b.
				tenantA := &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: tenantANamespace,
					},
					Spec: operatorv1.TenantSpec{ID: "tenant-a"},
				}
				Expect(c.Create(ctx, tenantA)).NotTo(HaveOccurred())
				tenantB := &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: tenantBNamespace,
					},
					Spec: operatorv1.TenantSpec{ID: "tenant-b"},
				}
				Expect(c.Create(ctx, tenantB)).NotTo(HaveOccurred())

				managementCluster := &operatorv1.ManagementCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
				}
				Expect(c.Create(ctx, managementCluster)).NotTo(HaveOccurred())

				certificateManagerTenantA, err := certificatemanager.Create(c, nil, "", tenantANamespace, certificatemanager.AllowCACreation(), certificatemanager.WithTenant(tenantA))
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, certificateManagerTenantA.KeyPair().Secret(tenantANamespace)))
				managerTLSTenantA, err := certificateManagerTenantA.GetOrCreateKeyPair(c, render.ManagerInternalTLSSecretName, tenantANamespace, []string{render.ManagerInternalTLSSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, managerTLSTenantA.Secret(tenantANamespace))).NotTo(HaveOccurred())
				bundleA, err := certificateManagerTenantA.CreateMultiTenantTrustedBundleWithSystemRootCertificates()
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, bundleA.ConfigMap(tenantANamespace))).NotTo(HaveOccurred())

				certificateManagerTenantB, err := certificatemanager.Create(c, nil, "", tenantBNamespace, certificatemanager.AllowCACreation(), certificatemanager.WithTenant(tenantB))
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, certificateManagerTenantB.KeyPair().Secret(tenantBNamespace)))
				managerTLSTenantB, err := certificateManagerTenantB.GetOrCreateKeyPair(c, render.ManagerInternalTLSSecretName, tenantBNamespace, []string{render.ManagerInternalTLSSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, managerTLSTenantB.Secret(tenantBNamespace))).NotTo(HaveOccurred())
				bundleB, err := certificateManagerTenantB.CreateMultiTenantTrustedBundleWithSystemRootCertificates()
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, bundleB.ConfigMap(tenantBNamespace))).NotTo(HaveOccurred())

				err = c.Create(ctx, &operatorv1.Manager{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-secure",
						Namespace: tenantANamespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())

				err = c.Create(ctx, &operatorv1.Manager{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-secure",
						Namespace: tenantBNamespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should reconcile only if a namespace is provided", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				tenantADeployment := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-manager",
						Namespace: tenantANamespace,
					},
				}
				tenantAClusterConnection := corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.VoltronTunnelSecretName,
						Namespace: tenantANamespace,
					},
				}

				tenantBDeployment := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-manager",
						Namespace: tenantBNamespace,
					},
				}
				tenantBClusterConnection := corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.VoltronTunnelSecretName,
						Namespace: tenantBNamespace,
					},
				}
				clusterRoleBinding := rbacv1.ClusterRoleBinding{
					TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name: render.ManagerClusterRoleBinding,
					},
				}

				// We called Reconcile without specifying a namespace, so neither of these namespaced deployments should
				// exist yet
				err = test.GetResource(c, &tenantADeployment)
				Expect(kerror.IsNotFound(err)).Should(BeTrue())

				err = test.GetResource(c, &tenantBDeployment)
				Expect(kerror.IsNotFound(err)).Should(BeTrue())

				// Now reconcile only tenant A's namespace and check that its deployment exists, but tenant B's deployment
				// still hasn't been reconciled so it should still not exist
				result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantANamespace}})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))

				err = test.GetResource(c, &tenantADeployment)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())

				// Ensure the secret was created in tenant namespace
				// and that it configures the tenant ID as a Subject Alternate Name
				err = test.GetResource(c, &tenantAClusterConnection)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())
				assertSANs(&tenantAClusterConnection, "tenant-a")

				err = test.GetResource(c, &tenantBDeployment)
				Expect(kerror.IsNotFound(err)).Should(BeTrue())

				// Now reconcile tenant B's namespace and check that its deployment exists now alongside tenant A's
				_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantBNamespace}})
				Expect(err).ShouldNot(HaveOccurred())

				err = test.GetResource(c, &tenantADeployment)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())

				// Ensure the secret was created in tenant namespace
				// and that it configures the tenant ID as a Subject Alternate Name
				err = test.GetResource(c, &tenantBClusterConnection)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())
				assertSANs(&tenantBClusterConnection, "tenant-b")

				err = test.GetResource(c, &tenantBDeployment)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())

				// Ensure a cluster role binding was created that binds both tenants,
				err = test.GetResource(c, &clusterRoleBinding)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())
				Expect(clusterRoleBinding.Subjects).To(HaveLen(2))
			})

			Context("with both OSS and Enterprise managed clusters", func() {
				tenantCNamespace := "tenant-c"

				BeforeEach(func() {
					// Create a third tenant that manages a Calico OSS cluster.
					tenantC := &operatorv1.Tenant{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "default",
							Namespace: tenantCNamespace,
						},
						Spec: operatorv1.TenantSpec{
							ID:                    "tenant-c",
							ManagedClusterVariant: &operatorv1.Calico,
						},
					}
					Expect(c.Create(ctx, tenantC)).NotTo(HaveOccurred())

					// Create certificates for this tenant.
					certificateManagerTenantC, err := certificatemanager.Create(c, nil, "", tenantCNamespace, certificatemanager.AllowCACreation(), certificatemanager.WithTenant(tenantC))
					Expect(err).NotTo(HaveOccurred())
					Expect(c.Create(ctx, certificateManagerTenantC.KeyPair().Secret(tenantCNamespace)))
					managerTLStenantC, err := certificateManagerTenantC.GetOrCreateKeyPair(c, render.ManagerInternalTLSSecretName, tenantCNamespace, []string{render.ManagerInternalTLSSecretName})
					Expect(err).NotTo(HaveOccurred())
					Expect(c.Create(ctx, managerTLStenantC.Secret(tenantCNamespace))).NotTo(HaveOccurred())
					bundleB, err := certificateManagerTenantC.CreateMultiTenantTrustedBundleWithSystemRootCertificates()
					Expect(err).NotTo(HaveOccurred())
					Expect(c.Create(ctx, bundleB.ConfigMap(tenantCNamespace))).NotTo(HaveOccurred())

					// Create a Manager instance for it.
					err = c.Create(ctx, &operatorv1.Manager{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "tigera-secure",
							Namespace: tenantCNamespace,
						},
					})
					Expect(err).NotTo(HaveOccurred())
				})

				It("should reconcile distinct RBAC for OSS and Enterprise managed clusters", func() {
					// Reconcile the OSS tenant - tenant-c - and verify.
					result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantCNamespace}})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).To(Equal(reconcile.Result{}))

					ossClusterRolebinding := rbacv1.ClusterRoleBinding{
						TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name: render.ManagerManagedCalicoClusterRoleBinding,
						},
					}
					err = test.GetResource(c, &ossClusterRolebinding)
					Expect(kerror.IsNotFound(err)).Should(BeFalse())
					Expect(ossClusterRolebinding.Subjects).To(HaveLen(1))
					Expect(ossClusterRolebinding.Subjects[0].Name).To(Equal("tigera-manager"))
					Expect(ossClusterRolebinding.Subjects[0].Namespace).To(Equal(tenantCNamespace))
					Expect(ossClusterRolebinding.RoleRef.Name).To(Equal("tigera-manager-managed-calico"))

					// The cluster role should exist too.
					ossClusterRole := rbacv1.ClusterRole{
						TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name: render.ManagerManagedCalicoClusterRole,
						},
					}
					err = test.GetResource(c, &ossClusterRole)
					Expect(kerror.IsNotFound(err)).Should(BeFalse())

					// Reconcile tenant-b (the enterprise tenant) and verify.
					result, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantBNamespace}})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(result).To(Equal(reconcile.Result{}))

					// It should have an entry for tenant-a and tenant-b, but not tenant-c.
					clusterRoleBinding := rbacv1.ClusterRoleBinding{
						TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "v1"},
						ObjectMeta: metav1.ObjectMeta{
							Name: render.ManagerClusterRoleBinding,
						},
					}
					err = test.GetResource(c, &clusterRoleBinding)
					Expect(kerror.IsNotFound(err)).Should(BeFalse())
					Expect(clusterRoleBinding.Subjects).To(HaveLen(2))
					for _, sub := range clusterRoleBinding.Subjects {
						Expect(sub.Namespace).NotTo(Equal(tenantCNamespace))
					}
				})
			})

			It("should apply TLSRoutes in from the manager namespace", func() {
				Expect(c.Create(ctx, &operatorv1.TLSTerminatedRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: tenantANamespace,
						Name:      "tenant-a-route",
					},
					Spec: operatorv1.TLSTerminatedRouteSpec{
						CABundle: &corev1.ConfigMapKeySelector{
							Key: certificatemanagement.TrustedCertConfigMapKeyName,
							LocalObjectReference: corev1.LocalObjectReference{
								Name: certificatemanagement.TrustedCertConfigMapNamePublic,
							},
						},
						Destination: "https://internal.foo.svc",
						PathMatch: &operatorv1.PathMatch{
							Path: "/foo/",
						},
						Target: "UI",
					},
				})).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: tenantANamespace,
					},
				})
				Expect(err).ShouldNot(HaveOccurred())

				_, err = r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: tenantBNamespace,
					},
				})
				Expect(err).ShouldNot(HaveOccurred())

				tenantARoutes := corev1.ConfigMap{
					TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "voltron-routes",
						Namespace: tenantANamespace,
					},
				}
				tenantBRoutes := corev1.ConfigMap{
					TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "voltron-routes",
						Namespace: tenantBNamespace,
					},
				}

				Expect(test.GetResource(c, &tenantARoutes)).ToNot(HaveOccurred())
				Expect(tenantARoutes.Data).ToNot(BeEmpty())

				Expect(kerror.IsNotFound(test.GetResource(c, &tenantBRoutes))).Should(BeTrue())
			})

			It("should reconcile pull secrets and rolebindings", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: tenantANamespace,
					},
				})
				Expect(err).ShouldNot(HaveOccurred())

				// Expect operator role binding to be created
				rb := rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{},
				}
				Expect(c.Get(ctx, client.ObjectKey{
					Name:      render.TigeraOperatorSecrets,
					Namespace: tenantANamespace,
				}, &rb)).NotTo(HaveOccurred())
				Expect(rb.OwnerReferences).To(HaveLen(1))
				ownerRoleBinding := rb.OwnerReferences[0]
				Expect(ownerRoleBinding.Kind).To(Equal("Tenant"))

				// Expect pull secrets to be created
				pullSecrets := corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				}
				Expect(c.Get(ctx, client.ObjectKey{
					Name:      "tigera-pull-secret",
					Namespace: tenantANamespace,
				}, &pullSecrets)).NotTo(HaveOccurred())
				Expect(pullSecrets.OwnerReferences).To(HaveLen(1))
				pullSecret := pullSecrets.OwnerReferences[0]
				Expect(pullSecret.Kind).To(Equal("Tenant"))
			})
		})
	})
})

func assertSANs(secret *corev1.Secret, expectedSAN string) {
	var cert *x509.Certificate

	certPEM := secret.Data[corev1.TLSCertKey]
	keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
	_, err := tls.X509KeyPair(certPEM, keyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	block, _ := pem.Decode(certPEM)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(block).To(Not(BeNil()))

	cert, err = x509.ParseCertificate(block.Bytes)
	Expect(err).ShouldNot(HaveOccurred())

	Expect(cert.DNSNames).To(Equal([]string{expectedSAN}))
}
