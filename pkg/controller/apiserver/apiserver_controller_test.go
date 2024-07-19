// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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

package apiserver

import (
	"context"
	"fmt"
	"time"

	kerror "k8s.io/apimachinery/pkg/api/errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"
)

var _ = Describe("apiserver controller tests", func() {
	var (
		cli                   client.Client
		scheme                *runtime.Scheme
		ctx                   context.Context
		mockStatus            *status.MockStatus
		installation          *operatorv1.Installation
		certificateManagement *operatorv1.CertificateManagement
		apiSecret             *corev1.Secret
	)

	notReady := &utils.ReadyFlag{}
	ready := &utils.ReadyFlag{}
	ready.MarkAsReady()

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Create a CertificateManagement instance for tests that need it.
		ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		Expect(err).NotTo(HaveOccurred())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		certificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		replicas := int32(2)
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
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.TigeraSecureEnterprise,
				Registry:             "some.registry.org/",
			},
		}

		// Apply prerequisites for the basic reconcile to succeed.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		cryptoCA, err := tls.MakeCA("byo-ca")
		Expect(err).NotTo(HaveOccurred())
		apiSecret, err = secret.CreateTLSSecret(cryptoCA, "tigera-apiserver-certs", common.OperatorNamespace(), "key.key", "cert.crt", time.Hour, nil, dns.GetServiceDNSNames(render.ProjectCalicoAPIServerServiceName(operatorv1.TigeraSecureEnterprise), "tigera-system", dns.DefaultClusterDomain)...)
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://localhost:9443",
				OIDC: &operatorv1.AuthenticationOIDC{
					IssuerURL: "https://localhost:9443/dex",
				},
			},
		})).ToNot(HaveOccurred())
		dexSecret, err := secret.CreateTLSSecret(cryptoCA, render.DexTLSSecretName, common.OperatorNamespace(), corev1.TLSPrivateKeyKey, corev1.TLSCertKey, time.Hour, nil, dns.GetServiceDNSNames(render.DexTLSSecretName, render.DexNamespace, dns.DefaultClusterDomain)...)
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, dexSecret)).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-oidc-credentials", Namespace: common.OperatorNamespace()},
			Data: map[string][]byte{
				render.ClientIDSecretField:     []byte("a"),
				render.ClientSecretSecretField: []byte("a"),
				render.RootCASecretField:       []byte(dexSecret.Data[corev1.TLSCertKey]),
			},
		})).ToNot(HaveOccurred())

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("AddCertificateSigningRequests", mock.Anything)
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
	})

	Context("verify reconciliation", func() {
		It("should use builtin images", func() {
			installation.Spec.CertificateManagement = certificateManagement
			Expect(cli.Create(ctx, installation)).To(BeNil())

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-apiserver",
					Namespace: "tigera-system",
				},
			}
			Expect(test.GetResource(cli, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(2))
			apiserver := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-apiserver")
			Expect(apiserver).ToNot(BeNil())
			Expect(apiserver.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentAPIServer.Image,
					components.ComponentAPIServer.Version)))
			qserver := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-queryserver")
			Expect(qserver).ToNot(BeNil())
			Expect(qserver.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentQueryServer.Image,
					components.ComponentQueryServer.Version)))
			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, "calico-apiserver-certs-key-cert-provisioner")
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraCSRInitContainer.Image,
					components.ComponentTigeraCSRInitContainer.Version)))

		})
		It("should use images from imageset", func() {
			installation.Spec.CertificateManagement = certificateManagement
			Expect(cli.Create(ctx, installation)).To(BeNil())

			Expect(cli.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/cnx-apiserver", Digest: "sha256:apiserverhash"},
						{Image: "tigera/cnx-queryserver", Digest: "sha256:queryserverhash"},
						{Image: "tigera/key-cert-provisioner", Digest: "sha256:calicocsrinithash"},
					},
				},
			})).ToNot(HaveOccurred())

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-apiserver",
					Namespace: "tigera-system",
				},
			}
			Expect(test.GetResource(cli, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(2))
			apiserver := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-apiserver")
			Expect(apiserver).ToNot(BeNil())
			Expect(apiserver.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentAPIServer.Image,
					"sha256:apiserverhash")))
			qserver := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-queryserver")
			Expect(qserver).ToNot(BeNil())
			Expect(qserver.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentQueryServer.Image,
					"sha256:queryserverhash")))
			csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, "calico-apiserver-certs-key-cert-provisioner")
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraCSRInitContainer.Image,
					"sha256:calicocsrinithash")))

		})

		It("should not add OwnerReference to user-supplied apiserver TLS cert secrets", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())

			secretName := render.ProjectCalicoAPIServerTLSSecretName(operatorv1.TigeraSecureEnterprise)

			Expect(cli.Create(ctx, apiSecret)).ShouldNot(HaveOccurred())

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				clusterDomain:       dns.DefaultClusterDomain,
				tierWatchReady:      ready,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			apiSecret2 := &corev1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: secretName}, apiSecret2)).ShouldNot(HaveOccurred())
			Expect(apiSecret2.GetOwnerReferences()).To(HaveLen(0))

		})

		It("should add OwnerReference apiserver cert operator managed secrets", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())

			secretName := "tigera-apiserver-certs"

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: secretName}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

		})

		It("should render allow-tigera policy when tier and tier watch are ready", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(1))
			Expect(policies.Items[0].Name).To(Equal("allow-tigera.cnx-apiserver-access"))
		})

		It("should omit allow-tigera policy and not degrade when tier is not ready", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())
			Expect(cli.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})

			Expect(err).ShouldNot(HaveOccurred())
			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should omit allow-tigera policy and not degrade when tier watch is not ready", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      notReady,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})

			Expect(err).ShouldNot(HaveOccurred())
			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should omit allow-tigera policy and not degrade when installation is calico", func() {
			Expect(netv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			installation.Spec.Variant = operatorv1.Calico
			installation.Status.Variant = operatorv1.Calico
			Expect(cli.Create(ctx, installation)).To(BeNil())
			Expect(cli.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: false,
				status:              mockStatus,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})

			Expect(err).ShouldNot(HaveOccurred())
			policies := v3.NetworkPolicyList{}
			Expect(cli.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should create the cert secrets in the correct namespace when migrating from calico to enterprise", func() {
			Expect(netv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			installation.Spec.Variant = operatorv1.TigeraSecureEnterprise
			installation.Status.Variant = operatorv1.Calico
			Expect(cli.Create(ctx, installation)).To(BeNil())
			Expect(cli.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: false,
				status:              mockStatus,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})

			Expect(err).ShouldNot(HaveOccurred())

			certSecret := corev1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-apiserver-certs", Namespace: "tigera-system"}, &certSecret)).ToNot(HaveOccurred())
		})
	})

	Context("Reconcile for Condition status", func() {
		generation := int64(2)
		BeforeEach(func() {
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
		})
		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver"},
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
			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "apiserver",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, _, err := utils.GetAPIServer(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(1))

			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
		})
		It("should reconcile with empty tigerastatus conditions ", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "apiserver",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, _, err := utils.GetAPIServer(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(0))
		})
		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver"},
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
			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "apiserver",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, _, err := utils.GetAPIServer(ctx, r.client)
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
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver"},
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
			r := ReconcileAPIServer{
				client:              cli,
				scheme:              scheme,
				provider:            operatorv1.ProviderNone,
				enterpriseCRDsExist: true,
				status:              mockStatus,
				tierWatchReady:      ready,
			}
			installation.Status.Conditions = []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionStatus(operatorv1.ConditionFalse),
					Reason:             string(operatorv1.NotApplicable),
					Message:            "Not Applicable",
					LastTransitionTime: metav1.NewTime(time.Now()),
				},
				{
					Type:               "Progressing",
					Status:             metav1.ConditionStatus(operatorv1.ConditionTrue),
					LastTransitionTime: metav1.NewTime(time.Now()),
					Reason:             string(operatorv1.ResourceNotReady),
					Message:            "All resources are not available",
				},
				{
					Type:               "Degraded",
					Status:             metav1.ConditionStatus(operatorv1.ConditionFalse),
					Reason:             string(operatorv1.NotApplicable),
					Message:            "Not Applicable",
					LastTransitionTime: metav1.NewTime(time.Now()),
				},
			}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "apiserver",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, _, err := utils.GetAPIServer(ctx, r.client)
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
		Context("Management cluster reconciliation", func() {
			BeforeEach(func() {
				// Create the ManagementCluster CR needed to configure
				// a management cluster for a multi-cluster setup
				managementCluster := &operatorv1.ManagementCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tigera-secure",
					},
					Spec: operatorv1.ManagementClusterSpec{
						TLS: &operatorv1.TLS{
							SecretName: render.VoltronTunnelSecretName,
						},
					},
				}
				Expect(cli.Create(ctx, managementCluster)).NotTo(HaveOccurred())

				// Create the APIServer CR needed to jumpstart the reconciliation
				// for the api server
				err := cli.Create(ctx, &operatorv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-secure",
						Namespace: common.OperatorNamespace(),
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should create management-cluster certificate with old cert keys", func() {
				// Create the tunnel secret in operator namespace
				// In a production cluster, this would be created by Manager controller in tigera-operator namespace
				err := cli.Create(ctx, &corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.VoltronTunnelSecretName,
						Namespace: common.OperatorNamespace(),
					},
					Data: map[string][]byte{
						"cert": []byte("certvalue"),
						"key":  []byte("keyvalue"),
					},
				})
				Expect(err).NotTo(HaveOccurred())

				r := ReconcileAPIServer{
					client:              cli,
					scheme:              scheme,
					provider:            operatorv1.ProviderNone,
					enterpriseCRDsExist: true,
					status:              mockStatus,
					tierWatchReady:      ready,
					multiTenant:         false,
				}

				// Reconcile the API server
				_, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				clusterConnectionInAppNs := corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.VoltronTunnelSecretName,
						Namespace: "tigera-system",
					},
				}

				// Ensure that the tunnel secret was copied in tigera-system namespace
				err = test.GetResource(cli, &clusterConnectionInAppNs)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())
				Expect(clusterConnectionInAppNs.Data).Should(HaveKeyWithValue("tls.crt", []byte("certvalue")))
				Expect(clusterConnectionInAppNs.Data).Should(HaveKeyWithValue("tls.key", []byte("keyvalue")))
			})

			It("Should reconcile multi-cluster setup for a management cluster for a single tenant", func() {
				// Create the tunnel secret in operator namespace
				// In a production cluster, this would be created by Manager controller in tigera-operator namespace
				err := cli.Create(ctx, &corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.VoltronTunnelSecretName,
						Namespace: common.OperatorNamespace(),
					},
				})
				Expect(err).NotTo(HaveOccurred())

				r := ReconcileAPIServer{
					client:              cli,
					scheme:              scheme,
					provider:            operatorv1.ProviderNone,
					enterpriseCRDsExist: true,
					status:              mockStatus,
					tierWatchReady:      ready,
					multiTenant:         false,
				}

				// Reconcile the API server
				_, err = r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				deployment := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-apiserver",
						Namespace: "tigera-system",
					},
				}
				clusterConnectionInAppNs := corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.VoltronTunnelSecretName,
						Namespace: "tigera-system",
					},
				}

				// Ensure a deployment was created for the API server
				err = test.GetResource(cli, &deployment)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())

				// Ensure that the tunnel secret was copied in tigera-system namespace
				err = test.GetResource(cli, &clusterConnectionInAppNs)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())
			})

			It("Should reconcile multi-cluster setup for a management cluster for a multiple tenant", func() {
				r := ReconcileAPIServer{
					client:              cli,
					scheme:              scheme,
					provider:            operatorv1.ProviderNone,
					enterpriseCRDsExist: true,
					status:              mockStatus,
					tierWatchReady:      ready,
					multiTenant:         true,
				}

				// Reconcile the API server
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				deployment := appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-apiserver",
						Namespace: "tigera-system",
					},
				}
				clusterConnectionInAppNs := corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      render.VoltronTunnelSecretName,
						Namespace: "tigera-system",
					},
				}

				// Ensure a deployment was created for the API server
				err = test.GetResource(cli, &deployment)
				Expect(kerror.IsNotFound(err)).Should(BeFalse())

				// Do not expect any secrets to be copied over
				err = test.GetResource(cli, &clusterConnectionInAppNs)
				Expect(kerror.IsNotFound(err)).Should(BeTrue())
			})

		})
	})
})
