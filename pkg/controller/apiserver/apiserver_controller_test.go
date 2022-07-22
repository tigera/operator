// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

	"github.com/tigera/operator/pkg/controller/utils"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	netv1 "k8s.io/api/networking/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/render/common/secret"

	"github.com/stretchr/testify/mock"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
		packetCaptureSecret   *corev1.Secret
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
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		Expect(err).NotTo(HaveOccurred())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		certificateManagement = &operatorv1.CertificateManagement{CACert: cert}
		replicas := int32(2)
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
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
		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		cryptoCA, err := tls.MakeCA("byo-ca")
		Expect(err).NotTo(HaveOccurred())
		apiSecret, err = secret.CreateTLSSecret(cryptoCA, "tigera-apiserver-certs", common.OperatorNamespace(), "key.key", "cert.crt", time.Hour, nil, dns.GetServiceDNSNames(render.ProjectCalicoApiServerServiceName(operatorv1.TigeraSecureEnterprise), "tigera-system", dns.DefaultClusterDomain)...)
		Expect(err).NotTo(HaveOccurred())
		packetCaptureSecret, err = secret.CreateTLSSecret(cryptoCA, render.PacketCaptureCertSecret, common.OperatorNamespace(), "key.key", "cert.crt", time.Hour, nil, dns.GetServiceDNSNames(render.PacketCaptureServiceName, render.PacketCaptureNamespace, dns.DefaultClusterDomain)...)
		Expect(err).NotTo(HaveOccurred())

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
				amazonCRDExists:     false,
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
					components.ComponentCSRInitContainer.Image,
					components.ComponentCSRInitContainer.Version)))

			pcDeployment := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PacketCaptureName,
					Namespace: render.PacketCaptureNamespace,
				},
			}
			Expect(test.GetResource(cli, &pcDeployment)).To(BeNil())
			Expect(pcDeployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			pcContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.Containers, render.PacketCaptureContainerName)
			Expect(pcContainer).ToNot(BeNil())
			Expect(pcContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentPacketCapture.Image,
					components.ComponentPacketCapture.Version)))
			csrinitContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.InitContainers, "tigera-packetcapture-server-tls-key-cert-provisioner")
			Expect(csrinitContainer).ToNot(BeNil())
			Expect(csrinitContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentCSRInitContainer.Image,
					components.ComponentCSRInitContainer.Version)))
			pcSecret := v1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PacketCaptureCertSecret,
					Namespace: "tigera-operator",
				},
			}
			Expect(test.GetResource(cli, &pcSecret)).To(HaveOccurred()) // Since certificate management is enabled.
			Expect(pcSecret).NotTo(BeNil())
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
						{Image: "tigera/packetcapture", Digest: "sha256:packetcapturehash"},
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
					components.ComponentCSRInitContainer.Image,
					"sha256:calicocsrinithash")))

			pcDeployment := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PacketCaptureName,
					Namespace: render.PacketCaptureNamespace,
				},
			}
			Expect(test.GetResource(cli, &pcDeployment)).To(BeNil())
			Expect(pcDeployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			pcContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.Containers, render.PacketCaptureContainerName)
			Expect(pcContainer).ToNot(BeNil())
			Expect(pcContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentPacketCapture.Image,
					"sha256:packetcapturehash")))
			csrinitContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.InitContainers, "tigera-packetcapture-server-tls-key-cert-provisioner")
			Expect(csrinitContainer).ToNot(BeNil())
			Expect(csrinitContainer.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentCSRInitContainer.Image,
					"sha256:calicocsrinithash")))
			pcSecret := v1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PacketCaptureCertSecret,
					Namespace: "tigera-operator",
				},
			}
			Expect(test.GetResource(cli, &pcSecret)).To(HaveOccurred()) // Since certificate management is enabled.
			Expect(pcSecret).NotTo(BeNil())
		})

		It("should not add OwnerReference to user-supplied apiserver and packetcapture TLS cert secrets", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())

			secretName := render.ProjectCalicoApiServerTLSSecretName(operatorv1.TigeraSecureEnterprise)

			Expect(cli.Create(ctx, apiSecret)).ShouldNot(HaveOccurred())

			Expect(cli.Create(ctx, packetCaptureSecret)).ShouldNot(HaveOccurred())

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

			packetCaptureSecret2 := &corev1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: render.PacketCaptureCertSecret}, packetCaptureSecret2)).ShouldNot(HaveOccurred())
			Expect(packetCaptureSecret2.GetOwnerReferences()).To(HaveLen(0))
		})

		It("should add OwnerReference apiserver and packetcapture TLS cert operator managed secrets", func() {
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

			secret := &v1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: secretName}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: render.PacketCaptureCertSecret}, secret)).ShouldNot(HaveOccurred())
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
			Expect(policies.Items).To(HaveLen(2))
			Expect(policies.Items[0].Name).To(Equal("allow-tigera.tigera-packetcapture"))
			Expect(policies.Items[1].Name).To(Equal("allow-tigera.cnx-apiserver-access"))
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
	})
})
