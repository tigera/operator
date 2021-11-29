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

package apiserver

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
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
		cli        client.Client
		scheme     *runtime.Scheme
		ctx        context.Context
		mockStatus *status.MockStatus
		variant    operatorv1.ProductVariant
	)

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = fake.NewFakeClientWithScheme(scheme)

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

		variant = operatorv1.TigeraSecureEnterprise
	})

	Context("verify reconciliation", func() {
		It("should use builtin images", func() {
			setUpApiServerInstallation(cli, ctx, variant, &operatorv1.CertificateManagement{})

			r := ReconcileAPIServer{
				client:          cli,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				amazonCRDExists: false,
				status:          mockStatus,
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
			apiserver := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-apiserver")
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
			csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, render.CSRInitContainerName)
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
			csrinitContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.InitContainers, render.CSRInitContainerName)
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
			Expect(test.GetResource(cli, &pcSecret)).To(BeNil())
			Expect(pcSecret).NotTo(BeNil())
		})
		It("should use images from imageset", func() {
			setUpApiServerInstallation(cli, ctx, variant, &operatorv1.CertificateManagement{})

			Expect(cli.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/cnx-apiserver", Digest: "sha256:apiserverhash"},
						{Image: "tigera/cnx-queryserver", Digest: "sha256:queryserverhash"},
						{Image: "tigera/key-cert-provisioner", Digest: "sha256:calicocsrinithash"},
						{Image: "tigera/packetcapture-api", Digest: "sha256:packetcapturehash"},
					},
				},
			})).ToNot(HaveOccurred())

			r := ReconcileAPIServer{
				client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
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
			apiserver := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-apiserver")
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
			csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, render.CSRInitContainerName)
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
			csrinitContainer := test.GetContainer(pcDeployment.Spec.Template.Spec.InitContainers, render.CSRInitContainerName)
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
			Expect(test.GetResource(cli, &pcSecret)).To(BeNil())
			Expect(pcSecret).NotTo(BeNil())
		})

		It("should not add OwnerReference to user-supplied apiserver and packetcapture TLS cert secrets", func() {
			setUpApiServerInstallation(cli, ctx, variant, nil)

			secretName := render.ProjectCalicoApiServerTLSSecretName(variant)

			testCA := test.MakeTestCA("apiserver-test")
			apiSecret, err := secret.CreateTLSSecret(testCA,
				secretName, common.OperatorNamespace(), render.APIServerSecretKeyName, render.APIServerSecretCertName,
				rmeta.DefaultCertificateDuration, nil, "tigera-api", "tigera-system", dns.DefaultClusterDomain,
			)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, apiSecret)).ShouldNot(HaveOccurred())

			packetCaptureSecret, err := secret.CreateTLSSecret(testCA,
				render.PacketCaptureCertSecret, common.OperatorNamespace(), v1.TLSPrivateKeyKey, v1.TLSCertKey,
				rmeta.DefaultCertificateDuration, nil, dns.GetServiceDNSNames(render.PacketCaptureServiceName, render.PacketCaptureNamespace, dns.DefaultClusterDomain)...,
			)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, packetCaptureSecret)).ShouldNot(HaveOccurred())

			r := ReconcileAPIServer{
				client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: secretName}, apiSecret)).ShouldNot(HaveOccurred())
			Expect(apiSecret.GetOwnerReferences()).To(HaveLen(0))

			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: render.PacketCaptureCertSecret}, packetCaptureSecret)).ShouldNot(HaveOccurred())
			Expect(packetCaptureSecret.GetOwnerReferences()).To(HaveLen(0))
		})

		It("should add OwnerReference apiserver and packetcapture TLS cert operator managed secrets", func() {
			setUpApiServerInstallation(cli, ctx, variant, nil)

			secretName := "calico-apiserver-certs"
			if variant == operatorv1.TigeraSecureEnterprise {
				secretName = "tigera-apiserver-certs"
			}

			r := ReconcileAPIServer{
				client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &v1.Secret{}
			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: secretName}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

			Expect(cli.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace(), Name: render.PacketCaptureCertSecret}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))
		})
	})
})

func setUpApiServerInstallation(cli client.Client, ctx context.Context, variant operatorv1.ProductVariant, certificateManagement *operatorv1.CertificateManagement) {

	replicas := int32(2)
	Expect(cli.Create(ctx, &operatorv1.Installation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Status: operatorv1.InstallationStatus{
			Variant:  variant,
			Computed: &operatorv1.InstallationSpec{},
		},
		Spec: operatorv1.InstallationSpec{
			ControlPlaneReplicas:  &replicas,
			Variant:               variant,
			Registry:              "some.registry.org/",
			CertificateManagement: certificateManagement,
		},
	})).To(BeNil())
	// Apply prerequisites for the basic reconcile to succeed.
	Expect(cli.Create(ctx, &operatorv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
	})).ToNot(HaveOccurred())
}
