// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

// This renderer is responsible for all resources related to a Guardian Deployment in a
// multicluster setup.

package certificatemanagement_test

import (
	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Test CertificateManagement suite", func() {

	const (
		appSecretName  = "my-app-tls"
		appSecretName2 = "my-app-tls-2"
		appNs          = "my-app"
		mountPath      = "/test"
		csrImage       = "my/image:tag"
	)

	var (
		cli                   client.Client
		scheme                *runtime.Scheme
		certificateManagement *operatorv1.CertificateManagement
		clusterDomain         = "cluster.local"
		appDNSNames           = []string{appSecretName}
		ctx                   = context.TODO()
		certificateManager    certificatemanagement.CertificateManager
		legacySecret          *corev1.Secret
		byoSecret             *corev1.Secret
	)
	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		Expect(v1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1beta.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		cli = fake.NewFakeClientWithScheme(scheme)

		certificateManager, err = certificatemanagement.CreateCertificateManager(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		keyPair, err := certificateManager.GetOrCreateKeyPair(cli, "temp", appNs, appDNSNames)
		certificateManagement = &operatorv1.CertificateManagement{CACert: keyPair.Secret("").Data[corev1.TLSCertKey]}

		// Create a legacy secret (how certs were before v1.24) with non-standardized legacy key and cert name.
		legacySecret, err = secret.CreateTLSSecret(nil, appSecretName, appNs, "key", "cert", time.Hour, nil, appSecretName)
		Expect(err).NotTo(HaveOccurred())

		// Create a byo secret with non-standardized legacy key and cert name (like our docs for felix/typha).
		cryptoCA, err := certificatemanagement.MakeCA("byo-ca")
		Expect(err).NotTo(HaveOccurred())
		byoSecret, err = secret.CreateTLSSecret(cryptoCA, appSecretName, appNs, "key.key", "cert.crt", time.Hour, nil, appSecretName)
		Expect(err).NotTo(HaveOccurred())

	})

	Describe("test CertificateManager interface", func() {
		It("should create a CA if it does not exist yet or reconstruct it from secret", func() {
			By("constructing a new CA and storing it")
			Expect(cli.Create(ctx, certificateManager.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			By("constructing a key pair signed by the CA and storing it in a secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair).NotTo(BeNil())
			Expect(certificateManager.Issued(keyPair)).To(BeTrue())

			By("reconstructing certificateManager2 from the secret that was stored")
			certificateManager2, err := certificatemanagement.CreateCertificateManager(cli, nil, clusterDomain)
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager2).NotTo(BeNil())
			Expect(certificateManager2.Issued(keyPair)).To(BeTrue()) // Proves that certificateManager & certificateManager2 are identical

			By("deleting the tigera-ca-secret")
			Expect(cli.Delete(ctx, certificateManager.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			By("constructing a brand new CA and storing it")
			certificateManager3, err := certificatemanagement.CreateCertificateManager(cli, nil, clusterDomain)
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager3).NotTo(BeNil())
			Expect(certificateManager3.Issued(keyPair)).To(BeFalse()) // Proves that certificateManager & certificateManager3 are different

			By("Constructing a certificateManager with Certificate management enabled and verifying differences")
			certificateManager4, err := certificatemanagement.CreateCertificateManager(cli, certificateManagement, clusterDomain)
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager4.Issued(keyPair)).To(BeFalse())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			keyPair2, err := certificateManager4.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager4.Issued(keyPair2)).To(BeFalse()) // We expect the customer to bring an issuer to the cluster
			Expect(keyPair2.UseCertificateManagement()).To(BeTrue())
		})

		It("should create a keyPair if it does not exist yet or reconstruct it from secret", func() {

			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			By("fetching the key pair again and verify the two are identical")
			keyPair2, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.X509Certificate().SerialNumber).ToNot(BeNil())
			Expect(keyPair2.X509Certificate().SerialNumber).NotTo(Equal(keyPair.X509Certificate().SerialNumber))
		})

		It("should be able to fetch a key pair if it exists", func() {
			By("verifying that it returns an error if the key pair does not exist")
			key, err := certificateManager.GetKeyPair(cli, appSecretName, appNs)
			Expect(key).To(BeNil())
			Expect(err).NotTo(HaveOccurred())

			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("verifying that it returns the key pair")
			keyPair2, err := certificateManager.GetKeyPair(cli, appSecretName, appNs)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair2).NotTo(BeNil())
		})

		It("should be able to fetch a certificate if it exists", func() {
			By("verifying that it returns an error if the certificate does not exist")
			_, err := certificateManager.GetCertificate(cli, appSecretName, appNs)
			Expect(err).To(HaveOccurred())

			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("verifying that it returns the certificate")
			certificate, err := certificateManager.GetCertificate(cli, appSecretName, appNs)
			Expect(err).NotTo(HaveOccurred())
			Expect(certificate).NotTo(BeNil())
		})
	})

	Describe("test KeyPair interface", func() {
		It("should not be possible to modify its internal secret", func() {
			By("creating a key pair")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())

			By("verifying that the secret() method creates a copy, and does not modify its internal data")
			secret1 := keyPair.Secret("test")
			secret1.Name = "test"
			secret2 := keyPair.Secret("test")
			Expect(secret2.Name).NotTo(Equal(secret1.Name))

		})

		It("render the right spec for certificateManager issued key pairs", func() {
			By("creating a key pair signed by certificateManager")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeFalse())
			Expect(certificateManager.Issued(keyPair)).To(BeTrue())

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(mountPath)
			Expect(mount.MountPath).To(Equal(mountPath))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())
		})

		It("renders the right spec for certificate management", func() {
			By("creating a key pair w/ certificate management")
			certificateManager, err := certificatemanagement.CreateCertificateManager(cli, certificateManagement, clusterDomain)
			Expect(err).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeTrue())
			Expect(keyPair.BYO()).To(BeFalse())
			Expect(certificateManager.Issued(keyPair)).To(BeFalse())

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.EmptyDir).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.EmptyDir).NotTo(BeNil())

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(mountPath)
			Expect(mount.MountPath).To(Equal(mountPath))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(keyPair.HashAnnotationValue()).To(Equal(""))

			By("verifying the init container")
			initContainer := keyPair.InitContainer(appNs, csrImage)
			Expect(initContainer.Image).To(Equal(csrImage))
			Expect(initContainer.Env).To(ContainElement(corev1.EnvVar{Name: "COMMON_NAME", Value: appSecretName}))
		})

		It("renders the right spec for BYO certs", func() {
			By("creating a BYO corev1.Secret and then create a KeyPair using the certificateManager")
			Expect(cli.Create(ctx, byoSecret)).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeTrue())
			Expect(certificateManager.Issued(keyPair)).To(BeFalse())

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(mountPath)
			Expect(mount.MountPath).To(Equal(mountPath))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())

			By("verifying that the non-standard secret fields have been standardized")
			Expect(keyPair.Secret(appNs).Data[corev1.TLSPrivateKeyKey]).NotTo(BeNil())
			Expect(keyPair.Secret(appNs).Data[corev1.TLSCertKey]).NotTo(BeNil())
		})

		It("renders the right spec for legacy certs (<= v1.24)", func() {
			By("creating a legacy corev1.Secret and then create a KeyPair using the certificateManager")
			Expect(cli.Create(ctx, legacySecret)).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeTrue())
			Expect(certificateManager.Issued(keyPair)).To(BeFalse())

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(mountPath)
			Expect(mount.MountPath).To(Equal(mountPath))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())

			By("verifying that the non-standard secret fields have been standardized")
			Expect(keyPair.Secret(appNs).Data[corev1.TLSPrivateKeyKey]).NotTo(BeNil())
			Expect(keyPair.Secret(appNs).Data[corev1.TLSCertKey]).NotTo(BeNil())
		})
	})

	Describe("test TrustedBundle interface", func() {

		It("should add a pem block for each certificate", func() {
			By("creating four secrets in the datastore")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			keyPair2, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName2, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair2.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(err).NotTo(HaveOccurred())
			byoSecret.Name, byoSecret.Namespace = "byo-secret", common.OperatorNamespace()
			Expect(cli.Create(ctx, byoSecret)).NotTo(HaveOccurred())
			Expect(err).NotTo(HaveOccurred())
			legacySecret.Name, legacySecret.Namespace = "legacy-secret", common.OperatorNamespace()
			Expect(cli.Create(ctx, legacySecret)).NotTo(HaveOccurred())
			Expect(err).NotTo(HaveOccurred())

			By("creating and validating the four certificates")
			cert, err := certificateManager.GetCertificate(cli, appSecretName, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			cert2, err := certificateManager.GetCertificate(cli, appSecretName2, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			byo, err := certificateManager.GetCertificate(cli, byoSecret.Name, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			legacy, err := certificateManager.GetCertificate(cli, legacySecret.Name, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			Expect(cert.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(cert.HashAnnotationValue()).NotTo(BeEmpty())
			Expect(cert.HashAnnotationValue()).NotTo(Equal(cert2.HashAnnotationValue()))
			Expect(certificateManager.Issued(cert)).To(BeTrue())
			Expect(cert2.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls-2"))
			Expect(cert2.HashAnnotationValue()).NotTo(BeEmpty())
			Expect(certificateManager.Issued(cert2)).To(BeTrue())
			Expect(byo.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/byo-secret"))
			Expect(byo.HashAnnotationValue()).NotTo(BeEmpty())
			Expect(certificateManager.Issued(byo)).To(BeFalse())
			Expect(legacy.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/legacy-secret"))
			Expect(legacy.HashAnnotationValue()).NotTo(BeEmpty())
			Expect(certificateManager.Issued(legacy)).To(BeFalse())

			By("creating and validating a trusted certificate bundle")
			trustedBundle := certificatemanagement.CreateTrustedBundle(certificateManager, cert, cert2, byo, legacy)
			Expect(trustedBundle.Volume()).To(Equal(corev1.Volume{
				Name: certificatemanagement.TrustedCertConfigMapName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: certificatemanagement.TrustedCertConfigMapName},
					},
				},
			}))
			Expect(trustedBundle.VolumeMount()).To(Equal(corev1.VolumeMount{
				Name:      certificatemanagement.TrustedCertConfigMapName,
				MountPath: certificatemanagement.TrustedCertVolumeMountPath,
				ReadOnly:  true,
			}))
			Expect(trustedBundle.MountPath()).To(Equal(certificatemanagement.TrustedCertBundleMountPath))
			configMap := trustedBundle.ConfigMap(appNs)
			Expect(configMap.ObjectMeta).To(Equal(metav1.ObjectMeta{Name: certificatemanagement.TrustedCertConfigMapName, Namespace: appNs}))
			Expect(configMap.TypeMeta).To(Equal(metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}))
			By("counting the number of pem blocks in the configmap")
			bundle := configMap.Data[certificatemanagement.TrustedCertConfigMapKeyName]
			numBlocks := strings.Count(bundle, "certificate name:")
			// While we have the ca + 4 certs, we expect 3 cert blocks (+ 2):
			// - the certificateManager: this covers for all certs signed by the tigera root ca
			// - the byo block (+ its ca block)
			// - the legacy block (+ its ca block)
			Expect(numBlocks).To(Equal(3))
			Expect(trustedBundle.HashAnnotations()).To(HaveKey("hash.operator.tigera.io/tigera-ca-private"))
			Expect(trustedBundle.HashAnnotations()).To(HaveKey("hash.operator.tigera.io/byo-secret"))
			Expect(trustedBundle.HashAnnotations()).To(HaveKey("hash.operator.tigera.io/legacy-secret"))
		})
	})
})
