// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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

package certificatemanager_test

import (
	"context"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/openshift/library-go/pkg/crypto"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"

	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Test CertificateManagement suite", func() {

	const (
		appSecretName       = "my-app-tls"
		appSecretName2      = "my-app-tls-2"
		appNs               = "my-app"
		legacyKeyFieldName  = "key"
		legacyCertFieldName = "cert"
	)

	var (
		cli                 client.Client
		scheme              *k8sruntime.Scheme
		installation        *operatorv1.InstallationSpec
		cm                  *operatorv1.CertificateManagement
		clusterDomain       = "cluster.local"
		appDNSNames         = []string{appSecretName}
		ctx                 = context.TODO()
		certificateManager  certificatemanager.CertificateManager
		expiredSecret       *corev1.Secret
		legacySecret        *corev1.Secret
		expiredLegacySecret *corev1.Secret
		byoSecret           *corev1.Secret
		expiredByoSecret    *corev1.Secret
	)
	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = k8sruntime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		installation = &operatorv1.InstallationSpec{}
		certificateManager, err = certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		keyPair, err := certificateManager.GetOrCreateKeyPair(cli, "temp", appNs, appDNSNames)
		Expect(err).NotTo(HaveOccurred())
		cm = &operatorv1.CertificateManagement{CACert: keyPair.GetCertificatePEM()}

		// Create a legacy secret (how certs were before v1.24) with non-standardized legacy key and cert name.
		legacySecret, err = secret.CreateTLSSecret(nil, appSecretName, appNs, legacyKeyFieldName, legacyCertFieldName, time.Hour, nil, appSecretName)
		Expect(err).NotTo(HaveOccurred())

		// Create a byo secret with non-standardized legacy key and cert name (like our docs for felix/typha).
		cryptoCA, err := tls.MakeCA("byo-ca")
		Expect(err).NotTo(HaveOccurred())
		byoSecret, err = secret.CreateTLSSecret(cryptoCA, appSecretName, appNs, "key.key", "cert.crt", time.Hour, nil, appSecretName)
		Expect(err).NotTo(HaveOccurred())
		expiredByoSecret, err = secret.CreateTLSSecret(cryptoCA, appSecretName, appNs, "key.key", "cert.crt", -time.Hour, nil, appSecretName)
		Expect(err).NotTo(HaveOccurred())

		legacyCryptoCA, err := tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix + "@some-hash")
		Expect(err).NotTo(HaveOccurred())
		expiredLegacySecret, err = secret.CreateTLSSecret(legacyCryptoCA, appSecretName, appNs, legacyKeyFieldName, legacyCertFieldName, -time.Hour, nil, appSecretName)
		Expect(err).NotTo(HaveOccurred())

		ca, err := crypto.GetCAFromBytes(certificateManager.KeyPair().GetCertificatePEM(), certificateManager.KeyPair().Secret("").Data[corev1.TLSPrivateKeyKey])
		Expect(err).NotTo(HaveOccurred())
		expiredSecret, err = secret.CreateTLSSecret(ca, appSecretName, appNs, legacyKeyFieldName, legacyCertFieldName, -time.Hour, nil, appSecretName)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("test CertificateManager interface", func() {
		It("should create a CA if it does not exist yet or reconstruct it from secret", func() {
			By("constructing a new CA and storing it")
			Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			By("constructing a key pair signed by the CA and storing it in a secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair).NotTo(BeNil())
			Expect(keyPair.GetIssuer()).To(Equal(certificateManager.KeyPair()))

			By("reconstructing certificateManager2 from the secret that was stored")
			certificateManager2, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager2).NotTo(BeNil())
			Expect(keyPair.GetIssuer()).To(Equal(certificateManager2.KeyPair())) // Proves that certificateManager & certificateManager2 are identical

			By("deleting the tigera-ca-secret")
			Expect(cli.Delete(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

			By("constructing a brand new CA and storing it")
			certificateManager3, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager3).NotTo(BeNil())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager3.KeyPair())) // Proves that certificateManager & certificateManager3 are different

			By("Constructing a certificateManager with Certificate management enabled and verifying differences")
			installation.CertificateManagement = cm
			certificateManager4, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager4.KeyPair()))
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			keyPair2, err := certificateManager4.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair2.GetIssuer()).NotTo(Equal(certificateManager4.KeyPair())) // We expect the customer to bring an issuer to the cluster
			Expect(keyPair2.UseCertificateManagement()).To(BeTrue())
		})

		It("should create a KeyPair if it does not exist yet or reconstruct it from secret", func() {

			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("fetching the key pair again and verify the two are identical")
			keyPair2, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.HashAnnotationValue()).ToNot(BeNil())
			Expect(keyPair2.HashAnnotationValue()).To(Equal(keyPair.HashAnnotationValue()))
		})

		It("should replace a KeyPair if it was created by an older ca", func() {

			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("fetching the key pair again with a newer ca")
			certificateManager2, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			Expect(certificateManager2).NotTo(BeNil())
			keyPair2, err := certificateManager2.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.HashAnnotationValue()).ToNot(BeNil())
			Expect(keyPair2.HashAnnotationValue()).NotTo(Equal(keyPair.HashAnnotationValue()))
		})

		It("should be able to fetch a key pair if it exists", func() {
			By("verifying that it returns nil if the key pair does not exist")
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
			By("verifying that it returns nil if the certificate does not exist")
			crt, err := certificateManager.GetCertificate(cli, appSecretName, appNs)
			Expect(crt).To(BeNil())
			Expect(err).NotTo(HaveOccurred())

			By("creating a key pair and storing the secret")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, keyPair.Secret(appNs))).NotTo(HaveOccurred())

			By("verifying that it returns the certificate")
			certificate, err := certificateManager.GetCertificate(cli, appSecretName, appNs)
			Expect(err).NotTo(HaveOccurred())
			Expect(certificate).NotTo(BeNil())
		})

		Describe("test certificate expiry", func() {
			It("should create a new secret when it has expired", func() {
				secret := expiredSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				kp, err := certificateManager.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(kp.GetCertificatePEM()).NotTo(Equal(secret.Data[corev1.TLSCertKey]))
			})

			It("should create a new secret when a legacy operator secret has expired", func() {
				secret := expiredLegacySecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				kp, err := certificateManager.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).NotTo(HaveOccurred())
				Expect(kp.GetCertificatePEM()).NotTo(Equal(secret.Data[corev1.TLSCertKey]))
			})

			It("should return an error on byo expired secrets", func() {
				secret := expiredByoSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				_, err := certificateManager.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).To(HaveOccurred())
			})

			It("should ignore the expired secret when certificate management is enabled", func() {
				secret := expiredSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				installation.CertificateManagement = cm
				certificateManagerCM, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
				Expect(err).NotTo(HaveOccurred())
				_, err = certificateManagerCM.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return an error on byo expired secrets when certificate management is enabled", func() {
				secret := expiredByoSecret
				Expect(cli.Create(ctx, secret)).NotTo(HaveOccurred())
				installation.CertificateManagement = cm
				certificateManagerCM, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
				Expect(err).NotTo(HaveOccurred())
				_, err = certificateManagerCM.GetOrCreateKeyPair(cli, secret.Name, secret.Namespace, []string{appSecretName})
				Expect(err).To(HaveOccurred())
			})
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
			Expect(keyPair.GetIssuer()).To(Equal(certificateManager.KeyPair()))

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(rmeta.OSTypeLinux)
			Expect(mount.MountPath).To(Equal("/" + appSecretName))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())
		})

		It("renders the right spec for certificate management", func() {
			By("creating a key pair w/ certificate management")
			installation.CertificateManagement = cm
			certificateManager, err := certificatemanager.Create(cli, installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeTrue())
			Expect(keyPair.BYO()).To(BeFalse())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.EmptyDir).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.EmptyDir).NotTo(BeNil())

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(rmeta.OSTypeLinux)
			Expect(mount.MountPath).To(Equal("/" + appSecretName))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(keyPair.HashAnnotationValue()).To(Equal(""))

			By("verifying the init container")
			initContainer := keyPair.InitContainer(appNs)
			imageSet, err := imageset.GetImageSet(context.Background(), cli, installation.Variant)
			Expect(err).NotTo(HaveOccurred())
			expectedImage, err := components.GetReference(
				components.ComponentCSRInitContainer,
				installation.Registry,
				installation.ImagePath,
				installation.ImagePrefix,
				imageSet,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(initContainer.Image).To(Equal(expectedImage))
			Expect(initContainer.Env).To(ContainElement(corev1.EnvVar{Name: "COMMON_NAME", Value: appSecretName}))
		})

		It("renders the right spec for BYO certs", func() {
			By("creating a BYO corev1.Secret and then create a KeyPair using the certificateManager")
			Expect(cli.Create(ctx, byoSecret)).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeTrue())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(rmeta.OSTypeLinux)
			Expect(mount.MountPath).To(Equal("/" + appSecretName))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())

			By("verifying that the non-standard secret fields have been standardized")
			Expect(keyPair.Secret(appNs).Data[corev1.TLSPrivateKeyKey]).NotTo(BeNil())
			Expect(keyPair.Secret(appNs).Data[corev1.TLSCertKey]).NotTo(BeNil())
		})

		It("handles missing DNS names as expected", func() {
			missingDNSNames := append(appDNSNames, "missing-name")
			By("verifying it does replace a secret when dns names are missing")
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			test.VerifyCertSANs(keyPair.GetCertificatePEM(), appDNSNames...)
			keyPair, err = certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, missingDNSNames)
			Expect(err).NotTo(HaveOccurred())
			test.VerifyCertSANs(keyPair.GetCertificatePEM(), missingDNSNames...)

			By("verifying it does not replace a BYO secret, nor throw an error")
			Expect(cli.Create(ctx, byoSecret)).NotTo(HaveOccurred())
			keyPair, err = certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, missingDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeTrue())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))
		})

		It("renders the right spec for legacy certs (<= v1.24)", func() {
			By("creating a legacy secret and then create a KeyPair using the certificateManager")
			Expect(cli.Create(ctx, legacySecret)).NotTo(HaveOccurred())
			keyPair, err := certificateManager.GetOrCreateKeyPair(cli, appSecretName, appNs, appDNSNames)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyPair.UseCertificateManagement()).To(BeFalse())
			Expect(keyPair.BYO()).To(BeTrue())
			Expect(keyPair.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))

			By("verifying the volume is correct")
			volume := keyPair.Volume()
			Expect(volume.Secret).NotTo(BeNil())
			Expect(volume.Name).To(Equal(appSecretName))
			Expect(volume.VolumeSource.Secret.SecretName).To(Equal(appSecretName))

			By("verifying the volume mount is correct")
			mount := keyPair.VolumeMount(rmeta.OSTypeLinux)
			Expect(mount.MountPath).To(Equal("/" + appSecretName))
			Expect(mount.Name).To(Equal(appSecretName))

			By("verifying the annotations")
			Expect(keyPair.HashAnnotationKey()).To(Equal("hash.operator.tigera.io/my-app-tls"))
			Expect(len(keyPair.HashAnnotationValue())).NotTo(BeNil())

			By("verifying that the non-standard secret fields have been standardized")
			Expect(keyPair.Secret(appNs).Data[corev1.TLSPrivateKeyKey]).NotTo(BeNil())
			Expect(keyPair.Secret(appNs).Data[corev1.TLSCertKey]).NotTo(BeNil())

			By("verifying that the legacy fields have been preserved for certain edge-cases in cluster upgrades")
			Expect(keyPair.Secret(appNs).Data[legacyKeyFieldName]).NotTo(BeNil())
			Expect(keyPair.Secret(appNs).Data[legacyCertFieldName]).NotTo(BeNil())
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

			Expect(cert.GetIssuer()).To(Equal(certificateManager.KeyPair()))
			Expect(cert2.GetIssuer()).To(Equal(certificateManager.KeyPair()))
			Expect(byo.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))
			Expect(legacy.GetIssuer()).NotTo(Equal(certificateManager.KeyPair()))

			By("creating and validating a trusted certificate bundle")
			trustedBundle := certificateManager.CreateTrustedBundle(cert, cert2, byo, legacy)
			Expect(trustedBundle.Volume()).To(Equal(corev1.Volume{
				Name: "tigera-ca-bundle",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-ca-bundle"},
					},
				},
			}))
			Expect(trustedBundle.VolumeMounts(rmeta.OSTypeLinux)).To(Equal([]corev1.VolumeMount{
				{
					Name:      "tigera-ca-bundle",
					MountPath: "/etc/pki/tls/certs",
					ReadOnly:  true,
				},
			}))
			Expect(trustedBundle.MountPath()).To(Equal(certificatemanagement.TrustedCertBundleMountPath))
			configMap := trustedBundle.ConfigMap(appNs)
			Expect(configMap.ObjectMeta).To(Equal(metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: appNs}))
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
		It("should load the system certificates into the bundle", func() {
			if runtime.GOOS != "linux" {
				Skip("Skip for users that run this test outside of a container on incompatible systems.")
			}
			trustedBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates()
			Expect(err).NotTo(HaveOccurred())
			configMap := trustedBundle.ConfigMap(appNs)
			Expect(configMap.ObjectMeta).To(Equal(metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: appNs}))
			Expect(configMap.TypeMeta).To(Equal(metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}))
			By("counting the number of pem blocks in the configmap")
			bundle := configMap.Data[certificatemanagement.RHELRootCertificateBundleName]
			numBlocks := strings.Count(bundle, "-----BEGIN CERTIFICATE-----")
			Expect(numBlocks > 1).To(BeTrue()) // We expect tens of them most likely.
		})
	})
})
