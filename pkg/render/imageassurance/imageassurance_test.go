// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package imageassurance_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/imageassurance"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Image Assurance Render", func() {
	var installation *operatorv1.InstallationSpec

	BeforeEach(func() {
		// Initialize a default installation spec.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
		}

	})

	It("should render all resources with default image assurance configuration", func() {

		pgUserSecret := corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.PGUserSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"username": []byte("username"),
				"password": []byte("my-secret-pass"),
			},
		}

		pgConfig := corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.PGConfigMapName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string]string{
				"host": "some.domain.io",
				"name": "my-database",
				"port": "1234",
			},
		}

		pgServerCertSecret := corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.PGCertSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"server-ca":   []byte("server-ca"),
				"client-cert": []byte("client-cert"),
				"client-key":  []byte("client-key"),
			},
		}

		// relies on secrets in operator namespace
		tlsSecrets := &corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.APICertSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{"tls.key": []byte("tlskey"), "tls.cert": []byte("tlscert")},
		}

		mgrSecrets := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.ManagerCertSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{"tls.key": []byte("mgrkey"), "tls.cert": []byte("mgrcert")},
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: imageassurance.NameSpaceImageAssurance, ns: "", group: "", version: "v1", kind: "Namespace"},
			// secrets
			{name: imageassurance.APICertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGCertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGUserSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGConfigMapName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ConfigMap"},
			{name: imageassurance.ManagerCertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},

			// image assurance adp resources
			{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
			{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
			{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
			{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "ClusterRole"},
			{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "ClusterRoleBinding"},
			{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Service"},
			{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},

			{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
			{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
			{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
			{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},
		}
		// Should render the correct resources.
		component := imageassurance.ImageAssurance(&imageassurance.Config{
			PullSecrets:       nil,
			Installation:      installation,
			OsType:            rmeta.OSTypeLinux,
			PGCertSecret:      &pgServerCertSecret,
			PGUserSecret:      &pgUserSecret,
			PGConfig:          &pgConfig,
			TLSSecret:         tlsSecrets,
			InternalMgrSecret: mgrSecrets,
		})
		resources, _ := component.Objects()
		Expect(component.ResolveImages(nil)).To(BeNil())
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// Check rendering of api deployment.
		adp := rtest.GetResource(resources, imageassurance.ResourceNameImageAssuranceAPI, imageassurance.NameSpaceImageAssurance,
			"apps", "v1", "Deployment").(*appsv1.Deployment)
		api := adp.Spec.Template.Spec

		Expect(api.HostNetwork).To(BeFalse())
		Expect(api.HostIPC).To(BeFalse())
		Expect(api.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
		Expect(len(api.Containers)).To(Equal(1))

		apiEnvs := api.Containers[0].Env
		apiExpectedENV := []corev1.EnvVar{
			{Name: "IMAGE_ASSURANCE_HTTPS_CERT", Value: "/certs/https/tls.crt"},
			{Name: "IMAGE_ASSURANCE_HTTPS_KEY", Value: "/certs/https/tls.key"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_ROOT_CERT", Value: "/certs/db/server-ca"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_CERT", Value: "/certs/db/client-cert"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_KEY", Value: "/certs/db/client-key"},
			{Name: "IMAGE_ASSURANCE_PORT", Value: "5557"},
			{Name: "IMAGE_ASSURANCE_LOGLEVEL", Value: "INFO"},
			{Name: "IMAGE_ASSURANCE_DB_HOST_ADDR", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGConfigMapName,
						},
						Key: imageassurance.PGConfigHostKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_PORT", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGConfigMapName,
						},
						Key: imageassurance.PGConfigPortKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_NAME", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGConfigMapName,
						},
						Key: imageassurance.PGConfigNameKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_USER_NAME", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGUserSecretName,
						},
						Key: imageassurance.PGUserSecretKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_PASSWORD", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGUserSecretName,
						},
						Key: imageassurance.PGUserPassKey,
					},
				},
			},
		}

		Expect(len(apiExpectedENV)).To(Equal(len(api.Containers[0].Env)))
		for _, expected := range apiExpectedENV {
			rtest.ExpectEnv(apiEnvs, expected.Name, expected.Value)
		}

		Expect(*api.Containers[0].SecurityContext.Privileged).To(BeTrue())

		apiVMs := api.Containers[0].VolumeMounts
		apiExpectedVMs := []corev1.VolumeMount{
			{Name: imageassurance.APICertSecretName, MountPath: "/certs/https/"},
			{Name: imageassurance.PGCertSecretName, MountPath: "/certs/db/"},
			{Name: imageassurance.ManagerCertSecretName, MountPath: "/manager-tls/"},
		}

		Expect(len(apiExpectedVMs)).To(Equal(len(apiVMs)))
		for _, expected := range apiExpectedVMs {
			rtest.ExpectVolumeMount(apiVMs, expected.Name, expected.MountPath)
		}

		// Check rendering of scanner deployment.
		sdp := rtest.GetResource(resources, imageassurance.ResourceNameImageAssuranceScanner, imageassurance.NameSpaceImageAssurance,
			"apps", "v1", "Deployment").(*appsv1.Deployment)
		scanner := sdp.Spec.Template.Spec

		Expect(scanner.HostNetwork).To(BeFalse())
		Expect(scanner.HostIPC).To(BeFalse())
		Expect(scanner.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
		Expect(len(scanner.Containers)).To(Equal(1))

		scannerEnv := scanner.Containers[0].Env
		scannerExpectedENV := []corev1.EnvVar{
			{Name: "IMAGE_ASSURANCE_LOGLEVEL", Value: "INFO"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_ROOT_CERT", Value: "/certs/db/server-ca"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_CERT", Value: "/certs/db/client-cert"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_KEY", Value: "/certs/db/client-key"},
			{Name: "IMAGE_ASSURANCE_SCANNER_RETRIES", Value: "3"},
			{Name: "IMAGE_ASSURANCE_DB_HOST_ADDR", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGConfigMapName,
						},
						Key: imageassurance.PGConfigHostKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_PORT", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGConfigMapName,
						},
						Key: imageassurance.PGConfigPortKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_NAME", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGConfigMapName,
						},
						Key: imageassurance.PGConfigNameKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_USER_NAME", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGUserSecretName,
						},
						Key: imageassurance.PGUserSecretKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_PASSWORD", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGUserSecretName,
						},
						Key: imageassurance.PGUserPassKey,
					},
				},
			},
		}
		Expect(len(scannerExpectedENV)).To(Equal(len(scannerEnv)))
		for _, expected := range scannerExpectedENV {
			rtest.ExpectEnv(scannerEnv, expected.Name, expected.Value)
		}

		Expect(*api.Containers[0].SecurityContext.Privileged).To(BeTrue())

		scannerVMs := scanner.Containers[0].VolumeMounts
		scannerExpectedVMs := []corev1.VolumeMount{
			{Name: imageassurance.PGCertSecretName, MountPath: "/certs/db/"},
		}

		Expect(len(scannerVMs)).To(Equal(len(scannerVMs)))
		for _, expected := range scannerExpectedVMs {
			rtest.ExpectVolumeMount(scannerVMs, expected.Name, expected.MountPath)
		}
	})

})
