// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package imageassurance_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/imageassurance"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Image Assurance Render", func() {
	var (
		installation              *operatorv1.InstallationSpec
		pgAdminUserSecret         corev1.Secret
		pgUserSecret              corev1.Secret
		pgServerCertSecret        corev1.Secret
		tlsSecrets                corev1.Secret
		mgrSecrets                corev1.Secret
		pgConfig                  corev1.ConfigMap
		config                    corev1.ConfigMap
		tenantEncryptionKeySecret corev1.Secret
	)

	BeforeEach(func() {
		// Initialize a default installation spec.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
			Registry:           components.UseDefault,
			ImagePath:          components.UseDefault,
			ImagePrefix:        components.UseDefault,
		}

		pgUserSecret = corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.PGUserSecretName,
				Namespace: imageassurance.NameSpaceImageAssurance,
			},
			Data: map[string][]byte{
				"username": []byte("username"),
				"password": []byte("my-secret-pass"),
			},
		}

		pgAdminUserSecret = corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.PGAdminUserSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"username": []byte("username"),
				"password": []byte("my-secret-pass"),
			},
		}

		pgConfig = corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.PGConfigMapName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string]string{
				"host":      "some.domain.io",
				"name":      "my-database",
				"port":      "1234",
				"dbOrgID":   "tenant123",
				"dbOrgName": "tenantName",
			},
		}

		config = corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      rcimageassurance.ConfigurationConfigMapName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string]string{
				"organizationID": "tenant123",
			},
		}

		pgServerCertSecret = corev1.Secret{
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
		tlsSecrets = corev1.Secret{TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.APICertSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{"tls.key": []byte("tlskey"), "tls.cert": []byte("tlscert")},
		}

		mgrSecrets = corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.ManagerCertSecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{"tls.key": []byte("mgrkey"), "tls.cert": []byte("mgrcert")},
		}

		tenantEncryptionKeySecret = corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.TenantEncryptionKeySecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{"encryption_key": []byte("encryption_key")},
		}
	})

	type expectedResource struct {
		name    string
		ns      string
		group   string
		version string
		kind    string
	}

	var resources = func(enableOIDC bool) []expectedResource {
		res := []expectedResource{
			{name: imageassurance.NameSpaceImageAssurance, ns: "", group: "", version: "v1", kind: "Namespace"},

			// secrets
			{name: imageassurance.PGCertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGUserSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGAdminUserSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGConfigMapName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ConfigMap"},
			{name: rcimageassurance.ConfigurationConfigMapName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ConfigMap"},

			// image assurance db migrator resources
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: "batch", version: "v1", kind: "Job"},

			// image assurance adp resources
			{name: imageassurance.APICertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.ManagerCertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.TenantEncryptionKeySecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},

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

			{name: imageassurance.ResourceNameImageAssuranceCAW, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
			{name: imageassurance.ResourceNameImageAssuranceCAW, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
			{name: imageassurance.ResourceNameImageAssuranceCAW, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
			{name: imageassurance.ResourceNameImageAssuranceCAW, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},
			{name: imageassurance.AdmissionControllerAPIClusterRoleName, group: rbacv1.GroupName, version: "v1", kind: "ClusterRole"},
		}
		if enableOIDC {
			var oidc = []expectedResource{
				{name: "tigera-dex-tls", ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			}
			res = append(res, oidc...)
		}
		return res

	}

	var apiExpectedENV = func(enableOIDC bool) []corev1.EnvVar {
		env := []corev1.EnvVar{
			{Name: "IMAGE_ASSURANCE_HTTPS_CERT", Value: "/certs/https/tls.crt"},
			{Name: "IMAGE_ASSURANCE_HTTPS_KEY", Value: "/certs/https/tls.key"},
			{Name: "IMAGE_ASSURANCE_TENANT_ENCRYPTION_KEY", Value: "/tenant-key/encryption_key"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_ROOT_CERT", Value: "/certs/db/server-ca"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_CERT", Value: "/certs/db/client-cert"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_KEY", Value: "/certs/db/client-key"},
			{Name: "IMAGE_ASSURANCE_PORT", Value: "5557"},
			{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
			{Name: "IMAGE_ASSURANCE_DB_LOG_LEVEL", Value: "WARN"},
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
			rcimageassurance.EnvOrganizationID(),
		}

		if enableOIDC {
			env = append(env, []corev1.EnvVar{
				{
					Name:  "IMAGE_ASSURANCE_DEX_ENABLED",
					Value: "true",
				},
				{
					Name:  "IMAGE_ASSURANCE_DEX_URL",
					Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/",
				},
				{
					Name:  "IMAGE_ASSURANCE_OIDC_AUTH_ENABLED",
					Value: "true",
				},
				{
					Name:  "IMAGE_ASSURANCE_OIDC_AUTH_ISSUER",
					Value: "https://127.0.0.1/dex",
				},
				{
					Name:  "IMAGE_ASSURANCE_OIDC_AUTH_JWKSURL",
					Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys",
				},
				{
					Name:  "IMAGE_ASSURANCE_OIDC_AUTH_CLIENT_ID",
					Value: "tigera-manager",
				},
				{
					Name:  "IMAGE_ASSURANCE_OIDC_AUTH_USERNAME_CLAIM",
					Value: "email",
				},
				{
					Name:  "IMAGE_ASSURANCE_OIDC_AUTH_GROUPS_CLAIM",
					Value: "groups",
				},
				{
					Name:  "IMAGE_ASSURANCE_OIDC_AUTH_USERNAME_PREFIX",
					Value: "",
				},
				{
					Name:  "IMAGE_ASSURANCE_OIDC_AUTH_GROUPS_PREFIX",
					Value: "",
				},
			}...)
		}

		return env
	}

	var apiExpectedVolMounts = func(enableOIDC bool) []corev1.VolumeMount {
		vms := []corev1.VolumeMount{
			{Name: imageassurance.APICertSecretName, MountPath: "/certs/https/"},
			{Name: imageassurance.PGCertSecretName, MountPath: "/certs/db/"},
			{Name: imageassurance.ManagerCertSecretName, MountPath: "/manager-tls/"},
			{Name: imageassurance.TenantEncryptionKeySecretName, MountPath: "/tenant-key/"},
		}
		if enableOIDC {
			vms = append(vms, corev1.VolumeMount{
				Name:      "tigera-dex-tls-crt",
				ReadOnly:  false,
				MountPath: "/etc/ssl/certs",
			})
		}

		return vms
	}

	It("should render all resources with default image assurance configuration", func() {

		expectedResources := resources(false)
		// Should render the correct resources.
		component := imageassurance.ImageAssurance(&imageassurance.Config{
			PullSecrets:               nil,
			Installation:              installation,
			OsType:                    rmeta.OSTypeLinux,
			PGCertSecret:              &pgServerCertSecret,
			PGAdminUserSecret:         &pgAdminUserSecret,
			PGUserSecret:              &pgUserSecret,
			PGConfig:                  &pgConfig,
			ConfigurationConfigMap:    &config,
			TLSSecret:                 &tlsSecrets,
			InternalMgrSecret:         &mgrSecrets,
			NeedsMigrating:            false,
			ComponentsUp:              false,
			TenantEncryptionKeySecret: &tenantEncryptionKeySecret,
		})
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// Check rendering of migrator job.
		mdp := rtest.GetResource(resources, imageassurance.ResourceNameImageAssuranceDBMigrator, imageassurance.NameSpaceImageAssurance,
			"batch", "v1", "Job").(*batchv1.Job)
		migrator := mdp.Spec.Template.Spec

		Expect(migrator.HostNetwork).To(BeFalse())
		Expect(migrator.HostIPC).To(BeFalse())
		Expect(migrator.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
		Expect(len(migrator.Containers)).To(Equal(1))

		migratorEnvs := migrator.Containers[0].Env
		migratorExpectedENV := []corev1.EnvVar{
			{Name: "IMAGE_ASSURANCE_DB_SSL_ROOT_CERT", Value: "/certs/db/server-ca"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_CERT", Value: "/certs/db/client-cert"},
			{Name: "IMAGE_ASSURANCE_DB_SSL_KEY", Value: "/certs/db/client-key"},
			{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
			{Name: "IMAGE_ASSURANCE_DB_LOG_LEVEL", Value: "WARN"},
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
							Name: "tigera-image-assurance-postgres-admin-user",
						},
						Key: imageassurance.PGUserSecretKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_DB_PASSWORD", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-image-assurance-postgres-admin-user",
						},
						Key: imageassurance.PGUserPassKey,
					},
				},
			},
			rcimageassurance.EnvOrganizationID(),
			{Name: "IMAGE_ASSURANCE_ORGANIZATION_NAME", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGConfigMapName,
						},
						Key: imageassurance.PGConfigOrgNameKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_TENANT_USER_NAME", Value: "",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: imageassurance.PGUserSecretName,
						},
						Key: imageassurance.PGUserPassKey,
					},
				},
			},
			{Name: "IMAGE_ASSURANCE_TENANT_PASSWORD", Value: "",
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

		Expect(len(migratorExpectedENV)).To(Equal(len(migrator.Containers[0].Env)))
		for _, expected := range migratorExpectedENV {
			rtest.ExpectEnv(migratorEnvs, expected.Name, expected.Value)
		}

		migratorVMs := migrator.Containers[0].VolumeMounts
		migratorExpectedVMs := []corev1.VolumeMount{
			{Name: imageassurance.PGCertSecretName, MountPath: "/certs/db/"},
		}

		Expect(len(migratorExpectedVMs)).To(Equal(len(migratorVMs)))
		for _, expected := range migratorExpectedVMs {
			rtest.ExpectVolumeMount(migratorVMs, expected.Name, expected.MountPath)
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
		apiExpectedENV := apiExpectedENV(false)

		Expect(len(apiExpectedENV)).To(Equal(len(api.Containers[0].Env)))
		for _, expected := range apiExpectedENV {
			rtest.ExpectEnv(apiEnvs, expected.Name, expected.Value)
		}

		Expect(*api.Containers[0].SecurityContext.Privileged).To(BeTrue())

		apiVMs := api.Containers[0].VolumeMounts
		apiExpectedVMs := apiExpectedVolMounts(false)

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
			{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
			{Name: "IMAGE_ASSURANCE_DB_LOG_LEVEL", Value: "WARN"},
			{Name: "IMAGE_ASSURANCE_TENANT_ENCRYPTION_KEY", Value: "/tenant-key/encryption_key"},
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
			rcimageassurance.EnvOrganizationID(),
		}

		Expect(len(scannerExpectedENV)).To(Equal(len(scannerEnv)))
		for _, expected := range scannerExpectedENV {
			rtest.ExpectEnv(scannerEnv, expected.Name, expected.Value)
		}

		Expect(*api.Containers[0].SecurityContext.Privileged).To(BeTrue())

		scannerVMs := scanner.Containers[0].VolumeMounts
		scannerExpectedVMs := []corev1.VolumeMount{
			{Name: imageassurance.PGCertSecretName, MountPath: "/certs/db/"},
			{Name: imageassurance.TenantEncryptionKeySecretName, MountPath: "/tenant-key/"},
		}

		Expect(len(scannerVMs)).To(Equal(len(scannerVMs)))
		for _, expected := range scannerExpectedVMs {
			rtest.ExpectVolumeMount(scannerVMs, expected.Name, expected.MountPath)
		}
	})

	It("should render only migrator resources when no previous migrator job was found", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: imageassurance.NameSpaceImageAssurance, ns: "", group: "", version: "v1", kind: "Namespace"},

			// secrets
			{name: imageassurance.PGCertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGUserSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGAdminUserSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
			{name: imageassurance.PGConfigMapName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ConfigMap"},
			{name: rcimageassurance.ConfigurationConfigMapName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ConfigMap"},

			// image assurance db migrator resources
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: "batch", version: "v1", kind: "Job"},
		}
		// Should render the correct resources.
		component := imageassurance.ImageAssurance(&imageassurance.Config{
			PullSecrets:               nil,
			Installation:              installation,
			OsType:                    rmeta.OSTypeLinux,
			PGCertSecret:              &pgServerCertSecret,
			PGAdminUserSecret:         &pgAdminUserSecret,
			PGUserSecret:              &pgUserSecret,
			PGConfig:                  &pgConfig,
			ConfigurationConfigMap:    &config,
			TLSSecret:                 &tlsSecrets,
			InternalMgrSecret:         &mgrSecrets,
			NeedsMigrating:            true,
			ComponentsUp:              false,
			TenantEncryptionKeySecret: &tenantEncryptionKeySecret,
		})
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
	})

	It("should delete the scanner, caw and api deployments, along with the migrator job when the NeedsMigrating and ComponentsUp are both true", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: "batch", version: "v1", kind: "Job"},
			{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},
			{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},
			{name: imageassurance.ResourceNameImageAssuranceCAW, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},
		}

		// Should delete the correct resources.
		component := imageassurance.ImageAssurance(&imageassurance.Config{
			PullSecrets:               nil,
			Installation:              installation,
			OsType:                    rmeta.OSTypeLinux,
			PGCertSecret:              &pgServerCertSecret,
			PGAdminUserSecret:         &pgAdminUserSecret,
			PGUserSecret:              &pgUserSecret,
			PGConfig:                  &pgConfig,
			ConfigurationConfigMap:    &config,
			TLSSecret:                 &tlsSecrets,
			InternalMgrSecret:         &mgrSecrets,
			NeedsMigrating:            true,
			ComponentsUp:              true,
			TenantEncryptionKeySecret: &tenantEncryptionKeySecret,
		})
		Expect(component.ResolveImages(nil)).To(BeNil())
		_, resources := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should delete the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
	})

	It("should API resource correctly with Authentication Enabled", func() {
		// Should render the correct resources.
		var authentication *operatorv1.Authentication
		authentication = &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"}}}

		var dexCfg = render.NewDexKeyValidatorConfig(authentication, nil, render.CreateDexTLSSecret("cn"), dns.DefaultClusterDomain)

		component := imageassurance.ImageAssurance(&imageassurance.Config{
			PullSecrets:               nil,
			Installation:              installation,
			OsType:                    rmeta.OSTypeLinux,
			PGCertSecret:              &pgServerCertSecret,
			PGAdminUserSecret:         &pgAdminUserSecret,
			PGUserSecret:              &pgUserSecret,
			PGConfig:                  &pgConfig,
			ConfigurationConfigMap:    &config,
			TLSSecret:                 &tlsSecrets,
			InternalMgrSecret:         &mgrSecrets,
			KeyValidatorConfig:        dexCfg,
			NeedsMigrating:            false,
			ComponentsUp:              false,
			TenantEncryptionKeySecret: &tenantEncryptionKeySecret,
		})
		expectedResources := resources(true)
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
		apiExpectedENV := apiExpectedENV(true)

		Expect(len(apiExpectedENV)).To(Equal(len(api.Containers[0].Env)))
		for _, expected := range apiExpectedENV {
			rtest.ExpectEnv(apiEnvs, expected.Name, expected.Value)
		}

		apiVMs := api.Containers[0].VolumeMounts
		apiExpectedVMs := apiExpectedVolMounts(true)

		Expect(len(apiExpectedVMs)).To(Equal(len(apiVMs)))
		for _, expected := range apiExpectedVMs {
			rtest.ExpectVolumeMount(apiVMs, expected.Name, expected.MountPath)
		}

	})

})
