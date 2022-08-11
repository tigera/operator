// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package imageassurance_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/imageassurance"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type expectedResource struct {
	name    string
	ns      string
	group   string
	version string
	kind    string
}

var _ = Describe("Image Assurance Render", func() {
	var (
		installation              *operatorv1.InstallationSpec
		pgAdminUserSecret         corev1.Secret
		pgUserSecret              corev1.Secret
		pgServerCertSecret        corev1.Secret
		tlsSecrets                corev1.Secret
		pgConfig                  corev1.ConfigMap
		config                    corev1.ConfigMap
		tenantEncryptionKeySecret corev1.Secret
		bundle                    certificatemanagement.TrustedBundle
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

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain)
		Expect(err).NotTo(HaveOccurred())
		bundle = certificateManager.CreateTrustedBundle()

		tenantEncryptionKeySecret = corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      imageassurance.TenantEncryptionKeySecretName,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{"encryption_key": []byte("encryption_key")},
		}
	})

	var expectedDeletedResources = []expectedResource{
		{name: imageassurance.ResourceNameImageAssuranceCAW, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},

		{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
		{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
		{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
		{name: imageassurance.ResourceNameImageAssuranceDBMigrator, ns: imageassurance.NameSpaceImageAssurance, group: "batch", version: "v1", kind: "Job"},

		{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
		{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
		{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},
	}

	var expectedCreatedResources = []expectedResource{
		{name: imageassurance.NameSpaceImageAssurance, ns: "", group: "", version: "v1", kind: "Namespace"},

		// secrets
		{name: imageassurance.PGCertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
		{name: imageassurance.PGUserSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
		{name: imageassurance.PGAdminUserSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
		{name: imageassurance.PGConfigMapName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ConfigMap"},
		{name: rcimageassurance.ConfigurationConfigMapName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ConfigMap"},

		// image assurance adp resources
		{name: imageassurance.APICertSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
		{name: imageassurance.TenantEncryptionKeySecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},

		{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
		{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "ClusterRole"},
		{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "ClusterRoleBinding"},
		{name: imageassurance.ResourceNameImageAssuranceAPI, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Service"},
		{name: imageassurance.APIProxyResourceName, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},

		{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
		{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
		{name: imageassurance.ScannerClusterRoleName, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "ClusterRole"},
		{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
		{name: imageassurance.ScannerAPIAccessSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
		{name: imageassurance.ResourceNameImageAssuranceScanner, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},

		{name: imageassurance.AdmissionControllerAPIClusterRoleName, group: rbacv1.GroupName, version: "v1", kind: "ClusterRole"},

		{name: imageassurance.ResourceNameImageAssurancePodWatcher, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "ServiceAccount"},
		{name: imageassurance.ResourceNameImageAssurancePodWatcher, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "Role"},
		{name: imageassurance.PodWatcherClusterRoleName, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "ClusterRole"},
		{name: imageassurance.ResourceNameImageAssurancePodWatcher, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "ClusterRole"},
		{name: imageassurance.ResourceNameImageAssurancePodWatcher, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "RoleBinding"},
		{name: imageassurance.ResourceNameImageAssurancePodWatcher, ns: imageassurance.NameSpaceImageAssurance, group: rbacv1.GroupName, version: "v1", kind: "ClusterRoleBinding"},
		{name: imageassurance.PodWatcherAPIAccessSecretName, ns: imageassurance.NameSpaceImageAssurance, group: "", version: "v1", kind: "Secret"},
		{name: imageassurance.ResourceNameImageAssurancePodWatcher, ns: imageassurance.NameSpaceImageAssurance, group: "apps", version: "v1", kind: "Deployment"},
	}

	var apiExpectedCommonENV = []corev1.EnvVar{
		rcimageassurance.EnvOrganizationID(),
		{Name: "IMAGE_ASSURANCE_PORT", Value: "5557"},
		{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
		{Name: "IMAGE_ASSURANCE_HTTPS_CERT", Value: "/certs/https/tls.crt"},
		{Name: "IMAGE_ASSURANCE_HTTPS_KEY", Value: "/certs/https/tls.key"},
		{Name: "IMAGE_ASSURANCE_PROXY_URL", Value: "https://ia-api.dev.calicocloud.io"},
		{Name: "IMAGE_ASSURANCE_PROXY_HTTPS_CERT", Value: "/certs/https/tls.crt"},
		{Name: "AUTH0_AUDIENCE", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "audience",
			},
		}},
		{Name: "AUTH0_CLIENT_ID", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "client_id",
			},
		}},
		{Name: "AUTH0_CLIENT_SECRET", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "client_secret",
			},
		}},
		{Name: "AUTH0_TOKEN_URL", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "token_url",
			},
		}},
		{Name: "AUTH0_CLOUD_BASE_URL", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-calico-cloud-client-credentials"},
				Key:                  "cloud_base_url",
			},
		}},
	}

	var apiExpectedOIDCENV = []corev1.EnvVar{
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
	}

	var apiExpectedVolMounts = []corev1.VolumeMount{
		{Name: imageassurance.APICertSecretName, MountPath: "/certs/https/"},
		{Name: certificatemanagement.TrustedCertConfigMapName, MountPath: certificatemanagement.TrustedCertVolumeMountPath},
	}

	It("should render all resources with default image assurance configuration", func() {
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
			TrustedCertBundle:         bundle,
			TenantEncryptionKeySecret: &tenantEncryptionKeySecret,
		})
		Expect(component.ResolveImages(nil)).To(BeNil())
		createdResources, deletedResources := component.Objects()
		Expect(createdResources).To(HaveLen(len(expectedCreatedResources)))
		Expect(deletedResources).To(HaveLen(len(expectedDeletedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedCreatedResources {
			rtest.ExpectResource(createdResources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// Check rendering of api deployment.
		adp := rtest.GetResource(createdResources, imageassurance.APIProxyResourceName, imageassurance.NameSpaceImageAssurance,
			"apps", "v1", "Deployment").(*appsv1.Deployment)
		api := adp.Spec.Template.Spec

		Expect(api.HostNetwork).To(BeFalse())
		Expect(api.HostIPC).To(BeFalse())
		Expect(api.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
		Expect(len(api.Containers)).To(Equal(1))

		apiEnvs := api.Containers[0].Env
		apiExpectedENV := apiExpectedCommonENV

		Expect(api.Containers[0].Env).To(HaveLen(len(apiExpectedENV)), fmt.Sprintf("env var count was %d", len(api.Containers[0].Env)))
		for _, expected := range apiExpectedENV {
			rtest.ExpectEnv(apiEnvs, expected.Name, expected.Value)
		}

		apiVMs := api.Containers[0].VolumeMounts

		Expect(len(apiExpectedVolMounts)).To(Equal(len(apiVMs)))
		for _, expected := range apiExpectedVolMounts {
			rtest.ExpectVolumeMount(apiVMs, expected.Name, expected.MountPath)
		}

		// Check rendering of scanner deployment.
		sdp := rtest.GetResource(createdResources, imageassurance.ResourceNameImageAssuranceScanner, imageassurance.NameSpaceImageAssurance,
			"apps", "v1", "Deployment").(*appsv1.Deployment)
		scanner := sdp.Spec.Template.Spec

		Expect(scanner.HostNetwork).To(BeFalse())
		Expect(scanner.HostIPC).To(BeFalse())
		Expect(scanner.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
		Expect(len(scanner.Containers)).To(Equal(1))

		scannerEnv := scanner.Containers[0].Env
		scannerExpectedENV := []corev1.EnvVar{
			{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
			{Name: "IMAGE_ASSURANCE_TENANT_ENCRYPTION_KEY", Value: "/tenant-key/encryption_key"},
			{Name: "IMAGE_ASSURANCE_SCANNER_RETRIES", Value: "3"},
			rcimageassurance.EnvOrganizationID(),
			{Name: "IMAGE_ASSURANCE_CA_BUNDLE_PATH", Value: "/certs/bast/tls.crt"},
			{Name: "IMAGE_ASSURANCE_API_SERVICE_URL", Value: "https://tigera-image-assurance-api.tigera-image-assurance.svc:9443"},
			{Name: "IMAGE_ASSURANCE_API_TOKEN", Value: ""},
		}

		Expect(len(scannerExpectedENV)).To(Equal(len(scannerEnv)))
		for _, expected := range scannerExpectedENV {
			rtest.ExpectEnv(scannerEnv, expected.Name, expected.Value)
		}

		Expect(*scanner.Containers[0].SecurityContext.Privileged).To(BeTrue())

		scannerVMs := scanner.Containers[0].VolumeMounts
		scannerExpectedVMs := []corev1.VolumeMount{
			{Name: imageassurance.PGCertSecretName, MountPath: "/certs/db/"},
			{Name: imageassurance.TenantEncryptionKeySecretName, MountPath: "/tenant-key/"},
		}

		Expect(len(scannerVMs)).To(Equal(len(scannerVMs)))
		for _, expected := range scannerExpectedVMs {
			rtest.ExpectVolumeMount(scannerVMs, expected.Name, expected.MountPath)
		}

		// Check rendering of pod watcher deployment.
		podWatcherDeployment := rtest.GetResource(createdResources, imageassurance.ResourceNameImageAssurancePodWatcher, imageassurance.NameSpaceImageAssurance,
			"apps", "v1", "Deployment").(*appsv1.Deployment)
		podWatcher := podWatcherDeployment.Spec.Template.Spec

		Expect(podWatcher.HostNetwork).To(BeFalse())
		Expect(podWatcher.HostIPC).To(BeFalse())
		Expect(podWatcher.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
		Expect(len(podWatcher.Containers)).To(Equal(1))

		podWatcherEnv := podWatcher.Containers[0].Env
		podWatcherExpectedENV := []corev1.EnvVar{
			{Name: "IMAGE_ASSURANCE_LOG_LEVEL", Value: "INFO"},
			rcimageassurance.EnvOrganizationID(),
			{Name: "IMAGE_ASSURANCE_API_CA", Value: "/certs/bast/tls.crt"},
			{Name: "IMAGE_ASSURANCE_API_SERVICE_URL", Value: "https://tigera-image-assurance-api.tigera-image-assurance.svc:9443"},
			{Name: "IMAGE_ASSURANCE_API_TOKEN", Value: ""},
			{Name: "IMAGE_ASSURANCE_MULTI_CLUSTER_FORWARDING_CA", Value: certificatemanagement.TrustedCertBundleMountPath},
		}

		Expect(len(podWatcherExpectedENV)).To(Equal(len(podWatcherEnv)))
		for _, expected := range podWatcherExpectedENV {
			rtest.ExpectEnv(podWatcherEnv, expected.Name, expected.Value)
		}

		Expect(*podWatcher.Containers[0].SecurityContext.Privileged).To(BeTrue())

		podWatcherVMs := podWatcher.Containers[0].VolumeMounts
		podWatcherExpectedVMs := []corev1.VolumeMount{
			{
				Name:      certificatemanagement.TrustedCertConfigMapName,
				MountPath: certificatemanagement.TrustedCertVolumeMountPath,
			},
			{
				Name:      rcimageassurance.ImageAssuranceSecretName,
				MountPath: rcimageassurance.CAMountPath,
			},
		}

		Expect(len(podWatcherExpectedVMs)).To(Equal(len(podWatcherVMs)))
		for _, expected := range podWatcherExpectedVMs {
			rtest.ExpectVolumeMount(podWatcherVMs, expected.Name, expected.MountPath)
		}
	})

	It("should API resource correctly with Authentication Enabled", func() {
		// Should render the correct resources.
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"}}}

		var dexCfg = render.NewDexKeyValidatorConfig(authentication, nil, dns.DefaultClusterDomain)

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
			TrustedCertBundle:         bundle,
			KeyValidatorConfig:        dexCfg,
			TenantEncryptionKeySecret: &tenantEncryptionKeySecret,
		})

		createdResources, _ := component.Objects()
		Expect(component.ResolveImages(nil)).To(BeNil())
		Expect(createdResources).To(HaveLen(len(expectedCreatedResources)), fmt.Sprintf("had length %d", len(createdResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedCreatedResources {
			rtest.ExpectResource(createdResources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// Check rendering of api deployment.
		apiProxyDeployment := rtest.GetResource(createdResources, imageassurance.APIProxyResourceName, imageassurance.NameSpaceImageAssurance,
			"apps", "v1", "Deployment").(*appsv1.Deployment)
		apiProxyPodSpec := apiProxyDeployment.Spec.Template.Spec

		Expect(apiProxyPodSpec.HostNetwork).To(BeFalse())
		Expect(apiProxyPodSpec.HostIPC).To(BeFalse())
		Expect(apiProxyPodSpec.DNSPolicy).To(Equal(corev1.DNSClusterFirst))
		Expect(len(apiProxyPodSpec.Containers)).To(Equal(1))

		apiEnvs := apiProxyPodSpec.Containers[0].Env
		apiExpectedENV := append(apiExpectedCommonENV, apiExpectedOIDCENV...)

		Expect(len(apiExpectedENV)).To(Equal(len(apiProxyPodSpec.Containers[0].Env)))
		for _, expected := range apiExpectedENV {
			rtest.ExpectEnv(apiEnvs, expected.Name, expected.Value)
		}

		apiVMs := apiProxyPodSpec.Containers[0].VolumeMounts

		Expect(apiProxyPodSpec.Containers[0].VolumeMounts).To(HaveLen(len(apiVMs)))
		for _, expected := range apiExpectedVolMounts {
			rtest.ExpectVolumeMount(apiVMs, expected.Name, expected.MountPath)
		}
	})
})
