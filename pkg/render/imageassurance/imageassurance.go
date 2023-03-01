// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package imageassurance

import (
	"fmt"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/clusterrole"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	NameSpaceImageAssurance                  = "tigera-image-assurance"
	ResourceNameImageAssuranceAPI            = "tigera-image-assurance-api"
	ResourceNameImageAssuranceScanner        = "tigera-image-assurance-scanner"
	ResourceNameImageAssuranceDBMigrator     = "tigera-image-assurance-db-migrator"
	ResourceNameImageAssuranceCAW            = "tigera-image-assurance-caw"
	ResourceNameImageAssurancePodWatcher     = "tigera-image-assurance-pod-watcher"
	ResourceNameImageAssuranceRuntimeCleaner = "tigera-image-assurance-runtime-cleaner"

	// APICertSecretName is tls certificates for the tigera-manager and the image assurance api.
	APICertSecretName = "tigera-image-assurance-api-cert-pair"

	ScannerAPIAccessResourceName = "tigera-image-assurance-scanner-api-access"
	ScannerAPIAccessSecretName   = "scanner-image-assurance-api-token"
	ScannerCLIClusterRoleName    = "tigera-image-assurance-scanner-cli-api-access"

	PodWatcherClusterRoleName     = "tigera-image-assurance-pod-watcher-api-access"
	PodWatcherAPIAccessSecretName = "pod-watcher-image-assurance-api-token"

	RuntimeCleanerAPIAccessResourceName = "tigera-image-assurance-runtime-cleaner-api-access"
	RuntimeCleanerAPIAccessSecretName   = "runtime-cleaner-image-assurance-api-token"

	OperatorAPIAccessServiceAccountName = "tigera-image-assurance-operator-api-access"

	mountPathAPITLSCerts = "/certs/https/"

	CalicoCloudAuthSecretName = "tigera-calico-cloud-client-credentials"
)

func ImageAssurance(
	config *Config,
) render.Component {
	// self signed TLS cert, key to enable https on image assurance api.
	ts := secret.CopyToNamespace(NameSpaceImageAssurance, config.TLSSecret)[0]
	tlsHash := rmeta.AnnotationHash(config.TLSSecret.Data)
	config.TLSSecret = ts
	config.tlsHash = tlsHash

	return &component{
		config: config,
	}
}

// Config contains all the config information ImageAssurance needs to render component.
type Config struct {
	// Required config.
	PullSecrets  []*corev1.Secret
	Installation *operatorv1.InstallationSpec
	OsType       rmeta.OSType

	// ConfigMap contains database host, port, name.
	ConfigurationConfigMap *corev1.ConfigMap
	TLSSecret              *corev1.Secret
	TrustedCertBundle      certificatemanagement.TrustedBundle
	KeyValidatorConfig     authentication.KeyValidatorConfig
	ScannerAPIAccessToken  []byte

	// Calculated internal fields.
	tlsHash             string
	apiProxyImage       string
	scannerImage        string
	runtimeCleanerImage string

	RuntimeCleanerAPIAccessToken []byte

	APIProxyURL string
}

type component struct {
	config *Config
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.config.Installation.Registry
	path := c.config.Installation.ImagePath
	prefix := c.config.Installation.ImagePrefix

	if c.config.OsType != c.SupportedOSType() {
		return fmt.Errorf("image assurance is supported only on %s", c.SupportedOSType())
	}

	var err error
	var errMsgs []string

	c.config.apiProxyImage, err = components.GetReference(components.ComponentImageAssuranceApiProxy, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.scannerImage, err = components.GetReference(components.ComponentImageAssuranceScanner, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.runtimeCleanerImage, err = components.GetReference(components.ComponentImageAssuranceRuntimeCleaner, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}

	return nil
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object

	objs = append(objs,
		render.CreateNamespace(NameSpaceImageAssurance, c.config.Installation.KubernetesProvider, render.PSSPrivileged),
	)

	objs = append(objs, configmap.ToRuntimeObjects(
		configmap.CopyToNamespace(NameSpaceImageAssurance, c.config.ConfigurationConfigMap)...,
	)...)

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.PullSecrets...)...)...)

	// certificate pair for image assurance api tls
	objs = append(objs, secret.ToRuntimeObjects(c.config.TLSSecret)...)

	objs = append(objs,
		c.apiServiceAccount(),
		c.apiClusterRole(),
		c.apiClusterRoleBinding(),
		c.apiService(APIProxyResourceName),
		c.apiProxyDeployment(),
	)

	// scanner resources
	objs = append(objs,
		c.scannerServiceAccount(),
		c.scannerRole(),
		c.scannerClusterRole(),
		c.scannerCLIClusterRole(),
		c.scannerRoleBinding(),
		c.scannerAPIAccessTokenSecret(),
		c.scannerDeployment(),
	)

	// admission controller resources
	objs = append(objs,
		c.admissionControllerClusterRole(),
		c.crAdaptorClusterRole(),
	)

	objs = append(objs, c.operatorClusterRole())

	// Keep the cluster roles (now empty) so kube controllers doesn't fail when it can't find them.
	// TODO Remove once kube controllers no longer relies on this.
	objs = append(objs, clusterrole.ToRuntimeObjects(c.podWatcherClusterRoles()...)...)

	// runtime cleaner resources
	objs = append(objs,
		c.runtimeCleanerServiceAccount(),
		c.runtimeCleanerRole(),
	)
	objs = append(objs, clusterrole.ToRuntimeObjects(c.runtimeCleanerClusterRoles()...)...)
	objs = append(objs,
		c.runtimeCleanerRoleBinding(),
		c.runtimeCleanerClusterRoleBinding(),
		c.runtimeCleanerAPIAccessTokenSecret(),
		c.runtimeCleanerDeployment(),
	)

	if c.config.KeyValidatorConfig != nil {
		objs = append(objs, secret.ToRuntimeObjects(c.config.KeyValidatorConfig.RequiredSecrets(NameSpaceImageAssurance)...)...)
		objs = append(objs, configmap.ToRuntimeObjects(c.config.KeyValidatorConfig.RequiredConfigMaps(NameSpaceImageAssurance)...)...)
	}

	objsToDelete := []client.Object{
		c.cawDeployment(),

		c.migratorServiceAccount(),
		c.migratorRole(),
		c.migratorRoleBinding(),
		c.migratorJob(),

		c.apiRole(),
		c.apiRoleBinding(),
		c.apiDeployment()}

	objsToDelete = append(objsToDelete,
		c.podWatcherServiceAccount(),
		c.podWatcherRole(),
	)

	objsToDelete = append(objsToDelete,
		c.podWatcherRoleBinding(),
		c.podWatcherClusterRoleBinding(),
		c.podWatcherAPIAccessTokenSecret(),
		c.podWatcherDeployment(),
	)

	return objs, objsToDelete
}

func (c *component) Ready() bool {
	return true
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
