// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	"fmt"
	"strings"

	"github.com/tigera/operator/pkg/render/common/clusterrole"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	NameSpaceImageAssurance              = "tigera-image-assurance"
	ResourceNameImageAssuranceAPI        = "tigera-image-assurance-api"
	ResourceNameImageAssuranceScanner    = "tigera-image-assurance-scanner"
	ResourceNameImageAssuranceDBMigrator = "tigera-image-assurance-db-migrator"
	ResourceNameImageAssuranceCAW        = "tigera-image-assurance-caw"
	ResourceNameImageAssurancePodWatcher = "tigera-image-assurance-pod-watcher"

	// APICertSecretName is tls certificates for the tigera-manager and the image assurance api.
	APICertSecretName = "tigera-image-assurance-api-cert-pair"

	ScannerClusterRoleName             = "tigera-image-assurance-scanner-api-access"
	ScannerClusterRoleBindingName      = "tigera-image-assurance-scanner-api-access"
	ScannerAPIAccessServiceAccountName = "tigera-image-assurance-scanner-api-access"
	ScannerAPIAccessSecretName         = "scanner-image-assurance-api-token"
	ScannerCLIClusterRoleName          = "tigera-image-assurance-scanner-cli-api-access"

	PodWatcherClusterRoleName             = "tigera-image-assurance-pod-watcher-api-access"
	PodWatcherClusterRoleBindingName      = "tigera-image-assurance-pod-watcher-api-access"
	PodWatcherAPIAccessServiceAccountName = "tigera-image-assurance-pod-watcher-api-access"
	PodWatcherAPIAccessSecretName         = "pod-watcher-image-assurance-api-token"

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
	tlsHash         string
	apiProxyImage   string
	scannerImage    string
	podWatcherImage string

	PodWatcherAPIAccessToken []byte

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

	c.config.podWatcherImage, err = components.GetReference(components.ComponentImageAssurancePodWatcher, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}

	return nil
}

// Objects returns Image Assurance resources to be created or deleted based c.config.NeedsMigrating and c.config.ComponentsUp.
// When both c.config.NeedsMigrating and c.config.ComponentsUp are true, we need to clean up the api, scanner and pod watcher deployments
// before proceeding. When only c.config.NeedsMigrating is true, return just the migrator job and associated resources.
// When both c.config.NeedsMigrating and c.config.ComponentsUp are false, return all resources.
// Right now we need to clean up CAW deployment for all circumstances because we stop supporting cloud-based scanning.
func (c *component) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object

	objs = append(objs,
		render.CreateNamespace(NameSpaceImageAssurance, c.config.Installation.KubernetesProvider),
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
	)

	objs = append(objs,
		c.podWatcherServiceAccount(),
		c.podWatcherRole(),
	)
	objs = append(objs, clusterrole.ToRuntimeObjects(c.podWatcherClusterRoles()...)...)
	objs = append(objs,
		c.podWatcherRoleBinding(),
		c.podWatcherClusterRoleBinding(),
		c.podWatcherAPIAccessTokenSecret(),
		c.podWatcherDeployment(),
	)

	if c.config.KeyValidatorConfig != nil {
		objs = append(objs, secret.ToRuntimeObjects(c.config.KeyValidatorConfig.RequiredSecrets(NameSpaceImageAssurance)...)...)
		objs = append(objs, configmap.ToRuntimeObjects(c.config.KeyValidatorConfig.RequiredConfigMaps(NameSpaceImageAssurance)...)...)
	}

	return objs, []client.Object{
		c.cawDeployment(),

		c.migratorServiceAccount(),
		c.migratorRole(),
		c.migratorRoleBinding(),
		c.migratorJob(),

		c.apiRole(),
		c.apiRoleBinding(),
		c.apiDeployment()}
}

func (c *component) Ready() bool {
	return true
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
