// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	"fmt"
	"github.com/tigera/operator/pkg/render/common/clusterrole"
	"strings"

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

	PGConfigMapName  = "tigera-image-assurance-postgres"
	PGCertSecretName = "tigera-image-assurance-postgres-cert"

	// PGAdminUserSecretName corresponds to the secret containing the admin postgres credentials that are only used by the db-migrator
	// to run database migrations and create users for Image Assurance customers.
	PGAdminUserSecretName = "tigera-image-assurance-postgres-admin-user"
	// PGUserSecretName corresponds to the secret containing the customer credentials that are generated by operator and used by
	// other Image Assurance components to access the Postgres database restricted to the customer schema.
	PGUserSecretName = "tigera-image-assurance-postgres-user"

	// tls certificates for tigera-manager and image assurance api
	APICertSecretName = "tigera-image-assurance-api-cert-pair"

	ScannerClusterRoleName             = "tigera-image-assurance-scanner-api-access"
	ScannerAPIAccessServiceAccountName = "tigera-image-assurance-scanner-api-access"
	ScannerAPIAccessSecretName         = "scanner-image-assurance-api-token"

	PodWatcherClusterRoleName             = "tigera-image-assurance-pod-watcher-api-access"
	PodWatcherAPIAccessServiceAccountName = "tigera-image-assurance-pod-watcher-api-access"
	PodWatcherAPIAccessSecretName         = "pod-watcher-image-assurance-api-token"

	MountPathPostgresCerts = "/certs/db/"
	mountPathAPITLSCerts   = "/certs/https/"

	TenantEncryptionKeySecretName  = "tigera-secure-bast-tenant-key"
	EncryptionKey                  = "encryption_key"
	MountTenantEncryptionKeySecret = "/tenant-key/"

	pgConfigHashAnnotation        = "hash.operator.tigera.io/pgconfig"
	pgUserHashAnnotation          = "hash.operator.tigera.io/pguser"
	pgCertsHashAnnotation         = "hash.operator.tigera.io/pgcerts"
	pgAdminUserHashAnnotation     = "hash.operator.tigera.io/pgadminuser"
	apiCertHashAnnotation         = "hash.operator.tigera.io/apicerts"
	tenantKeySecretHashAnnotation = "hash.operator.tigera.io/tenantkeysecret"
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
	PullSecrets       []*corev1.Secret
	Installation      *operatorv1.InstallationSpec
	OsType            rmeta.OSType
	PGAdminUserSecret *corev1.Secret
	PGUserSecret      *corev1.Secret
	PGCertSecret      *corev1.Secret
	// ConfigMap contains database host, port, name.
	ConfigurationConfigMap    *corev1.ConfigMap
	PGConfig                  *corev1.ConfigMap
	TLSSecret                 *corev1.Secret
	TrustedCertBundle         certificatemanagement.TrustedBundle
	KeyValidatorConfig        authentication.KeyValidatorConfig
	TenantEncryptionKeySecret *corev1.Secret
	ScannerAPIAccessToken     []byte

	NeedsMigrating bool
	ComponentsUp   bool

	// Calculated internal fields.
	tlsHash         string
	apiImage        string
	scannerImage    string
	migratorImage   string
	cawImage        string
	podWatcherImage string

	PodWatcherAPIAccessToken []byte
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

	c.config.apiImage, err = components.GetReference(components.ComponentImageAssuranceApi, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.scannerImage, err = components.GetReference(components.ComponentImageAssuranceScanner, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.migratorImage, err = components.GetReference(components.ComponentImageAssuranceDBMigrator, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.cawImage, err = components.GetReference(components.ComponentImageAssuranceCAW, reg, path, prefix, is)
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
// When both c.config.NeedsMigrating and c.config.ComponentsUp are true, we need to clean up the api, scanner and CAW deployments
// before proceeding. When only c.config.NeedsMigrating is true, return just the migrator job and associated resources.
// When both c.config.NeedsMigrating and c.config.ComponentsUp are false, return all resources.
func (c *component) Objects() (objsToCreate, objsToDelete []client.Object) {
	var objs []client.Object

	if c.config.NeedsMigrating && c.config.ComponentsUp {
		// TODO: deleting the migratorJob is a temporary measure, once we extend the componenthandler
		// to handle updating a job by comparing spec fields rather than just the annotations, we can remove
		// this deletion. https://tigera.atlassian.net/browse/CNX-15687.
		return nil, []client.Object{
			c.migratorJob(),
			c.apiDeployment(),
			c.scannerDeployment(),
			c.cawDeployment(),
			c.podWatcherDeployment(),
		}
	}

	objs = append(objs,
		render.CreateNamespace(NameSpaceImageAssurance, c.config.Installation.KubernetesProvider),
	)

	// PostgreSQL cert secret for image assurance.
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.PGCertSecret)...)...)
	// Operator generated PostgreSQL credentials for image assurance components.
	objs = append(objs, secret.ToRuntimeObjects(c.config.PGUserSecret)...)
	// Admin PostgreSQL user, only used by the migrator.
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.PGAdminUserSecret)...)...)
	objs = append(objs, configmap.ToRuntimeObjects(
		configmap.CopyToNamespace(NameSpaceImageAssurance, c.config.PGConfig, c.config.ConfigurationConfigMap)...,
	)...)

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.PullSecrets...)...)...)

	// Migrator resources.
	objs = append(objs,
		c.migratorServiceAccount(),
		c.migratorRole(),
		c.migratorRoleBinding(),
		c.migratorJob(),
	)

	if c.config.NeedsMigrating {
		return objs, nil
	}

	// certificate pair for image assurance api tls
	objs = append(objs, secret.ToRuntimeObjects(c.config.TLSSecret)...)

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.TenantEncryptionKeySecret)...)...)

	// api resources
	objs = append(objs,
		c.apiServiceAccount(),
		c.apiRole(),
		c.apiRoleBinding(),
		c.apiClusterRole(),
		c.apiClusterRoleBinding(),
		c.apiService(),
		c.apiDeployment(),
	)

	// scanner resources
	objs = append(objs,
		c.scannerServiceAccount(),
		c.scannerRole(),
		c.scannerClusterRole(),
		c.scannerRoleBinding(),
		c.scannerAPIAccessTokenSecret(),
		c.scannerDeployment(),
	)

	// caw resources
	objs = append(objs,
		c.cawServiceAccount(),
		c.cawRole(),
		c.cawRoleBinding(),
		c.cawDeployment(),
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

	return objs, nil
}

func (c *component) Ready() bool {
	return true
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
