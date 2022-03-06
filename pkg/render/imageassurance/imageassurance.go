// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	"fmt"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	NameSpaceImageAssurance           = "tigera-image-assurance"
	ResourceNameImageAssuranceAPI     = "tigera-image-assurance-api"
	ResourceNameImageAssuranceScanner = "tigera-image-assurance-scanner"

	// secrets copied from operator namespace
	PGConfigMapName  = "tigera-image-assurance-postgres"
	PGUserSecretName = "tigera-image-assurance-postgres-user"
	PGCertSecretName = "tigera-image-assurance-postgres-cert"

	// tls certificates for tigera-manager and image assurance api
	APICertSecretName     = "tigera-image-assurance-api-cert-pair"
	ManagerCertSecretName = "internal-manager-tls"

	VoltronCertSecretName    = "tigera-image-assurance-api-cert-key"
	mountPathPostgresCerts   = "/certs/db/"
	mountPathAPITLSCerts     = "/certs/https/"
	mountPathManagerTLSCerts = "/manager-tls/"

	pgConfigHashAnnotation    = "hash.operator.tigera.io/pgconfig"
	pgUserHashAnnotation      = "hash.operator.tigera.io/pguser"
	pgCertsHashAnnotation     = "hash.operator.tigera.io/pgcerts"
	apiCertHashAnnotation     = "hash.operator.tigera.io/apicerts"
	managerCertHashAnnotation = "hash.operator.tigera.io/managercerts"
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
	PGUserSecret *corev1.Secret
	PGCertSecret *corev1.Secret
	// ConfigMap contains database host, port, name.
	PGConfig          *corev1.ConfigMap
	TLSSecret         *corev1.Secret
	InternalMgrSecret *corev1.Secret

	// Calculated internal fields.
	tlsHash      string
	apiImage     string
	scannerImage string
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

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}

	return nil
}

func (c *component) Objects() (objsToCreate, objsToDelete []client.Object) {
	var objs []client.Object

	// create namespace
	objs = append(objs,
		render.CreateNamespace(NameSpaceImageAssurance, c.config.Installation.KubernetesProvider),
	)

	// certificate pair for image assurance api tls
	objs = append(objs, secret.ToRuntimeObjects(c.config.TLSSecret)...)
	// passing image assurance api tls cert key to voltron for api->voltron https communication
	objs = append(objs, c.voltronSecrets(c.config.TLSSecret))
	// PostgreSQL secret for image assurance api to connect
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.PGCertSecret)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.PGUserSecret)...)...)
	objs = append(objs, configmap.ToRuntimeObjects(configmap.CopyToNamespace(NameSpaceImageAssurance, c.config.PGConfig)...)...)

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.InternalMgrSecret)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(NameSpaceImageAssurance, c.config.PullSecrets...)...)...)

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
		c.scannerRoleBinding(),
		c.scannerDeployment(),
	)

	return objs, nil
}

func (c *component) Ready() bool {
	return true
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) voltronSecrets(tls *corev1.Secret) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: VoltronCertSecretName, Namespace: render.ManagerNamespace},
		Data: map[string][]byte{
			corev1.TLSCertKey: tls.Data[corev1.TLSCertKey],
		},
	}
}
