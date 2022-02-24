package certificatemanagement

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateManagement renders your KeyPairs and TrustedBundle, thereby simplifying other render components.
func CertificateManagement(
	cfg *Config,
) render.Component {
	return &component{
		cfg: cfg,
	}
}

// Config contains all the config CertificateManagement needs to render objects.
type Config struct {
	// The service account that is mounting the key pairs and may issue CSRs if installation.CertificateManagement is used.
	ServiceAccountName string
	Namespace          string
	KeyPairs           []certificatemanagement.KeyPair
	TrustedBundle      certificatemanagement.TrustedBundle
}

type component struct {
	cfg *Config
}

func (c component) ResolveImages(*operatorv1.ImageSet) error {
	return nil
}

func (c component) Objects() (objsToCreate, objsToDelete []client.Object) {
	if c.cfg.TrustedBundle != nil {
		objsToCreate = append(objsToCreate, c.cfg.TrustedBundle.ConfigMap(c.cfg.Namespace))
	}
	var needsCSRRoleAndBinding bool
	for _, keyPair := range c.cfg.KeyPairs {
		if keyPair != nil {
			if keyPair.UseCertificateManagement() {
				needsCSRRoleAndBinding = true
				objsToDelete = append(objsToDelete, keyPair.Secret(c.cfg.Namespace))
			} else {
				objsToCreate = append(objsToCreate, keyPair.Secret(c.cfg.Namespace))
				if !keyPair.HasSkipRenderInOperatorNamespace() {
					objsToCreate = append(objsToCreate, keyPair.Secret(common.OperatorNamespace()))
				}
			}
		}
	}
	if needsCSRRoleAndBinding {
		objsToCreate = append(objsToCreate, certificatemanagement.CSRClusterRoleBinding(c.cfg.ServiceAccountName, c.cfg.Namespace))
	} else {
		objsToDelete = append(objsToDelete, certificatemanagement.CSRClusterRoleBinding(c.cfg.ServiceAccountName, common.TigeraPrometheusNamespace))
	}
	return
}

func (c component) Ready() bool {
	return true
}

func (c component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}
