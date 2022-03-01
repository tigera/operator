package certificatemanagement

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	cmrender "github.com/tigera/operator/pkg/tls/certificatemanagement/render"
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
	// The service accounts that are mounting the key pairs and may issue CSRs if installation.CertificateManagement is used.
	ServiceAccounts []string
	KeyPairOptions  []KeyPairCreator
	Namespace       string
	TrustedBundle   cmrender.TrustedBundle
}

func NewKeyPairOption(keyPair cmrender.KeyPair, renderInOperatorNamespace, renderInNamespace bool) KeyPairCreator {
	return KeyPairCreator{
		keyPair:                   keyPair,
		renderInOperatorNamespace: renderInOperatorNamespace,
		renderInNamespace:         renderInNamespace,
	}
}

type KeyPairCreator struct {
	keyPair                   cmrender.KeyPair
	renderInOperatorNamespace bool
	renderInNamespace         bool
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
	for _, keyPairCreator := range c.cfg.KeyPairOptions {
		keyPair := keyPairCreator.keyPair
		if keyPair != nil {
			if keyPair.UseCertificateManagement() {
				if keyPairCreator.renderInOperatorNamespace {
					objsToDelete = append(objsToDelete, keyPair.Secret(common.OperatorNamespace()))
				}
				if keyPairCreator.renderInNamespace {
					objsToDelete = append(objsToDelete, keyPair.Secret(c.cfg.Namespace))
				}
				needsCSRRoleAndBinding = true
			} else {
				if keyPairCreator.renderInOperatorNamespace && !keyPair.BYO() {
					objsToCreate = append(objsToCreate, keyPair.Secret(common.OperatorNamespace()))
				}
				if keyPairCreator.renderInNamespace {
					objsToCreate = append(objsToCreate, keyPair.Secret(c.cfg.Namespace))
				}
			}
		}
	}
	if needsCSRRoleAndBinding {
		for _, sa := range c.cfg.ServiceAccounts {
			objsToCreate = append(objsToCreate, certificatemanagement.CSRClusterRoleBinding(sa, c.cfg.Namespace))
		}
	} else {
		for _, sa := range c.cfg.ServiceAccounts {
			objsToDelete = append(objsToDelete, certificatemanagement.CSRClusterRoleBinding(sa, c.cfg.Namespace))
		}
	}
	return
}

func (c component) Ready() bool {
	return true
}

func (c component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}
