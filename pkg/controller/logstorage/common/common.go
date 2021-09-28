package common

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/render/kubecontrollers"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/crypto"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
)

const (
	TigeraElasticsearchUserSecretLabel = "tigera-elasticsearch-user"
	DefaultElasticsearchShards         = 1

	// ESGatewaySelectorLabel is used to mark any secret containing credentials for ES gateway with this label key/value.
	// This will allow ES gateway to watch only the relevant secrets it needs.
	ESGatewaySelectorLabel      = "esgateway.tigera.io/secrets"
	ESGatewaySelectorLabelValue = "credentials"
)

// CreateKubeControllersSecrets checks for the existence of the secrets necessary for Kube controllers to access Elasticsearch through ES gateway and
// creates them if they are missing. Kube controllers no longer uses admin credentials to make requests directly to Elasticsearch. Instead, gateway credentials
// are generated and stored in the user secret, a hashed version of the credentials is stored in the tigera-elasticsearch namespace for ES Gateway to retrieve and use to compare
// the gateway credentials, and a secret containing real admin level credentials is created and stored in the tigera-elasticsearch namespace to be swapped in once
// ES Gateway has confirmed that the gateway credentials match.
func CreateKubeControllersSecrets(ctx context.Context, esAdminUserSecret *corev1.Secret, esAdminUserName string, cli client.Client) (*corev1.Secret, *corev1.Secret, *corev1.Secret, error) {
	kubeControllersGatewaySecret, err := utils.GetSecret(ctx, cli, kubecontrollers.ElasticsearchKubeControllersUserSecret, common.OperatorNamespace())
	if err != nil {
		return nil, nil, nil, err
	}
	if kubeControllersGatewaySecret == nil {
		password := crypto.GeneratePassword(16)
		kubeControllersGatewaySecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubecontrollers.ElasticsearchKubeControllersUserSecret,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"username": []byte(kubecontrollers.ElasticsearchKubeControllersUserName),
				"password": []byte(password),
			},
		}
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(kubeControllersGatewaySecret.Data["password"], bcrypt.MinCost)
	if err != nil {
		return nil, nil, nil, err
	}

	kubeControllersVerificationSecret, err := utils.GetSecret(ctx, cli, kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret, render.ElasticsearchNamespace)
	if err != nil {
		return nil, nil, nil, err
	}
	if kubeControllersVerificationSecret == nil {
		kubeControllersVerificationSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubecontrollers.ElasticsearchKubeControllersVerificationUserSecret,
				Namespace: render.ElasticsearchNamespace,
				Labels: map[string]string{
					ESGatewaySelectorLabel: ESGatewaySelectorLabelValue,
				},
			},
			Data: map[string][]byte{
				"username": []byte(kubecontrollers.ElasticsearchKubeControllersUserName),
				"password": hashedPassword,
			},
		}
	}

	kubeControllersSecureUserSecret, err := utils.GetSecret(ctx, cli, kubecontrollers.ElasticsearchKubeControllersSecureUserSecret, render.ElasticsearchNamespace)
	if err != nil {
		return nil, nil, nil, err
	}
	if kubeControllersSecureUserSecret == nil {
		kubeControllersSecureUserSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubecontrollers.ElasticsearchKubeControllersSecureUserSecret,
				Namespace: render.ElasticsearchNamespace,
				Labels: map[string]string{
					ESGatewaySelectorLabel: ESGatewaySelectorLabelValue,
				},
			},
			Data: map[string][]byte{
				"username": []byte(esAdminUserName),
				"password": esAdminUserSecret.Data[esAdminUserName],
			},
		}
	}

	return kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, nil
}

// GetESGatewayCertificateSecrets retrieves certificate secrets needed for ES Gateway to run or for
// components to communicate with Elasticsearch/Kibana through ES Gateway. The order of the secrets returned are:
// 1) The certificate/key secret to be mounted by ES Gateway and used to authenticate requests before
// proxying to Elasticsearch/Kibana (in the operator namespace). If the user didn't create this secret, it is created.
// 2) The certificate mounted by other clients that connect to Elasticsearch/Kibana through ES Gateway (in the operator namespace).
// The final return value is used to indicate that the certificate secret was provided by the customer. This
// ensures that we do not re-render the secret in the Operator Namespace and overwrite the OwnerReference.
func GetESGatewayCertificateSecrets(ctx context.Context, instl *operatorv1.InstallationSpec, cli client.Client, clusterDomain string, log logr.Logger) (*corev1.Secret, *corev1.Secret, bool, error) {
	var publicCertSecret *corev1.Secret

	svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, clusterDomain)
	svcDNSNames = append(svcDNSNames, dns.GetServiceDNSNames(esgateway.ServiceName, render.ElasticsearchNamespace, clusterDomain)...)

	// Get the secret - might be nil
	oprKeyCert, err := utils.GetSecret(ctx, cli, render.TigeraElasticsearchCertSecret, common.OperatorNamespace())
	if err != nil {
		return nil, nil, false, err
	}

	// Ensure that cert is valid.
	oprKeyCert, err = utils.EnsureCertificateSecret(render.TigeraElasticsearchCertSecret, oprKeyCert, corev1.TLSPrivateKeyKey, corev1.TLSCertKey, rmeta.DefaultCertificateDuration, svcDNSNames...)
	if err != nil {
		return nil, nil, false, err
	}

	// Three different certificate issuers are possible:
	// - The operator self-signed certificate
	// - A user's BYO keypair for Elastic (uncommon)
	// - The issuer that is provided through the certificate management feature.
	keyCertIssuer, err := utils.GetCertificateIssuer(oprKeyCert.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, nil, false, err
	}
	customerProvidedCert := !utils.IsOperatorIssued(keyCertIssuer)

	// If Certificate management is enabled, we only want to trust the CA cert and let the init container handle private key generation.
	if instl.CertificateManagement != nil {
		cmCa := instl.CertificateManagement.CACert
		cmIssuer, err := utils.GetCertificateIssuer(cmCa)
		if err != nil {
			return nil, nil, false, err
		}

		// If the issuer of the current secret is not the same as the certificate management issuer and also is not
		// issued by the tigera-operator, it means that it is added to this cluster by the customer. This is not supported
		// in combination with certificate management.
		if customerProvidedCert && cmIssuer != keyCertIssuer {
			return nil, nil, false, fmt.Errorf("certificate management does not support custom Elasticsearch secrets, please delete secret %s/%s or disable certificate management", oprKeyCert.Namespace, oprKeyCert.Name)
		}

		oprKeyCert.Data[corev1.TLSCertKey] = instl.CertificateManagement.CACert
		publicCertSecret = render.CreateCertificateSecret(instl.CertificateManagement.CACert, relasticsearch.PublicCertSecret, common.OperatorNamespace())
	} else {
		publicCertSecret = render.CreateCertificateSecret(oprKeyCert.Data[corev1.TLSCertKey], relasticsearch.PublicCertSecret, common.OperatorNamespace())
	}

	return oprKeyCert, publicCertSecret, customerProvidedCert, nil
}

// DeleteInvalidECKManagedPublicCertSecret deletes the given ECK managed cert secret.
func DeleteInvalidECKManagedPublicCertSecret(ctx context.Context, secret *corev1.Secret, cli client.Client, log logr.Logger) error {
	log.Info(fmt.Sprintf("Deleting invalid cert secret %q in %q namespace", secret.Name, secret.Namespace))
	return cli.Delete(ctx, secret)
}

func CalculateFlowShards(nodesSpecifications *operatorv1.Nodes, defaultShards int) int {
	if nodesSpecifications == nil || nodesSpecifications.ResourceRequirements == nil || nodesSpecifications.ResourceRequirements.Requests == nil {
		return defaultShards
	}

	var nodes = nodesSpecifications.Count
	var cores, _ = nodesSpecifications.ResourceRequirements.Requests.Cpu().AsInt64()
	var shardPerNode = int(cores) / 4

	if nodes <= 0 || shardPerNode <= 0 {
		return defaultShards
	}

	return int(nodes) * shardPerNode
}
