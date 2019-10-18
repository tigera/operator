// This file contains all code relevant for the interaction between the log-storage controller and elasticsearch. It uses
// the elasticsearch package to create, update, and retrieve elasticsearch users
package logstorage

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/elasticsearch"
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ElasticsearchUserPasswordLength = 100
	DefaultElasticsearchUser        = "elastic"
	ElasticsearchUserSecret         = "tigera-secure-es-elastic-user"
	ElasticsearchHTTPSEndpoint      = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
)

// updatedElasticsearchUserSecrets creates / updates all the Elasticsearch users returned by esusers.GetUsers with the username
// and password found in the users corresponding secret and the roles attached to that user. If there is no secret for an
// es user then the secret is generated and populated with the username and randomly, securely, generated password. Only
// secrets that need to be created or updated are returned by this function.
func updatedElasticsearchUserSecrets(ctx context.Context, rootsSecret *corev1.Secret, cli client.Client) ([]*corev1.Secret, error) {
	var secrets []*corev1.Secret
	esUserSecret := &corev1.Secret{}
	err := cli.Get(context.Background(), types.NamespacedName{
		Name:      ElasticsearchUserSecret,
		Namespace: render.ElasticsearchNamespace,
	}, esUserSecret)
	if err != nil {
		return nil, err
	}
	for _, esUser := range esusers.GetUsers() {
		userSecret := &corev1.Secret{}
		if err := cli.Get(ctx, client.ObjectKey{Name: esUser.SecretName(), Namespace: render.OperatorNamespace()}, userSecret); err != nil {
			log.V(2).Info(fmt.Sprintf("Didn't find existing Elasticsearch user secret for component %s, generating new password for elasticsearch user", esUser.Username))
			if errors.IsNotFound(err) {
				esUser.Password, err = utils.RandomPassword(ElasticsearchUserPasswordLength)
				if err != nil {
					return nil, err
				}
				secrets = append(secrets, createESUserSecret(esUser))
			} else {
				return nil, err
			}
		} else {
			log.V(2).Info(fmt.Sprintf("Found existing Elasticsearch user secret for component %s", esUser.Username))
			if password, exists := userSecret.Data["password"]; !exists {
				esUser.Password, err = utils.RandomPassword(ElasticsearchUserPasswordLength)
				if err != nil {
					return nil, err
				}
				secrets = append(secrets, createESUserSecret(esUser))
			} else {
				esUser.Password = string(password)
			}
		}

		roots, err := getESRoots(rootsSecret)
		if err != nil {
			return nil, err
		}

		if err := upsertElasticsearchUser(ElasticsearchHTTPSEndpoint, esUser, roots, esUserSecret); err != nil {
			return nil, err
		}
	}

	return secrets, nil
}

func createESUserSecret(user elasticsearch.User) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      user.SecretName(),
			Namespace: render.OperatorNamespace(),
		},
		Data: map[string][]byte{
			"username": []byte(user.Username),
			"password": []byte(user.Password),
		},
	}
}

// upsertElasticsearchUser creates or updates an elasticsearch user as well as the roles it needs to have
func upsertElasticsearchUser(esURL string, user elasticsearch.User, roots *x509.CertPool, esUserSecret *corev1.Secret) error {
	var esCli *elasticsearch.Client
	var err error
	if esDefaultPassword, exists := esUserSecret.Data[DefaultElasticsearchUser]; exists {
		esCli, err = elasticsearch.NewClient(esURL, DefaultElasticsearchUser, string(esDefaultPassword), roots)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("couldn't find the default elasticsearch password")
	}

	if exists, err := esCli.UserExists(user.Username); err != nil {
		return err
	} else if exists {
		// Since we can't get the password for an existing user we need to updated it with one we know
		if err := esCli.CreateUser(user); err != nil {
			return err
		}
	} else {
		if err := esCli.UpdateUser(user); err != nil {
			return err
		}
	}

	return nil
}

func getESRoots(esCertSecret *corev1.Secret) (*x509.CertPool, error) {
	rootPEM, exists := esCertSecret.Data["tls.crt"]
	if !exists {
		return nil, fmt.Errorf("Couldn't find tls.crt in Elasticsearch secret %s to create Elasticsearch client", render.ElasticsearchPublicCertSecret)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		return nil, fmt.Errorf("Failed to parse root certificate for Elasticsearch client")
	}

	return roots, nil
}
