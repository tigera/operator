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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ElasticsearchUserPasswordLength = 100
	DefaultElasticsearchUser        = "elastic"
	ElasticsearchUserSecret         = "tigera-secure-es-elastic-user"
	ElasticsearchHTTPEndpoint       = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
)

// elasticsearchUsers creates / updates all the Elasticsearch users returned by esusers.GetUsers, along with the roles attached
// to those users. The users return by esusers.GetUsers are registered through calling esusers.AddUser with an Elasticsearch
// user.
func elasticsearchUsers(ctx context.Context, rootsSecret *corev1.Secret, cli client.Client) ([]elasticsearch.User, error) {
	var users []elasticsearch.User
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
			} else {
				esUser.Password = string(password)
			}
		}

		roots, err := getESRoots(rootsSecret)
		if err != nil {
			return nil, err
		}

		if err := upsertElasticsearchUser(ElasticsearchHTTPEndpoint, esUser, roots, esUserSecret); err != nil {
			return nil, err
		}
		users = append(users, esUser)
	}

	return users, nil
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
