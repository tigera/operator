// This file contains functions common to the controllers to help them interace with elasticsearch.
package utils

import (
	"context"
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DefaultClusterName = "cluster"
)

// ElasticsearchSecrets gets the secrets needed for a component to be able to access Elasticsearch
func ElasticsearchSecrets(ctx context.Context, esUsernames []string, cli client.Client) ([]*corev1.Secret, error) {
	var esUserSecrets []*corev1.Secret
	for _, esUsername := range esUsernames {
		esUser, err := esusers.GetUser(esUsername)
		if err != nil {
			return nil, err
		}
		esUserSecret := &corev1.Secret{}
		err = cli.Get(ctx, types.NamespacedName{
			Name:      esUser.SecretName(),
			Namespace: render.OperatorNamespace(),
		}, esUserSecret)
		if err != nil {
			return nil, err
		}

		esUserSecrets = append(esUserSecrets, esUserSecret)
	}

	esCertSecret := &corev1.Secret{}
	err := cli.Get(ctx, types.NamespacedName{
		Name:      render.ElasticsearchPublicCertSecret,
		Namespace: render.OperatorNamespace(),
	}, esCertSecret)
	if err != nil {
		return nil, err
	}

	return append(esUserSecrets, esCertSecret), nil
}

func ClusterName(ctx context.Context, cli client.Client) (string, error) {
	// TODO grab the cluster name from a secret instead of using the default
	return DefaultClusterName, nil
}
