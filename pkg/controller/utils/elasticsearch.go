package utils

import (
	"context"
	"fmt"
	"github.com/tigera/operator/pkg/controller/elasticsearchaccess"
	"github.com/tigera/operator/pkg/elasticsearch"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DefaultElasticsearchUser       = "elastic"
	ElasticsearchUserSecret        = "tigera-secure-es-elastic-user"
	ElasticsearchHTTPEndpoint      = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
	DefaultElasticsearchCertSecret = "tigera-secure-es-http-certs-public"
)

func ElastisearchUsers(ctx context.Context, cli client.Client) (render.Component, error) {
	users := map[string]*elasticsearch.User{}
	for _, esComponent := range elasticsearchaccess.GetComponents() {
		if err := cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchNamespace}, &corev1.Namespace{}); err != nil {
			return nil, err
		} else if err := cli.Get(ctx, client.ObjectKey{Name: esComponent.SecretName(), Namespace: render.ElasticsearchNamespace}, &corev1.Secret{}); err != nil {
			if errors.IsNotFound(err) {
				user, err := UpsertElasticsearchComponentUser(ElasticsearchHTTPEndpoint, esComponent.Name(), esComponent.Roles(), cli)
				if err != nil {
					return nil, err
				}
				users[esComponent.SecretName()] = user
			} else {
				return nil, err
			}
			// TODO it might not be enough for the secret to just exist, we should validate the ES creds work (SASS-389)
		}
	}

	return render.ElasticsearchUsers(users), nil
}

func ElasticsearchAccess(ctx context.Context, componentUserSecret string, namespace string, esCertSecretRef *corev1.SecretReference, cli client.Client) (render.Component, error) {
	esUserSecret := &corev1.Secret{}
	err := cli.Get(ctx, types.NamespacedName{
		Name:      componentUserSecret,
		Namespace: render.ElasticsearchNamespace,
	}, esUserSecret)
	if err != nil {
		return nil, err
	}

	esCertSecretName := DefaultElasticsearchCertSecret

	if esCertSecretRef != nil {
		esCertSecretName = esCertSecretRef.Name
	}

	esCertSecret := &corev1.Secret{}
	err = cli.Get(ctx, types.NamespacedName{
		Name:      esCertSecretName,
		Namespace: render.ElasticsearchNamespace,
	}, esCertSecret)
	if err != nil {
		return nil, err
	}

	esConfigMap := &corev1.ConfigMap{}
	err = cli.Get(ctx, types.NamespacedName{
		Name:      "tigera-es-config",
		Namespace: "calico-monitoring",
	}, esConfigMap)
	if err != nil {
		return nil, err
	}

	return render.ElasticsearchAccess(namespace, *esUserSecret, *esCertSecret, *esConfigMap), nil
}

// UpsertElasticsearchComponentUser creates or updates an elasticsearch user
func UpsertElasticsearchComponentUser(esURL string, componentName string, roles []elasticsearch.Role, cli client.Client) (*elasticsearch.User, error) {
	secret := &corev1.Secret{}
	err := cli.Get(context.TODO(), types.NamespacedName{
		Name:      ElasticsearchUserSecret,
		Namespace: render.ElasticsearchNamespace,
	}, secret)
	if err != nil {
		return nil, err
	}

	var esCli *elasticsearch.Client
	if esDefaultPassword, exists := secret.Data[DefaultElasticsearchUser]; exists {
		esCli, err = elasticsearch.NewClient(esURL, DefaultElasticsearchUser, string(esDefaultPassword), true)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("couldn't find the default elasticsearch password")
	}

	var componentUser *elasticsearch.User

	password, err := RandomPassword(18)
	if err != nil {
		return nil, err
	}
	if err := esCli.CreateRoles(roles...); err != nil {
		return nil, err
	}

	rNames := roleNames(roles...)

	if exists, err := esCli.UserExists(componentName); err != nil {
		return nil, err
	} else if exists {
		// Since we can't get the password for an existing user we need to updated it with one we know
		if esUser, err := esCli.CreateUser(componentName, password, rNames); err != nil {
			return nil, err
		} else {
			componentUser = esUser
		}
	} else {
		if esUser, err := esCli.UpdateUser(componentName, password, rNames); err != nil {
			return nil, err
		} else {
			componentUser = esUser
		}
	}

	return componentUser, nil
}

func roleNames(roles ...elasticsearch.Role) []string {
	var names []string

	for _, role := range roles {
		names = append(names, role.Name)
	}

	return names
}
