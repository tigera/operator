package render

import (
	"fmt"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strconv"
)

func NewElasticsearchClusterConfig(clusterName string, replicas int, shards int) *ElasticsearchClusterConfig {
	return &ElasticsearchClusterConfig{
		clusterName: clusterName,
		replicas:    replicas,
		shards:      shards,
	}
}

func NewElasticsearchClusterConfigFromConfigMap(configMap *corev1.ConfigMap) (*ElasticsearchClusterConfig, error) {
	var replicas, shards int
	var err error

	if configMap.Data["clusterName"] == "" {
		return nil, fmt.Errorf("'clusterName' is not set")
	}

	if configMap.Data["replicas"] == "" {
		return nil, fmt.Errorf("'replicas' is not set")
	} else {
		if replicas, err = strconv.Atoi(configMap.Data["replicas"]); err != nil {
			return nil, errors.Wrap(err, "'replicas' must be an integer")
		}
	}

	if configMap.Data["shards"] == "" {
		return nil, fmt.Errorf("'shards' is not set")
	} else {
		if shards, err = strconv.Atoi(configMap.Data["shards"]); err != nil {
			return nil, errors.Wrap(err, "'shards' must be an integer")
		}
	}

	return &ElasticsearchClusterConfig{
		clusterName: configMap.Data["clusterName"],
		replicas:    replicas,
		shards:      shards,
	}, nil
}

type ElasticsearchClusterConfig struct {
	clusterName string
	replicas    int
	shards      int
}

func (c ElasticsearchClusterConfig) ClusterName() string {
	return c.clusterName
}

func (c ElasticsearchClusterConfig) Replicas() int {
	return c.replicas
}

func (c ElasticsearchClusterConfig) Shards() int {
	return c.shards
}

func (c ElasticsearchClusterConfig) Annotation() string {
	return AnnotationHash(c)
}

func (c ElasticsearchClusterConfig) ConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchConfigMapName,
			Namespace: OperatorNamespace(),
		},
		Data: map[string]string{
			"clusterName": c.clusterName,
			"replicas":    strconv.Itoa(c.replicas),
			"shards":      strconv.Itoa(c.shards),
		},
	}
}
