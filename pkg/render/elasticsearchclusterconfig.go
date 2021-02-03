// Copyright (c) 2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package render

import (
	"fmt"
	"strconv"

	rutil "github.com/tigera/operator/pkg/render/common"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewElasticsearchClusterConfig(clusterName string, replicas int, shards int, flowShards int) *ElasticsearchClusterConfig {
	return &ElasticsearchClusterConfig{
		clusterName: clusterName,
		replicas:    replicas,
		shards:      shards,
		flowShards:  flowShards,
	}
}

func NewElasticsearchClusterConfigFromConfigMap(configMap *corev1.ConfigMap) (*ElasticsearchClusterConfig, error) {
	var replicas, shards, flowShards int
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

	if configMap.Data["flowShards"] == "" {
		return nil, fmt.Errorf("'flowShards' is not set")
	} else {
		if flowShards, err = strconv.Atoi(configMap.Data["flowShards"]); err != nil {
			return nil, errors.Wrap(err, "'flowShards' must be an integer")
		}
	}

	return NewElasticsearchClusterConfig(configMap.Data["clusterName"], replicas, shards, flowShards), nil
}

type ElasticsearchClusterConfig struct {
	clusterName string
	replicas    int
	shards      int
	flowShards  int
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

func (c ElasticsearchClusterConfig) FlowShards() int {
	return c.flowShards
}

func (c ElasticsearchClusterConfig) Annotation() string {
	return rutil.AnnotationHash(c)
}

func (c ElasticsearchClusterConfig) ConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchConfigMapName,
			Namespace: rutil.OperatorNamespace(),
		},
		Data: map[string]string{
			"clusterName": c.clusterName,
			"replicas":    strconv.Itoa(c.replicas),
			"shards":      strconv.Itoa(c.shards),
			"flowShards":  strconv.Itoa(c.flowShards),
		},
	}
}
