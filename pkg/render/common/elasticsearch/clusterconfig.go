// Copyright (c) 2020, 2023 Tigera, Inc. All rights reserved.

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

package elasticsearch

import (
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

func NewClusterConfig(clusterName string, replicas int, shards int, flowShards int) *ClusterConfig {
	return &ClusterConfig{
		clusterName: clusterName,
		replicas:    replicas,
		shards:      shards,
		flowShards:  flowShards,
	}
}

type ClusterConfig struct {
	clusterName string
	replicas    int
	shards      int
	flowShards  int
}

func (c ClusterConfig) ClusterName() string {
	return c.clusterName
}

func (c ClusterConfig) Replicas() int {
	return c.replicas
}

func (c ClusterConfig) Shards() int {
	return c.shards
}

func (c ClusterConfig) FlowShards() int {
	return c.flowShards
}

func (c ClusterConfig) Annotation() string {
	return rmeta.AnnotationHash(c)
}
