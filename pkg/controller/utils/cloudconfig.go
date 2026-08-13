// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetCloudConfig retrieves the config map containing the configuration values needed to set up communications with
// external Elasticsearch and Kibana, such as the externalESDomain and externalKibanaDomain.
func GetCloudConfig(ctx context.Context, cli client.Client) (*cloudconfig.CloudConfig, error) {
	configMap := &corev1.ConfigMap{}
	if err := cli.Get(ctx, client.ObjectKey{Name: cloudconfig.CloudConfigConfigMapName, Namespace: common.OperatorNamespace()}, configMap); err != nil {
		return nil, err
	}

	return cloudconfig.NewCloudConfigFromConfigMap(configMap)
}
