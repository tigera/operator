// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package common

import (
	"context"

	"github.com/tigera/operator/pkg/render/kubecontrollers"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/crypto"
	"github.com/tigera/operator/pkg/render"
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
