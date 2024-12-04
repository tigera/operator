// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package externalelasticsearch

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
)

// ExternalElasticsearch is used when Elasticsearch doesn't exist in this cluster, but we still need to set up resources
// related to Elasticsearch in the cluster.
func ExternalElasticsearch(install *operatorv1.InstallationSpec, clusterConfig *relasticsearch.ClusterConfig, pullSecrets []*corev1.Secret) render.Component {
	return &externalElasticsearch{
		installation:  install,
		clusterConfig: clusterConfig,
		pullSecrets:   pullSecrets,
	}
}

type externalElasticsearch struct {
	installation  *operatorv1.InstallationSpec
	clusterConfig *relasticsearch.ClusterConfig
	pullSecrets   []*corev1.Secret
}

func (e externalElasticsearch) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (e externalElasticsearch) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, render.CreateNamespace(render.ElasticsearchNamespace, e.installation.KubernetesProvider, render.PSSBaseline, e.installation.Azure))
	toCreate = append(toCreate, render.CreateOperatorSecretsRoleBinding(render.ElasticsearchNamespace))
	toCreate = append(toCreate, e.clusterConfig.ConfigMap())
	toCreate = append(toCreate, e.oidcUserRole())
	toCreate = append(toCreate, e.oidcUserRoleBinding())
	if len(e.pullSecrets) > 0 {
		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.pullSecrets...)...)...)
	}
	return toCreate, toDelete
}

func (e externalElasticsearch) Ready() bool {
	return true
}

func (e externalElasticsearch) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e externalElasticsearch) oidcUserRole() client.Object {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.EsManagerRole,
			Namespace: render.ElasticsearchNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{render.OIDCUsersConfigMapName},
				Verbs:         []string{"update", "patch"},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{render.OIDCUsersESSecretName},
				Verbs:         []string{"get", "list"},
			},
		},
	}
}

func (e externalElasticsearch) oidcUserRoleBinding() client.Object {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.EsManagerRoleBinding,
			Namespace: render.ElasticsearchNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     render.EsManagerRole,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.ManagerServiceAccount,
				Namespace: render.ManagerNamespace,
			},
		},
	}
}
