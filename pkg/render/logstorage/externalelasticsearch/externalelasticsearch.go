// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package externalelasticsearch

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

// ExternalElasticsearch is used when Elasticsearch doesn't exist in this cluster, but we still need to set up resources
// related to Elasticsearch in the cluster.
func ExternalElasticsearch(install *operatorv1.InstallationSpec, clusterConfig *relasticsearch.ClusterConfig) render.Component {
	return &externalElasticsearch{
		installation:  install,
		clusterConfig: clusterConfig,
	}
}

type externalElasticsearch struct {
	installation  *operatorv1.InstallationSpec
	clusterConfig *relasticsearch.ClusterConfig
}

func (e externalElasticsearch) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (e externalElasticsearch) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, render.CreateNamespace(render.ElasticsearchNamespace, e.installation.KubernetesProvider))
	toCreate = append(toCreate, e.clusterConfig.ConfigMap())
	return toCreate, toDelete
}

func (e externalElasticsearch) Ready() bool {
	return true
}

func (e externalElasticsearch) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
