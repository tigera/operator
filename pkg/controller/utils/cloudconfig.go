package utils

import (
	"context"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetCloudConfig retrieves the config map containing the configuration values needed to set up communications with
// external Elasticsearch and Kibana, such as the externalESDomain and externalKibanaDomain.
func GetCloudConfig(ctx context.Context, cli client.Client) (*cloudconfig.CloudConfig, error) {
	configMap := &corev1.ConfigMap{}
	if err := cli.Get(ctx, client.ObjectKey{Name: cloudconfig.CloudConfigConfigMapName, Namespace: rmeta.OperatorNamespace()}, configMap); err != nil {
		return nil, err
	}

	return cloudconfig.NewCloudConfigFromConfigMap(configMap)
}
