package utils

import (
	"context"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetLogStorage gets the LogStorage resource set for this cluster, if it exists.
func GetLogStorage(ctx context.Context, cli client.Client) (*operatorv1.LogStorage, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}
