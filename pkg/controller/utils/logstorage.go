package utils

import (
	"context"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetLogStorage returns the LogStorage resource as the first return value if, and only if, it exists, it is "ready", and
// no error occurred, otherwise the first return value will be nil. If an error occurred it will be return as the second
// return value
func GetReadyLogStorage(ctx context.Context, cli client.Client) (*operatorv1.LogStorage, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	if instance.Status.State != operatorv1.LogStorageStatusReady {
		return nil, nil
	}

	return instance, nil
}
