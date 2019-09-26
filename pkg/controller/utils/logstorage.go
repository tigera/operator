package utils

import (
	"context"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// GetMonitoringConfig returns the default installation instance with defaults populated.
func GetLogStorage(ctx context.Context, cli client.Client) (*operatorv1.LogStorage, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func AddLogStorageWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{})
}
