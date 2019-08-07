package utils

import (
	"context"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetMonitoringConfig returns the default installation instance with defaults populated.
func GetMonitoringConfig(ctx context.Context, cli client.Client) (*operator.MonitoringConfiguration, error) {
	instance := &operator.MonitoringConfiguration{}
	err := cli.Get(ctx, client.ObjectKey{Name: "default"}, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}
