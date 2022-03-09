package utils

import (
	"context"

	operatorv1 "github.com/tigera/operator/api/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetImageAssurance returns the default ImageAssurance instance.
func GetImageAssurance(ctx context.Context, cli client.Client) (*operatorv1.ImageAssurance, error) {
	instance := &operatorv1.ImageAssurance{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}
