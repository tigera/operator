// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package utils

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/common"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	cloudAuthConfig = "cloud-auth-config"
)

func getCloudKeyValidatorOption(ctx context.Context, cli client.Client) (tigerakvc.Option, error) {
	cm := &corev1.ConfigMap{}
	if err := cli.Get(ctx, types.NamespacedName{Name: cloudAuthConfig, Namespace: common.OperatorNamespace()}, cm); err != nil {
		return nil, fmt.Errorf("missing config map %s/%s: %w", common.OperatorNamespace(), cloudAuthConfig, err)
	}

	fmt.Println("Read Cloud auth config", cm)

	tenantID, ok := cm.Data["tenantID"]
	if !ok {
		return nil, fmt.Errorf("Cloud config map %s/%s is missing the tenantID field", common.OperatorNamespace(), cloudAuthConfig)
	} else if tenantID == "" {
		return nil, fmt.Errorf("Cloud config map %s/%s has empty tenantID field", common.OperatorNamespace(), cloudAuthConfig)
	}

	return tigerakvc.WithTenantClaim(tenantID), nil
}
