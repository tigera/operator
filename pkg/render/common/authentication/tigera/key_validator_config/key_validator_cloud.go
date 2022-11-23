// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package tigerakvc

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type CloudAuthenticationConfig struct {
	tenantID string
}

func WithTenantClaim(tenantID string) Option {
	return func(config *KeyValidatorConfig) {
		config.cloud.tenantID = tenantID
	}
}

func (kvc *KeyValidatorConfig) addCloudEnvs(prefix string, envs []corev1.EnvVar) []corev1.EnvVar {
	return append(envs,
		corev1.EnvVar{Name: fmt.Sprintf("%sCALICO_CLOUD_REQUIRE_TENANT_CLAIM", prefix), Value: "true"},
		corev1.EnvVar{Name: fmt.Sprintf("%sCALICO_CLOUD_TENANT_CLAIM", prefix), Value: kvc.cloud.tenantID},
	)
}
