// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/tigera/operator/pkg/render/common/configmap"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	PGUserSecretKey = "username"
	PGUserPassKey   = "password"

	PGConfigHostKey    = "host"
	PGConfigNameKey    = "name"
	PGConfigPortKey    = "port"
	PGConfigOrgNameKey = "dbOrgName"

	PGServerCAKey   = "server-ca"
	PGClientCertKey = "client-cert"
	PGClientKeyKey  = "client-key"
)

func pgDecorateENVVars(env []corev1.EnvVar, pgUserSecret string, pgCertsPath string, pgConfig string) []corev1.EnvVar {
	envVars := []corev1.EnvVar{
		{
			Name:      "IMAGE_ASSURANCE_DB_HOST_ADDR",
			ValueFrom: configmap.GetEnvVarSource(pgConfig, PGConfigHostKey, false),
		}, {
			Name:      "IMAGE_ASSURANCE_DB_PORT",
			ValueFrom: configmap.GetEnvVarSource(pgConfig, PGConfigPortKey, false),
		},
		{
			Name:      "IMAGE_ASSURANCE_DB_NAME",
			ValueFrom: configmap.GetEnvVarSource(pgConfig, PGConfigNameKey, false),
		},
		{
			Name:      "IMAGE_ASSURANCE_DB_USER_NAME",
			ValueFrom: secret.GetEnvVarSource(pgUserSecret, PGUserSecretKey, false),
		},
		{
			Name:      "IMAGE_ASSURANCE_DB_PASSWORD",
			ValueFrom: secret.GetEnvVarSource(pgUserSecret, PGUserPassKey, false),
		},
		{
			Name:  "IMAGE_ASSURANCE_DB_SSL_ROOT_CERT",
			Value: pgCertsPath + PGServerCAKey,
		},
		{
			Name:  "IMAGE_ASSURANCE_DB_SSL_CERT",
			Value: pgCertsPath + PGClientCertKey,
		},
		{
			Name:  "IMAGE_ASSURANCE_DB_SSL_KEY",
			Value: pgCertsPath + PGClientKeyKey,
		},
	}
	env = append(env, envVars...)

	return env
}
