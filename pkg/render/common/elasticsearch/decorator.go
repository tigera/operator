// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elasticsearch

import (
	"strconv"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"

	corev1 "k8s.io/api/core/v1"
)

const (
	elasticsearchSecretsAnnotation   = "hash.operator.tigera.io/elasticsearch-secrets"
	elasticsearchConfigMapAnnotation = "hash.operator.tigera.io/elasticsearch-configmap"
)

type Annotatable interface {
	SetAnnotations(map[string]string)
	GetAnnotations() map[string]string
}

func elasticCertDir(osType rmeta.OSType) string {
	if osType == rmeta.OSTypeWindows {
		return certificatemanagement.TrustedCertVolumeMountPathWindows
	}
	return certificatemanagement.TrustedCertVolumeMountPath
}

func elasticCertPath(osType rmeta.OSType) string {
	if osType == rmeta.OSTypeWindows {
		return certificatemanagement.TrustedCertBundleMountPathWindows
	}
	return certificatemanagement.TrustedCertBundleMountPath
}

func DecorateAnnotations(obj Annotatable, config *ClusterConfig, secrets []*corev1.Secret) Annotatable {
	annots := obj.GetAnnotations()
	if annots == nil {
		annots = map[string]string{}
	}
	annots[elasticsearchConfigMapAnnotation] = config.Annotation()
	annots[elasticsearchSecretsAnnotation] = rmeta.SecretsAnnotationHash(secrets...)
	obj.SetAnnotations(annots)

	return obj
}

func ContainerDecorate(c corev1.Container, cluster, secret, clusterDomain string, osType rmeta.OSType) corev1.Container {
	return ContainerDecorateENVVars(c, cluster, secret, clusterDomain, osType)
}

func ContainerDecorateIndexCreator(c corev1.Container, replicas, shards int) corev1.Container {
	envVars := []corev1.EnvVar{
		{Name: "ELASTIC_REPLICAS", Value: strconv.Itoa(replicas)},
		{Name: "ELASTIC_SHARDS", Value: strconv.Itoa(shards)},
	}
	c.Env = append(c.Env, envVars...)

	return c
}

func ContainerDecorateENVVars(
	c corev1.Container,
	cluster, esUserSecretName, clusterDomain string,
	osType rmeta.OSType) corev1.Container {
	certPath := elasticCertPath(osType)
	esScheme, esHost, esPort, _ := url.ParseEndpoint(HTTPSEndpoint(osType, clusterDomain))
	envVars := []corev1.EnvVar{
		{Name: "ELASTIC_INDEX_SUFFIX", Value: cluster},
		{Name: "ELASTIC_SCHEME", Value: esScheme},
		{Name: "ELASTIC_HOST", Value: esHost},
		{Name: "ELASTIC_PORT", Value: esPort},
		{Name: "ELASTIC_ACCESS_MODE", Value: "serviceuser"},
		{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
		{
			Name:      "ELASTIC_USER",
			ValueFrom: secret.GetEnvVarSource(esUserSecretName, "username", false),
		},
		{
			Name:      "ELASTIC_USERNAME", // some pods require this name instead of ELASTIC_USER
			ValueFrom: secret.GetEnvVarSource(esUserSecretName, "username", false),
		},
		{
			Name:      "ELASTIC_PASSWORD",
			ValueFrom: secret.GetEnvVarSource(esUserSecretName, "password", false),
		},
		{Name: "ELASTIC_CA", Value: certPath},
		{Name: "ES_CA_CERT", Value: certPath},
		{Name: "ES_CURATOR_BACKEND_CERT", Value: certPath},
	}

	c.Env = append(c.Env, envVars...)
	return c
}

func DefaultVolumeMount(osType rmeta.OSType) corev1.VolumeMount {
	certPath := elasticCertDir(osType)
	return corev1.VolumeMount{
		Name:      certificatemanagement.TrustedCertConfigMapName,
		MountPath: certPath,
	}
}
