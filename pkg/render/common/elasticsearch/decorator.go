// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"github.com/tigera/operator/pkg/url"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
)

const (
	DefaultCertDir         = "/etc/ssl/elastic/"
	DefaultCertDirWindows  = "c:/etc/ssl/elastic/"
	DefaultCertPath        = DefaultCertDir + "ca.pem"
	DefaultCertPathWindows = DefaultCertDirWindows + "ca.pem"

	elasticsearchSecretsAnnotation   = "hash.operator.tigera.io/elasticsearch-secrets"
	elasticsearchConfigMapAnnotation = "hash.operator.tigera.io/elasticsearch-configmap"
)

type Annotatable interface {
	SetAnnotations(map[string]string)
	GetAnnotations() map[string]string
}

func elasticCertDir(osType rmeta.OSType) string {
	if osType == rmeta.OSTypeWindows {
		return DefaultCertDirWindows
	}
	return DefaultCertDir
}

func elasticCertPath(osType rmeta.OSType) string {
	if osType == rmeta.OSTypeWindows {
		return DefaultCertPathWindows
	}
	return DefaultCertPath
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
	return ContainerDecorateVolumeMounts(ContainerDecorateENVVars(c, cluster, secret, clusterDomain, osType), osType)
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

func ContainerDecorateVolumeMounts(c corev1.Container, osType rmeta.OSType) corev1.Container {
	c.VolumeMounts = append(c.VolumeMounts, DefaultVolumeMount(osType))

	return c
}

func DefaultVolumeMount(osType rmeta.OSType) corev1.VolumeMount {
	certPath := elasticCertDir(osType)
	return corev1.VolumeMount{
		Name:      "elastic-ca-cert-volume",
		MountPath: certPath,
	}
}

func PodSpecDecorate(p corev1.PodSpec) corev1.PodSpec {
	p.Volumes = append(p.Volumes, DefaultVolume())

	return p
}

func DefaultVolume() corev1.Volume {
	return corev1.Volume{
		Name: "elastic-ca-cert-volume",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: PublicCertSecret,
				Items: []v1.KeyToPath{
					{Key: "tls.crt", Path: "ca.pem"},
				},
			},
		},
	}
}
