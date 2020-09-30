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

package render

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
)

const (
	ElasticsearchDefaultCertDir      = "/etc/ssl/elastic/"
	ElasticsearchDefaultCertPath     = ElasticsearchDefaultCertDir + "ca.pem"
	TigeraElasticsearchCertSecret    = "tigera-secure-elasticsearch-cert"
	ElasticsearchPublicCertSecret    = "tigera-secure-es-http-certs-public"
	elasticsearchConfigMapAnnotation = "hash.operator.tigera.io/elasticsearch-configmap"
)

type Annotatable interface {
	SetAnnotations(map[string]string)
	GetAnnotations() map[string]string
}

func ElasticsearchDecorateAnnotations(obj Annotatable, config *ElasticsearchClusterConfig, secrets []*corev1.Secret) Annotatable {
	annots := obj.GetAnnotations()
	if annots == nil {
		annots = map[string]string{}
	}
	annots[elasticsearchConfigMapAnnotation] = config.Annotation()
	annots[elasticsearchSecretsAnnotation] = secretsAnnotationHash(secrets...)
	obj.SetAnnotations(annots)

	return obj
}

func ElasticsearchContainerDecorate(c corev1.Container, cluster, secret string) corev1.Container {
	return ElasticsearchContainerDecorateVolumeMounts(ElasticsearchContainerDecorateENVVars(c, cluster, secret))
}

func ElasticsearchContainerDecorateIndexCreator(c corev1.Container, replicas, shards int) corev1.Container {
	envVars := []corev1.EnvVar{
		{Name: "ELASTIC_REPLICAS", Value: strconv.Itoa(replicas)},
		{Name: "ELASTIC_SHARDS", Value: strconv.Itoa(shards)},
	}
	c.Env = append(c.Env, envVars...)

	return c
}

func ElasticsearchContainerDecorateENVVars(c corev1.Container, cluster, esUserSecretName string) corev1.Container {
	esScheme, esHost, esPort, _ := ParseEndpoint(ElasticsearchHTTPSEndpoint)
	envVars := []corev1.EnvVar{
		{Name: "ELASTIC_INDEX_SUFFIX", Value: cluster},
		{Name: "ELASTIC_SCHEME", Value: esScheme},
		{Name: "ELASTIC_HOST", Value: esHost},
		{Name: "ELASTIC_PORT", Value: esPort},
		{Name: "ELASTIC_ACCESS_MODE", Value: "serviceuser"},
		{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
		{
			Name:      "ELASTIC_USER",
			ValueFrom: envVarSourceFromSecret(esUserSecretName, "username", false),
		},
		{
			Name:      "ELASTIC_USERNAME", // some pods require this name instead of ELASTIC_USER
			ValueFrom: envVarSourceFromSecret(esUserSecretName, "username", false),
		},
		{
			Name:      "ELASTIC_PASSWORD",
			ValueFrom: envVarSourceFromSecret(esUserSecretName, "password", false),
		},
		{Name: "ELASTIC_CA", Value: ElasticsearchDefaultCertPath},
		{Name: "ES_CA_CERT", Value: ElasticsearchDefaultCertPath},
		{Name: "ES_CURATOR_BACKEND_CERT", Value: ElasticsearchDefaultCertPath},
	}

	c.Env = append(c.Env, envVars...)
	return c
}

func ElasticsearchContainerDecorateVolumeMounts(c corev1.Container) corev1.Container {
	c.VolumeMounts = append(c.VolumeMounts, ElasticsearchDefaultVolumeMount())

	return c
}

func ElasticsearchDefaultVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "elastic-ca-cert-volume",
		MountPath: ElasticsearchDefaultCertDir,
	}
}

func ElasticsearchPodSpecDecorate(p corev1.PodSpec) corev1.PodSpec {
	p.Volumes = append(p.Volumes, ElasticsearchDefaultVolume())

	return p
}

func ElasticsearchDefaultVolume() corev1.Volume {
	return corev1.Volume{
		Name: "elastic-ca-cert-volume",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: ElasticsearchPublicCertSecret,
				Items: []v1.KeyToPath{
					{Key: "tls.crt", Path: "ca.pem"},
				},
			},
		},
	}
}
