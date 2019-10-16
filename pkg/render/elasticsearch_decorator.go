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
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
)

const (
	ElasticsearchDefaultCertPath  = "/etc/ssl/elastic/ca.pem"
	TigeraElasticsearchCertSecret = "tigera-secure-elasticsearch-cert"
	ElasticsearchPublicCertSecret = "tigera-secure-es-http-certs-public"
)

func ElasticsearchContainerDecorate(c corev1.Container, cluster, secret string) corev1.Container {
	return ElasticsearchContainerDecorateVolumeMounts(ElasticsearchContainerDecorateENVVars(c, cluster, secret))
}

func ElasticsearchContainerDecorateENVVars(c corev1.Container, cluster, esUsername string) corev1.Container {
	esUser, err := esusers.GetUser(esUsername)
	if err != nil {
		// The esUser should be validated before we call ElasticsearchContainerDecorateENVVars
		panic(err)
	}
	esScheme, esHost, esPort, _ := ParseEndpoint(ElasticsearchHTTPSEndpoint)
	secretName := esUser.SecretName()
	envVars := []corev1.EnvVar{
		{Name: "ELASTIC_INDEX_SUFFIX", Value: cluster},
		{Name: "ELASTIC_SCHEME", Value: esScheme},
		{Name: "ELASTIC_HOST", Value: esHost},
		{Name: "ELASTIC_PORT", Value: esPort},
		{Name: "ELASTIC_ACCESS_MODE", Value: "serviceuser"},
		{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
		{
			Name:      "ELASTIC_USER",
			ValueFrom: envVarSourceFromSecret(secretName, "username", false),
		},
		{
			Name:      "ELASTIC_USERNAME", // some pods require this name instead of ELASTIC_USER
			ValueFrom: envVarSourceFromSecret(secretName, "username", false),
		},
		{
			Name:      "ELASTIC_PASSWORD",
			ValueFrom: envVarSourceFromSecret(secretName, "password", false),
		},
		{Name: "ELASTIC_CA", Value: ElasticsearchDefaultCertPath},
		{Name: "ES_CA_CERT", Value: ElasticsearchDefaultCertPath},
	}

	c.Env = append(c.Env, envVars...)
	return c
}

func ElasticsearchContainerDecorateVolumeMounts(c corev1.Container) corev1.Container {
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
		Name:      "elastic-ca-cert-volume",
		MountPath: "/etc/ssl/elastic/",
	})

	return c
}

func ElasticsearchPodSpecDecorate(p corev1.PodSpec) corev1.PodSpec {
	p.Volumes = append(p.Volumes, corev1.Volume{
		Name: "elastic-ca-cert-volume",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: ElasticsearchPublicCertSecret,
				Items: []v1.KeyToPath{
					{Key: "tls.crt", Path: "ca.pem"},
				},
			},
		},
	})
	return p
}
