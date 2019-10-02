package render

import (
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
)

func ElasticsearchContainerDecorate(c corev1.Container, cluster, secret string) corev1.Container {
	return ElasticsearchContainerDecorateVolumeMounts(ElasticsearchContainerDecorateENVVars(c, cluster, secret))
}

func ElasticsearchContainerDecorateENVVars(c corev1.Container, cluster, secret string) corev1.Container {
	esScheme, esHost, esPort, _ := ParseEndpoint(ElasticsearchHTTPEndpoint)
	envVars := []corev1.EnvVar{
		{Name: "ELASTIC_INDEX_SUFFIX", Value: cluster},
		{Name: "ELASTIC_SCHEME", Value: esScheme},
		{Name: "ELASTIC_HOST", Value: esHost},
		{Name: "ELASTIC_PORT", Value: esPort},
		{Name: "ELASTIC_ACCESS_MODE", Value: "serviceuser"},
		{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
		{
			Name:      "ELASTIC_USER",
			ValueFrom: envVarSourceFromSecret(secret, "username", false),
		},
		{
			Name:      "ELASTIC_PASSWORD",
			ValueFrom: envVarSourceFromSecret(secret, "password", false),
		},
		//{Name: "ELASTIC_CA", ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.ca.path")},
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
				SecretName: "tigera-secure-es-http-certs-public",
				Items: []v1.KeyToPath{
					{Key: "tls.crt", Path: "ca.pem"},
				},
			},
		},
	})
	return p
}
