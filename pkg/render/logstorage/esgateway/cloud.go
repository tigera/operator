// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package esgateway

import (
	"strconv"

	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ExternalCertsSecret     = "tigera-secure-external-es-certs"
	ExternalCertsVolumeName = "tigera-secure-external-es-certs"
)

type CloudConfig struct {
	EsAdminUserSecret    *corev1.Secret
	ExternalCertsSecret  *corev1.Secret
	TenantId             string
	EnableMTLS           bool
	ExternalElastic      bool
	ExternalESDomain     string
	ExternalKibanaDomain string
}

func removeEnv(evs []corev1.EnvVar, name string) []corev1.EnvVar {
	for i, ev := range evs {
		if ev.Name == name {
			evs = append(evs[:i], evs[i+1:]...)
		}
	}
	return evs
}

func (e *esGateway) modifyDeploymentForCloud(d *appsv1.Deployment) {
	envs := d.Spec.Template.Spec.Containers[0].Env
	// Enable prometheus metrics endpoint at :METRICS_PORT/metrics (Default is 9091).
	envs = append(envs, corev1.EnvVar{Name: "ES_GATEWAY_METRICS_ENABLED", Value: "true"})

	if e.cfg.Cloud.ExternalElastic {
		// Find the following Envs and remove them
		envs = removeEnv(envs, "ES_GATEWAY_ELASTIC_ENDPOINT")
		envs = removeEnv(envs, "ES_GATEWAY_KIBANA_ENDPOINT")
		envs = append(envs, corev1.EnvVar{
			Name:  "ES_GATEWAY_ELASTIC_ENDPOINT",
			Value: "https://" + e.cfg.Cloud.ExternalESDomain + ":443",
		})
		envs = append(envs, corev1.EnvVar{
			Name:  "ES_GATEWAY_KIBANA_ENDPOINT",
			Value: "https://" + e.cfg.Cloud.ExternalKibanaDomain + ":443",
		})
	}

	if e.cfg.Cloud.EnableMTLS {
		//todo: delete these from the envVars
		envs = removeEnv(envs, "ES_GATEWAY_KIBANA_CLIENT_CERT_PATH")
		envs = removeEnv(envs, "ES_GATEWAY_ELASTIC_CLIENT_CERT_PATH")

		envs = append(envs, []corev1.EnvVar{
			{Name: "ES_GATEWAY_ELASTIC_CLIENT_CERT_PATH", Value: "/certs/elasticsearch/mtls/client.crt"},
			{Name: "ES_GATEWAY_ELASTIC_CLIENT_KEY_PATH", Value: "/certs/elasticsearch/mtls/client.key"},
			{Name: "ES_GATEWAY_ENABLE_ELASTIC_MUTUAL_TLS", Value: strconv.FormatBool(e.cfg.Cloud.EnableMTLS)},
			{Name: "ES_GATEWAY_KIBANA_CLIENT_CERT_PATH", Value: "/certs/kibana/mtls/client.crt"},
			{Name: "ES_GATEWAY_KIBANA_CLIENT_KEY_PATH", Value: "/certs/kibana/mtls/client.key"},
			{Name: "ES_GATEWAY_ENABLE_KIBANA_MUTUAL_TLS", Value: strconv.FormatBool(e.cfg.Cloud.EnableMTLS)},
		}...)

		d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: ExternalCertsVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ExternalCertsSecret,
				},
			},
		})

		d.Spec.Template.Spec.Containers[0].VolumeMounts = append(d.Spec.Template.Spec.Containers[0].VolumeMounts,
			[]corev1.VolumeMount{
				{Name: ExternalCertsVolumeName, MountPath: "/certs/elasticsearch/mtls", ReadOnly: true},
				{Name: ExternalCertsVolumeName, MountPath: "/certs/kibana/mtls", ReadOnly: true},
			}...)
	}

	if e.cfg.Cloud.TenantId != "" {
		envs = append(envs, corev1.EnvVar{Name: "ES_GATEWAY_TENANT_ID", Value: e.cfg.Cloud.TenantId})
	}

	d.Spec.Template.Spec.Containers[0].Env = envs
	if e.cfg.Cloud.ExternalCertsSecret != nil {
		d.Spec.Template.ObjectMeta.Annotations["hash.operator.tigera.io/cloud-external-es-secrets"] =
			rmeta.SecretsAnnotationHash(e.cfg.Cloud.ExternalCertsSecret)
	}
}

func (e *esGateway) getCloudObjects() (toCreate []client.Object) {
	s := []client.Object{}

	if e.cfg.Cloud.ExternalCertsSecret != nil {
		s = append(s, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.Cloud.ExternalCertsSecret)...)...)
	}

	if e.cfg.Cloud.EsAdminUserSecret != nil {
		s = append(s, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.Cloud.EsAdminUserSecret)...)...)
	}
	return s
}
