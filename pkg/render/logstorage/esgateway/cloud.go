// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

package esgateway

import (
	"strconv"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	CloudPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "cloud-es-gateway-access"
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
		// todo: delete these from the envVars
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
			Name: logstorage.ExternalCertsVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: logstorage.ExternalCertsSecret,
				},
			},
		})

		d.Spec.Template.Spec.Containers[0].VolumeMounts = append(d.Spec.Template.Spec.Containers[0].VolumeMounts,
			[]corev1.VolumeMount{
				{Name: logstorage.ExternalCertsVolumeName, MountPath: "/certs/elasticsearch/mtls", ReadOnly: true},
				{Name: logstorage.ExternalCertsVolumeName, MountPath: "/certs/kibana/mtls", ReadOnly: true},
			}...)
	}

	if e.cfg.Cloud.TenantId != "" {
		envs = append(envs, corev1.EnvVar{Name: "ES_GATEWAY_TENANT_ID", Value: e.cfg.Cloud.TenantId})
	}

	d.Spec.Template.Spec.Containers[0].Env = envs
	if e.cfg.Cloud.ExternalCertsSecret != nil {
		d.Spec.Template.ObjectMeta.Annotations["hash.operator.tigera.io/cloud-external-es-secrets"] = rmeta.SecretsAnnotationHash(e.cfg.Cloud.ExternalCertsSecret)
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
	s = append(s, e.allowTigeraPolicyForCloud())
	return s
}

func (e *esGateway) allowTigeraPolicyForCloud() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	if e.cfg.Cloud.ExternalElastic {
		egressRules = append(egressRules,
			v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Ports:   []numorstring.Port{{MinPort: 443, MaxPort: 443}},
					Domains: []string{e.cfg.Cloud.ExternalESDomain, e.cfg.Cloud.ExternalKibanaDomain},
				},
			},
		)
	}

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				NamespaceSelector: "projectcalico.org/name == 'monitoring'",
				Selector:          "app == 'prometheus'",
			},
			// This matches the default. The metrics are enabled only on cloud (see
			// ES_GATEWAY_METRICS_ENABLED which is added in this file).
			Destination: v3.EntityRule{
				Ports: []numorstring.Port{{MinPort: 9091, MaxPort: 9091}},
			},
		},
	}
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CloudPolicyName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(DeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}
