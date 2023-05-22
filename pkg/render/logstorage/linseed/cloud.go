// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
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

package linseed

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/logstorage"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Name of the network policy that adds CC specific rules to Linseed.
	CloudPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "cloud-linseed-access"

	// Directory to mount client secrets within the Linseed container for ES mTLS
	mtlsCertsDir = "/certs/elasticsearch/mtls"
)

type CloudConfig struct {
	// AdminUser secret for elasticsearch.
	EsAdminUserSecret *corev1.Secret

	// Whether or not ES is external to the cluster.
	ExternalElastic  bool
	ExternalESDomain string

	// Optional secret containing mTLS credentials for Linseed to present to ES.
	ExternalCertsSecret *corev1.Secret
	EnableMTLS          bool

	// Tenant ID for this instance of Linseed.
	TenantId string
}

func removeEnv(evs []corev1.EnvVar, name string) []corev1.EnvVar {
	for i, ev := range evs {
		if ev.Name == name {
			evs = append(evs[:i], evs[i+1:]...)
		}
	}
	return evs
}

func setEnv(evs []corev1.EnvVar, name, value string) []corev1.EnvVar {
	envs := removeEnv(evs, name)
	envs = append(envs, corev1.EnvVar{
		Name:  name,
		Value: value,
	})
	return envs
}

func (c *linseed) modifyDeploymentForCloud(d *appsv1.Deployment) {
	envs := d.Spec.Template.Spec.Containers[0].Env

	// Enable prometheus metrics endpoint at :METRICS_PORT/metrics (Default is 9095).
	// We use the same certificate for TLS on the metrics endpoint as we do for the main API.
	envs = append(envs, corev1.EnvVar{Name: "LINSEED_ENABLE_METRICS", Value: "true"})
	envs = append(envs, corev1.EnvVar{Name: "LINSEED_METRICS_CERT", Value: c.cfg.KeyPair.VolumeMountCertificateFilePath()})
	envs = append(envs, corev1.EnvVar{Name: "LINSEED_METRICS_KEY", Value: c.cfg.KeyPair.VolumeMountKeyFilePath()})

	if c.cfg.Cloud.ExternalElastic {
		// Adjust the endpoint used for Elasticsearch to be the external ES.
		envs = setEnv(envs, "ELASTIC_HOST", c.cfg.Cloud.ExternalESDomain)
		envs = setEnv(envs, "ELASTIC_PORT", "443")
		envs = setEnv(envs, "ELASTIC_POST", "443") // Typo in the Linseed code needs this! https://github.com/tigera/calico-private/pull/6263
	}

	if c.cfg.Cloud.EnableMTLS {
		// Enalbe Elastic mTLS in Linseed.
		envs = setEnv(envs, "ELASTIC_MTLS_ENABLED", "true")

		// Configure client certificate for Linseed.
		envs = setEnv(envs, "ELASTIC_CLIENT_KEY", mtlsCertsDir+"/client.key")
		envs = setEnv(envs, "ELASTIC_CLIENT_CERT", mtlsCertsDir+"/client.crt")

		// Add a volume for the required client certificate and key.
		d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: logstorage.ExternalCertsVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: logstorage.ExternalCertsSecret,
				},
			},
		})

		// Mount the volume into the Linseed container at the expected location.
		d.Spec.Template.Spec.Containers[0].VolumeMounts = append(d.Spec.Template.Spec.Containers[0].VolumeMounts,
			[]corev1.VolumeMount{
				{
					Name:      logstorage.ExternalCertsVolumeName,
					MountPath: mtlsCertsDir,
					ReadOnly:  true,
				},
			}...)

		// Update the annotations to include the hash for the external certs used for mTLS with ES.
		if c.cfg.Cloud.ExternalCertsSecret != nil {
			d.Spec.Template.ObjectMeta.Annotations["hash.operator.tigera.io/cloud-external-es-secrets"] = rmeta.SecretsAnnotationHash(c.cfg.Cloud.ExternalCertsSecret)
		}
	}

	if c.cfg.Cloud.TenantId != "" {
		envs = append(envs, corev1.EnvVar{Name: "LINSEED_EXPECTED_TENANT_ID", Value: c.cfg.Cloud.TenantId})
	}

	d.Spec.Template.Spec.Containers[0].Env = envs
}

func (c *linseed) getCloudObjects() (toCreate []client.Object) {
	s := []client.Object{}

	// TODO: Both Linseed and es-gateway have this logic. It's only needed in one location.
	// if e.cfg.Cloud.ExternalCertsSecret != nil {
	// 	s = append(s, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.Cloud.ExternalCertsSecret)...)...)
	// }

	// if e.cfg.Cloud.EsAdminUserSecret != nil {
	// 	s = append(s, secret.ToRuntimeObjects(secret.CopyToNamespace(render.ElasticsearchNamespace, e.cfg.Cloud.EsAdminUserSecret)...)...)
	// }

	s = append(s, c.allowTigeraPolicyForCloud())
	return s
}

func (c *linseed) allowTigeraPolicyForCloud() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	if c.cfg.Cloud.ExternalElastic {
		// Allow egress traffic to the external Elasticsearch.
		egressRules = append(egressRules,
			v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Ports:   []numorstring.Port{{MinPort: 443, MaxPort: 443}},
					Domains: []string{c.cfg.Cloud.ExternalESDomain},
				},
			},
		)
	}

	ingressRules := []v3.Rule{
		{
			// Allow ingress traffic from Calico Cloud monitoring stack to the Linseed
			// metrics port.
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				NamespaceSelector: "projectcalico.org/name == 'monitoring'",
				Selector:          "app == 'prometheus'",
			},
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
