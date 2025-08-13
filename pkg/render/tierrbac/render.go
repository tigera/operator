// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.
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

package tierrbac

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// NodeConfiguration is the public API used to provide information to the render code to
// generate Kubernetes objects for installing calico/node on a cluster.
type Configuration struct {
	PullSecrets []*corev1.Secret
	KeyPair     certificatemanagement.KeyPairInterface
}

// Node creates the node daemonset and other resources for the daemonset to operate normally.
func RBAC(cfg *Configuration) render.Component {
	return &component{cfg: cfg}
}

type component struct {
	// Input configuration from the controller.
	cfg *Configuration
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	// Create the Deployment for the webhook.
	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tier-rbac-validator",
			Namespace: "calico-system",
		},
	}

	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tier-rbac-validator",
			Namespace: "calico-system",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.ToPtr(int32(1)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "validation",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tier-rbac-validator",
					Labels: map[string]string{
						"k8s-app": "validation",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "tier-rbac-validator",
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers: []corev1.Container{{
						Name:  "tier-rbac-validator",
						Image: "calico/webhook:latest",
						Args: []string{
							"webhook",
							fmt.Sprintf("--tls-cert-file=%s", c.cfg.KeyPair.VolumeMountCertificateFilePath()),
							fmt.Sprintf("--tls-private-key-file=%s", c.cfg.KeyPair.VolumeMountKeyFilePath()),
						},
						Ports: []corev1.ContainerPort{{
							ContainerPort: 443,
							Protocol:      corev1.ProtocolTCP,
						}},
						VolumeMounts: []corev1.VolumeMount{c.cfg.KeyPair.VolumeMount(c.SupportedOSType())},
					}},
					Volumes: []corev1.Volume{c.cfg.KeyPair.Volume()},
				},
			},
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tier-rbac-validator",
			Namespace: "calico-system",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(443),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"k8s-app": "validation",
			},
		},
	}

	reg := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api.projectcalico.org",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "api.projectcalico.org",
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
							admissionregistrationv1.Delete,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"*"},
							Scope:       &[]admissionregistrationv1.ScopeType{admissionregistrationv1.ClusterScope}[0],
						},
					},
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
							admissionregistrationv1.Delete,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"*"},
							Scope:       &[]admissionregistrationv1.ScopeType{admissionregistrationv1.NamespacedScope}[0],
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: "calico-system",
						Name:      "validation",
					},
					CABundle: c.cfg.KeyPair.GetCertificatePEM(),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &[]admissionregistrationv1.SideEffectClass{admissionregistrationv1.SideEffectClassNone}[0],
				TimeoutSeconds:          ptr.Int32ToPtr(5),
			},
		},
	}
	return []client.Object{sa, dep, svc, reg}, nil
}

func (c *component) Ready() bool {
	return true
}
