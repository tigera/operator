// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package applicationlayer

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	// WAFWebhookName is the resource name used for all WAF admission webhook objects.
	WAFWebhookName = "tigera-waf-admission-controller"

	// wafWebhookPort is the HTTPS port exposed by the WAF admission webhook.
	wafWebhookPort = int32(8443)
)

// WAFAdmissionWebhookComponents returns the full set of objects required for the WAF
// admission webhook: Deployment, Service, ServiceAccount, ClusterRole, ClusterRoleBinding,
// and ValidatingWebhookConfiguration.
//
// The caller is responsible for invoking this only when the gateway-addons license feature
// is present.
func WAFAdmissionWebhookComponents(install *operatorv1.InstallationSpec, image string, certPair certificatemanagement.KeyPairInterface) []client.Object {
	return []client.Object{
		wafWebhookServiceAccount(),
		wafWebhookClusterRole(),
		wafWebhookClusterRoleBinding(),
		wafWebhookDeployment(install, image, certPair),
		wafWebhookService(),
		wafValidatingWebhookConfiguration(certPair),
	}
}

// ---- WAF admission webhook private constructors ----

func wafWebhookServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WAFWebhookName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"app": WAFWebhookName},
		},
	}
}

func wafWebhookClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   WAFWebhookName,
			Labels: map[string]string{"app": WAFWebhookName},
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Required to read GatewayExtension CRs when validating admission requests.
				APIGroups: []string{"applicationlayer.projectcalico.org"},
				Resources: []string{"gatewayextensions", "globalwafpolicies"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
}

func wafWebhookClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   WAFWebhookName,
			Labels: map[string]string{"app": WAFWebhookName},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     WAFWebhookName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      WAFWebhookName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

func wafWebhookDeployment(install *operatorv1.InstallationSpec, image string, certPair certificatemanagement.KeyPairInterface) *appsv1.Deployment {
	var replicas int32 = 1
	if install.ControlPlaneReplicas != nil {
		replicas = *install.ControlPlaneReplicas
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WAFWebhookName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"app": WAFWebhookName},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": WAFWebhookName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": WAFWebhookName},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: WAFWebhookName,
					Containers: []corev1.Container{
						{
							Name:            WAFWebhookName,
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							SecurityContext: securitycontext.NewNonRootContext(),
							Args: []string{
								"--tls-cert-file=" + certPair.VolumeMountCertificateFilePath(),
								"--tls-private-key-file=" + certPair.VolumeMountKeyFilePath(),
								fmt.Sprintf("--port=%d", wafWebhookPort),
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "https",
									ContainerPort: wafWebhookPort,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								certPair.VolumeMount(rmeta.OSTypeLinux),
							},
						},
					},
					Volumes: []corev1.Volume{
						certPair.Volume(),
					},
				},
			},
		},
	}
}

func wafWebhookService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WAFWebhookName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"app": WAFWebhookName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": WAFWebhookName},
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(wafWebhookPort),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func wafValidatingWebhookConfiguration(certPair certificatemanagement.KeyPairInterface) *admissionregistrationv1.ValidatingWebhookConfiguration {
	failPolicy := admissionregistrationv1.Ignore
	sideEffects := admissionregistrationv1.SideEffectClassNone
	timeoutSeconds := int32(10)

	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ValidatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "tigera-waf.applicationlayer.projectcalico.org",
			Labels: map[string]string{"app": WAFWebhookName},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "waf.applicationlayer.projectcalico.org",
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"applicationlayer.projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"gatewayextensions", "globalwafpolicies"},
							Scope:       ptr.To(admissionregistrationv1.AllScopes),
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: common.CalicoNamespace,
						Name:      WAFWebhookName,
						Path:      ptr.To("/validate"),
					},
					CABundle: certPair.GetCertificatePEM(),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &sideEffects,
				TimeoutSeconds:          &timeoutSeconds,
				FailurePolicy:           &failPolicy,
			},
		},
	}
}
