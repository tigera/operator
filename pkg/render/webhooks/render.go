// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package webhooks

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

const (
	WebhooksTLSSecretName = "calico-webhooks-tls"

	WebhooksName = "calico-webhooks"
)

var WebhooksPolicyName = fmt.Sprintf("%s.%s", networkpolicy.TigeraComponentTierName, WebhooksName)

// Configuration is the public API used to provide information to the render code to
// generate Kubernetes objects for installing calico/webhooks on a cluster.
type Configuration struct {
	PullSecrets  []*corev1.Secret
	KeyPair      certificatemanagement.KeyPairInterface
	Installation *operatorv1.InstallationSpec
	APIServer    *operatorv1.APIServerSpec
	OpenShift    bool
}

func Component(cfg *Configuration) render.Component {
	return &component{cfg: cfg}
}

type component struct {
	// Input configuration from the controller.
	cfg *Configuration

	// Images.
	webhooksImage string
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.webhooksImage, err = components.GetReference(components.ComponentTigeraWebhooks, reg, path, prefix, is)
	} else {
		c.webhooksImage, err = components.GetReference(components.ComponentCalicoWebhooks, reg, path, prefix, is)
	}
	return err
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	// Create the ServiceAccount for the webhook.
	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhooksName,
			Namespace: common.CalicoNamespace,
		},
	}

	// Network policy to allow traffic to/from the webhook pod.
	egressRules := networkpolicy.AppendDNSEgressRules(nil, c.cfg.OpenShift)
	egressRules = append(egressRules,
		v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		v3.Rule{
			Action: v3.Pass,
		},
	)
	np := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhooksPolicyName,
			Namespace: common.CalicoNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(WebhooksName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(6443),
					},
				},
			},
			Egress: egressRules,
		},
	}

	// Create the correct security context for the webhook container. By default, it should run as non-root, but in Enterprise
	// we need to run as root to be able to write audit logs to the host filesystem.
	securtyContext := securitycontext.NewNonRootContext()
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		securtyContext = securitycontext.NewRootContext(c.cfg.Installation.KubernetesProvider.IsOpenShift())
	}

	// Create the Deployment for the webhook.
	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhooksName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Strategy: appsv1.DeploymentStrategy{
				// Use RollingUpdate to avoid downtime during rollouts. Since this is a webhook with
				// FailurePolicy=Fail, using Recreate would cause a window where no webhook pod is running,
				// blocking all matching API requests.
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       ptr.To(intstr.FromInt(1)),
					MaxUnavailable: ptr.To(intstr.FromInt(0)),
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: WebhooksName,
				},
				Spec: corev1.PodSpec{
					HostNetwork:        render.HostNetworkRequired(c.cfg.Installation),
					ServiceAccountName: WebhooksName,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers: []corev1.Container{{
						Name:            WebhooksName,
						Image:           c.webhooksImage,
						SecurityContext: securtyContext,
						Args: []string{
							"webhook",
							fmt.Sprintf("--tls-cert-file=%s", c.cfg.KeyPair.VolumeMountCertificateFilePath()),
							fmt.Sprintf("--tls-private-key-file=%s", c.cfg.KeyPair.VolumeMountKeyFilePath()),
						},
						Ports: []corev1.ContainerPort{{
							ContainerPort: 6443,
							Protocol:      corev1.ProtocolTCP,
						}},
						VolumeMounts: []corev1.VolumeMount{
							c.cfg.KeyPair.VolumeMount(c.SupportedOSType()),
							{
								Name:      "audit-logs",
								MountPath: "/var/log/calico/audit",
								ReadOnly:  false,
							},
						},
					}},
					Volumes: []corev1.Volume{
						// The volume for the TLS certs.
						c.cfg.KeyPair.Volume(),

						// Host volume for audit logs to be wrriten.
						{
							Name: "audit-logs",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/log/calico/audit",
									Type: ptr.To(corev1.HostPathDirectoryOrCreate),
								},
							},
						},
					},
				},
			},
		},
	}

	if overrides := c.cfg.APIServer.CalicoWebhooksDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(dep, overrides)
	}

	// Create the Service for the webhook.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      WebhooksName,
			Namespace: common.CalicoNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(6443),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	// Create the ValidatingWebhookConfiguration to register the webhook with the API server.
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api.projectcalico.org",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				// This first webhook is for CRUD operations on network policies, to ensure that tier-based RBAC is enforced
				Name: "tiered-rbac.api.projectcalico.org",
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
							Resources: []string{
								"networkpolicies",
								"globalnetworkpolicies",
								"stagednetworkpolicies",
								"stagedglobalnetworkpolicies",
							},
							Scope: ptr.To(admissionregistrationv1.AllScopes),
						},
					},
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
							admissionregistrationv1.Delete,
							admissionregistrationv1.Connect,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"networkpolicies", "globalnetworkpolicies", "stagednetworkpolicies", "stagedglobalnetworkpolicies"},
							Scope:       ptr.To(admissionregistrationv1.AllScopes),
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: common.CalicoNamespace,
						Name:      WebhooksName,
						Path:      ptr.To("/rbac"),
					},
					CABundle: c.cfg.KeyPair.GetCertificatePEM(),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				TimeoutSeconds:          ptr.To[int32](5),
				FailurePolicy:           ptr.To(admissionregistrationv1.Fail),
			},
			{
				// This webhook is for audit logging. The webhook controller will get events for all relevant Calico API types
				// and product audit logs for them.
				Name: "audit-logging.api.projectcalico.org",
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
							admissionregistrationv1.Delete,
							admissionregistrationv1.Connect,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"*"},
							Scope:       ptr.To(admissionregistrationv1.AllScopes),
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: common.CalicoNamespace,
						Name:      WebhooksName,
						Path:      ptr.To("/audit"),
					},
					CABundle: c.cfg.KeyPair.GetCertificatePEM(),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				TimeoutSeconds:          ptr.To[int32](5),
				FailurePolicy:           ptr.To(admissionregistrationv1.Ignore),
				MatchPolicy:             ptr.To(admissionregistrationv1.Exact),
			},
		},
	}

	// Create a MutatingAdmissionWebhookConfiguration to register mutating hooks for authorization reviews.
	mwc := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api.projectcalico.org",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				// This webhook is for v3.AuthorizationReviews.
				Name: "authorization-reviews.api.projectcalico.org",
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"projectcalico.org"},
							APIVersions: []string{"v3"},
							Resources:   []string{"authorizationreviews"},
							Scope:       ptr.To(admissionregistrationv1.ClusterScope),
						},
					},
				},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: common.CalicoNamespace,
						Name:      WebhooksName,
						Path:      ptr.To("/authorizationreview"),
					},
					CABundle: c.cfg.KeyPair.GetCertificatePEM(),
				},
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				TimeoutSeconds:          ptr.To[int32](5),
				FailurePolicy:           ptr.To(admissionregistrationv1.Fail),
				MatchPolicy:             ptr.To(admissionregistrationv1.Exact),
			},
		},
	}

	// Create a ClusterRole and ClusterRoleBinding for the webhook service account.
	rules := []rbacv1.PolicyRule{
		{
			// The webhook needs to be able to create SubjectAccessReviews in order to perform authorization checks for API requests.
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		rules = append(rules,
			rbacv1.PolicyRule{
				// The webhook needs to be able to update and delete AuthorizationReviews after they are handled.
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"authorizationreviews"},
				Verbs:     []string{"get", "list", "watch", "update", "delete"},
			},
			// The webhook service account needs a ClusterRole granting read access to clusterroles, clusterrolebindings, roles,
			// rolebindings, namespaces, and the Calico resources (tiers, uisettingsgroups, managedclusters) used by the RBAC calculator
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
					"uisettingsgroups",
					"managedclusters",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{
					"roles",
					"rolebindings",
					"clusterroles",
					"clusterrolebindings",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{
					"namespaces",
				},
				Verbs: []string{"get", "list", "watch"},
			},
		)
	}

	cr := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: WebhooksName,
		},
		Rules: rules,
	}

	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: WebhooksName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     WebhooksName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      WebhooksName,
				Namespace: common.CalicoNamespace,
			},
		},
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// For enterprise, we should create some additional objects (i.e., the mutating webhook).
		return []client.Object{sa, np, dep, svc, vwc, mwc, cr, crb}, nil
	}

	// Return the objects to be created for a Calico installation.
	return []client.Object{sa, np, dep, svc, vwc, cr, crb}, nil
}

func (c *component) Ready() bool {
	return true
}
