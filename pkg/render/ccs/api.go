// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package ccs

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	calicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	APIResourceName   = "tigera-ccs-api"
	APICertSecretName = "tigera-ccs-api-tls"

	APIAccessPolicyName        = networkpolicy.TigeraComponentPolicyPrefix + "ccs-api-access"
	ControllerAccessPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "ccs-controller-access"

	APITLSTerminatedRoute      = "tigera-ccs-api-tls-route"
	APIPublicCertConfigMapName = "tigera-ccs-api-public-cert"
)

func (c *component) apiServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIResourceName, Namespace: c.cfg.Namespace},
	}
}

func (c *component) apiRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIResourceName, Namespace: c.cfg.Namespace},
		Rules:      []rbacv1.PolicyRule{},
	}
}

func (c *component) apiRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIResourceName, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     APIResourceName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIResourceName,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *component) apiClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIResourceName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"ccsresults", "ccsruns"},
				Verbs:     []string{"get", "create"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

func (c *component) apiClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIResourceName},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     APIResourceName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIResourceName,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *component) apiDeployment() *appsv1.Deployment {
	var keyPath, certPath string
	if c.cfg.APIKeyPair != nil {
		keyPath, certPath = c.cfg.APIKeyPair.VolumeMountKeyFilePath(), c.cfg.APIKeyPair.VolumeMountCertificateFilePath()
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "trace"},
		{Name: "HTTPS_ENABLED", Value: "true"},
		{Name: "HTTPS_CERT", Value: certPath},
		{Name: "HTTPS_KEY", Value: keyPath},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
		{Name: "LINSEED_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		{Name: "LINSEED_TOKEN", Value: render.GetLinseedTokenPath(c.cfg.ManagementClusterConnection != nil)},
		{Name: "RESOURCE_AUTHORIZATION_MODE", Value: "k8s_rbac"},
		{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: certificatemanagement.TrustedCertBundleMountPath},
	}

	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}
		if c.cfg.Tenant.MultiTenant() {
			envVars = append(envVars, corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: c.cfg.Tenant.Namespace})
			envVars = append(envVars, corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", c.cfg.Tenant.Namespace)})
			envVars = append(envVars, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: render.ManagerService(c.cfg.Tenant)})
		}
	}

	annots := c.cfg.TrustedBundle.HashAnnotations()
	if c.cfg.APIKeyPair != nil {
		annots[c.cfg.APIKeyPair.HashAnnotationKey()] = c.cfg.APIKeyPair.HashAnnotationValue()
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        APIResourceName,
			Namespace:   c.cfg.Namespace,
			Labels:      map[string]string{"k8s-app": APIResourceName},
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: APIResourceName,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			Containers: []corev1.Container{
				{
					Name:            APIResourceName,
					Image:           "gcr.io/unique-caldron-775/suresh/ccs-api:dd-1", //c.apiImage,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					Ports:           []corev1.ContainerPort{{ContainerPort: 5557}},
					SecurityContext: securitycontext.NewNonRootContext(),
					VolumeMounts: append(
						c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType()),
						c.cfg.APIKeyPair.VolumeMount(c.SupportedOSType()),
					),
				},
			},
			RestartPolicy: corev1.RestartPolicyAlways,
			Volumes: []corev1.Volume{
				c.cfg.APIKeyPair.Volume(),
				c.cfg.TrustedBundle.Volume(),
			},
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIResourceName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{"k8s-app": APIResourceName},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": APIResourceName},
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.ComplianceConfigurationSecurity != nil {
		if overrides := c.cfg.ComplianceConfigurationSecurity.Spec.CCSAPIDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (c *component) apiService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIResourceName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{"k8s-app": APIResourceName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": APIResourceName},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.FromInt32(5557),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func (c *component) apiAllowTigeraNetworkPolicy() *calicov3.NetworkPolicy {
	_ = networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace)
	return &calicov3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIAccessPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: calicov3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(APIResourceName),
			Types:    []calicov3.PolicyType{calicov3.PolicyTypeIngress, calicov3.PolicyTypeEgress},
			Ingress: []calicov3.Rule{
				{
					Action: calicov3.Allow,
				},
			},
			Egress: []calicov3.Rule{
				{
					Action: calicov3.Allow,
				},
			},
		},
	}
}

// tlsTerminatedRoute creates the TLSTerminatedRoute object needed to route request from the UI, through voltron, and to
// the Bast API.
func (c *component) apiTLSTerminatedRoute() *operatorv1.TLSTerminatedRoute {
	return &operatorv1.TLSTerminatedRoute{
		TypeMeta: metav1.TypeMeta{Kind: "TLSTerminatedRoute", APIVersion: "operator.tigera.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APITLSTerminatedRoute,
			Namespace: render.ManagerNamespace,
		},
		Spec: operatorv1.TLSTerminatedRouteSpec{
			Target: operatorv1.TargetTypeUI,
			PathMatch: &operatorv1.PathMatch{
				Path:        "/ccs/",
				PathRegexp:  ptr.ToPtr("^/ccs/?"),
				PathReplace: ptr.ToPtr("/"),
			},
			Destination: fmt.Sprintf("https://%s.%s.svc:%s", APIResourceName, c.cfg.Namespace, "443"),
			CABundle: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: APIPublicCertConfigMapName,
				},
				Key: corev1.TLSCertKey,
			},
		},
	}
}

// publicCertConfigMap creates a config map that has the public CA for the API (without the private one), and can be used
// and copied by our components.
func (c *component) apiPublicCertConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APIPublicCertConfigMapName, Namespace: c.cfg.Namespace},
		Data: map[string]string{
			corev1.TLSCertKey: string(c.cfg.APIKeyPair.GetCertificatePEM()),
		},
	}
}
