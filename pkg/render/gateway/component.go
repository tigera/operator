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

package gateway

import (
	"fmt"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rgatewayapi "github.com/tigera/operator/pkg/render/gatewayapi"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	EnvoyGatewayGroup = "gateway.envoyproxy.io"
	BackendKind       = "Backend"

	OperatorGatewayRoleName = "tigera-operator-gateway"
)

// Configuration holds everything the shared gateway component needs to render
// Gateway API resources for a UI component (Manager or Whisker).
type Configuration struct {
	Hostname         string
	GatewayNamespace string
	GatewayClassName string

	BackendServiceName           string
	BackendPort                  int32
	BackendNamespace             string
	BackendCABundleConfigMapName string

	TLSKeyPair certificatemanagement.KeyPairInterface

	// ResourcePrefix names all generated resources, e.g. "calico-manager" produces
	// "calico-manager-gateway", "calico-manager-route", etc.
	ResourcePrefix string

	// Enterprise controls whether the proxy SA, RoleBinding, and NetworkPolicy
	// are rendered. The GatewayAPI controller creates SA/RoleBinding in user
	// namespaces but skips calico-system (lifecycle guard); when we place a
	// Gateway there, we render them operator-owned on the main path.
	Enterprise bool

	OpenShift bool
}

// Component renders Gateway API resources for CIG access to a UI component.
func Component(cfg *Configuration) *gatewayComponent {
	return &gatewayComponent{cfg: cfg}
}

type gatewayComponent struct {
	cfg *Configuration
}

func (c *gatewayComponent) ResolveImages(_ *operatorv1.ImageSet) error {
	return nil
}

func (c *gatewayComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *gatewayComponent) Ready() bool {
	return true
}

func (c *gatewayComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	objs := []client.Object{
		c.operatorGatewayRole(),
		c.operatorGatewayRoleBinding(),
		c.tlsSecret(),
		c.gateway(),
		c.backend(),
		c.httpRoute(),
	}

	if c.cfg.GatewayNamespace != c.cfg.BackendNamespace {
		objs = append(objs,
			c.referenceGrant(),
			c.operatorBackendRole(),
			c.operatorBackendRoleBinding(),
		)
	}

	if c.cfg.Enterprise {
		objs = append(objs,
			rgatewayapi.GatewayNamespaceServiceAccount(c.cfg.GatewayNamespace),
			rgatewayapi.GatewayNamespaceRoleBinding(c.cfg.GatewayNamespace),
			c.proxyNetworkPolicy(),
		)
	}

	return objs, nil
}

func (c *gatewayComponent) tlsSecret() *corev1.Secret {
	s := c.cfg.TLSKeyPair.Secret(c.cfg.GatewayNamespace)
	s.Type = corev1.SecretTypeTLS
	return s
}

func (c *gatewayComponent) gateway() *gapi.Gateway {
	listenerName := gapi.SectionName(c.cfg.ResourcePrefix + "-https")
	hostname := gapi.Hostname(c.cfg.Hostname)
	tlsSecretName := c.cfg.TLSKeyPair.GetName()

	return &gapi.Gateway{
		TypeMeta: metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.ResourcePrefix + "-gateway",
			Namespace: c.cfg.GatewayNamespace,
		},
		Spec: gapi.GatewaySpec{
			GatewayClassName: gapi.ObjectName(c.cfg.GatewayClassName),
			Listeners: []gapi.Listener{
				{
					Name:     listenerName,
					Protocol: gapi.HTTPSProtocolType,
					Port:     gapi.PortNumber(443),
					Hostname: &hostname,
					TLS: &gapi.ListenerTLSConfig{
						Mode: ptr.To(gapi.TLSModeTerminate),
						CertificateRefs: []gapi.SecretObjectReference{
							{
								Name: gapi.ObjectName(tlsSecretName),
							},
						},
					},
					AllowedRoutes: &gapi.AllowedRoutes{
						Namespaces: &gapi.RouteNamespaces{
							From: ptr.To(gapi.NamespacesFromSame),
						},
					},
				},
			},
		},
	}
}

func (c *gatewayComponent) httpRoute() *gapi.HTTPRoute {
	gatewayName := gapi.ObjectName(c.cfg.ResourcePrefix + "-gateway")
	sectionName := gapi.SectionName(c.cfg.ResourcePrefix + "-https")
	backendName := gapi.ObjectName(c.cfg.ResourcePrefix + "-backend")
	backendNS := gapi.Namespace(c.cfg.BackendNamespace)
	group := gapi.Group(EnvoyGatewayGroup)

	return &gapi.HTTPRoute{
		TypeMeta: metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.ResourcePrefix + "-route",
			Namespace: c.cfg.GatewayNamespace,
		},
		Spec: gapi.HTTPRouteSpec{
			CommonRouteSpec: gapi.CommonRouteSpec{
				ParentRefs: []gapi.ParentReference{
					{
						Name:        gatewayName,
						SectionName: &sectionName,
					},
				},
			},
			Rules: []gapi.HTTPRouteRule{
				{
					BackendRefs: []gapi.HTTPBackendRef{
						{
							BackendRef: gapi.BackendRef{
								BackendObjectReference: gapi.BackendObjectReference{
									Group:     &group,
									Kind:      ptr.To(gapi.Kind(BackendKind)),
									Name:      backendName,
									Namespace: &backendNS,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (c *gatewayComponent) backend() *envoyapi.Backend {
	svcFQDN := c.cfg.BackendServiceName + "." + c.cfg.BackendNamespace + ".svc"
	sni := gapi.PreciseHostname(svcFQDN)

	return &envoyapi.Backend{
		TypeMeta: metav1.TypeMeta{Kind: BackendKind, APIVersion: "gateway.envoyproxy.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.ResourcePrefix + "-backend",
			Namespace: c.cfg.BackendNamespace,
		},
		Spec: envoyapi.BackendSpec{
			Endpoints: []envoyapi.BackendEndpoint{
				{
					FQDN: &envoyapi.FQDNEndpoint{
						Hostname: svcFQDN,
						Port:     c.cfg.BackendPort,
					},
				},
			},
			TLS: &envoyapi.BackendTLSSettings{
				CACertificateRefs: []gapi.LocalObjectReference{
					{
						Group: "",
						Kind:  "ConfigMap",
						Name:  gapi.ObjectName(c.cfg.BackendCABundleConfigMapName),
					},
				},
				SNI: &sni,
			},
		},
	}
}

func (c *gatewayComponent) referenceGrant() *gapi.ReferenceGrant {
	backendName := gapi.ObjectName(c.cfg.ResourcePrefix + "-backend")

	return &gapi.ReferenceGrant{
		TypeMeta: metav1.TypeMeta{Kind: "ReferenceGrant", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.ResourcePrefix + "-allow-gateway",
			Namespace: c.cfg.BackendNamespace,
		},
		Spec: gapi.ReferenceGrantSpec{
			From: []gapi.ReferenceGrantFrom{
				{
					Group:     gapi.GroupName,
					Kind:      "HTTPRoute",
					Namespace: gapi.Namespace(c.cfg.GatewayNamespace),
				},
			},
			To: []gapi.ReferenceGrantTo{
				{
					Group: gapi.Group(EnvoyGatewayGroup),
					Kind:  BackendKind,
					Name:  &backendName,
				},
			},
		},
	}
}

func (c *gatewayComponent) operatorGatewayRole() *rbacv1.Role {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes"},
			Verbs:     []string{"create", "get", "list", "update", "patch", "delete", "watch"},
		},
	}
	if c.cfg.GatewayNamespace == c.cfg.BackendNamespace {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{EnvoyGatewayGroup},
			Resources: []string{"backends"},
			Verbs:     []string{"create", "get", "list", "update", "patch", "delete", "watch"},
		})
	}
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OperatorGatewayRoleName,
			Namespace: c.cfg.GatewayNamespace,
		},
		Rules: rules,
	}
}

func (c *gatewayComponent) operatorGatewayRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OperatorGatewayRoleName,
			Namespace: c.cfg.GatewayNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     OperatorGatewayRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      common.OperatorServiceAccount(),
				Namespace: common.OperatorNamespace(),
			},
		},
	}
}

func (c *gatewayComponent) operatorBackendRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OperatorGatewayRoleName,
			Namespace: c.cfg.BackendNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{EnvoyGatewayGroup},
				Resources: []string{"backends"},
				Verbs:     []string{"create", "get", "list", "update", "patch", "delete", "watch"},
			},
			{
				APIGroups: []string{"gateway.networking.k8s.io"},
				Resources: []string{"referencegrants"},
				Verbs:     []string{"create", "get", "list", "update", "patch", "delete", "watch"},
			},
		},
	}
}

func (c *gatewayComponent) operatorBackendRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      OperatorGatewayRoleName,
			Namespace: c.cfg.BackendNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     OperatorGatewayRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      common.OperatorServiceAccount(),
				Namespace: common.OperatorNamespace(),
			},
		},
	}
}

// proxyNetworkPolicy creates a Calico NetworkPolicy that allows the Envoy
// proxy pod to function in calico-system (which has a default deny).
func (c *gatewayComponent) proxyNetworkPolicy() *v3.NetworkPolicy {
	gatewayName := c.cfg.ResourcePrefix + "-gateway"
	policyName := networkpolicy.CalicoComponentPolicyPrefix + gatewayName + "-proxy"

	egressRules := networkpolicy.AppendDNSEgressRules(nil, c.cfg.OpenShift)
	egressRules = append(egressRules,
		v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: networkpolicy.CreateEntityRule(
				c.cfg.GatewayNamespace, "calico-gateway-api-controller",
				18000, 18001,
			),
		},
		v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: networkpolicy.CreateEntityRule(
				c.cfg.BackendNamespace, c.cfg.BackendServiceName,
				uint16(c.cfg.BackendPort),
			),
		},
	)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName,
			Namespace: c.cfg.GatewayNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: fmt.Sprintf("gateway.envoyproxy.io/owning-gateway-name == '%s'", gatewayName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   v3.EntityRule{Nets: []string{"0.0.0.0/0"}},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(443),
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   v3.EntityRule{Nets: []string{"::/0"}},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(443),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// ResourceNames returns the names of all gateway resources that this component
// manages. Used by controllers to clean up resources when gateway is removed.
func ResourceNames(prefix, gatewayNS, backendNS string) []client.ObjectKey {
	keys := []client.ObjectKey{
		{Name: prefix + "-gateway", Namespace: gatewayNS},
		{Name: prefix + "-route", Namespace: gatewayNS},
		{Name: prefix + "-backend", Namespace: backendNS},
	}
	if gatewayNS != backendNS {
		keys = append(keys, client.ObjectKey{Name: prefix + "-allow-gateway", Namespace: backendNS})
	}
	return keys
}
