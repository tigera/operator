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

	// GatewayLabel marks operator-managed UI Gateways; the value is the
	// component's resource prefix. Cleanup lists Gateways by this label to
	// find namespaces holding leftover gateway resources.
	GatewayLabel = "operator.tigera.io/gateway"
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

	// RouteRequestTimeout, when set, becomes the HTTPRoute rule's request
	// timeout. Whisker sets "0s" to disable Envoy Gateway's 15-second
	// default — its flow-log stream is server-sent events and must stay
	// open. Nil keeps the Envoy Gateway default.
	RouteRequestTimeout *string

	// Enterprise controls whether the WAF filter's ServiceAccount and
	// RoleBinding are rendered. The proxy NetworkPolicy is rendered on both
	// variants. All three are only rendered when the Gateway is placed in the
	// backend (install) namespace: the GatewayAPI controller skips
	// calico-system (lifecycle guard), so this component fills that gap. For
	// custom gateway namespaces the GatewayAPI controller creates the
	// SA/RoleBinding itself and no NetworkPolicy is rendered, matching
	// user-brought Gateways.
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
	var objs []client.Object

	// The access Role comes first because it grants the write permissions needed
	// for the resources below. The first reconcile may still be denied while the
	// authorizer catches up; the requeue will retry, as with the TLS Secret below.
	objs = append(objs, c.role(c.cfg.GatewayNamespace), c.roleBinding(c.cfg.GatewayNamespace))
	if c.cfg.GatewayNamespace != c.cfg.BackendNamespace {
		// The Backend and ReferenceGrant are written in the backend namespace.
		objs = append(objs, c.role(c.cfg.BackendNamespace), c.roleBinding(c.cfg.BackendNamespace))
	}

	// Render the Gateway before the other gateway resources. It carries the
	// cleanup label, so even if a later resource fails to render, cleanup can
	// still discover the gateway resources.
	objs = append(objs, c.gateway())

	if c.cfg.GatewayNamespace != c.cfg.BackendNamespace {
		// Allow the HTTPRoute to reference the backend across namespaces.
		objs = append(objs, c.referenceGrant())
	}

	// The TLS secret is rendered after the Gateway. In a custom gateway
	// namespace the operator gains secret access through the RoleBinding the
	// GatewayAPI controller creates once it sees the Gateway there, so the
	// secret create fails on the first reconcile and succeeds on the retry.
	objs = append(objs,
		c.backend(),
		c.httpRoute(),
		c.tlsSecret(),
	)

	if c.cfg.GatewayNamespace == c.cfg.BackendNamespace {
		// calico-system has an operator-managed default-deny on both variants,
		// and the GatewayAPI controller skips it (lifecycle guard), so the
		// proxy NetworkPolicy is rendered here. In a custom namespace no
		// NetworkPolicy is rendered — the same treatment user-brought Gateways
		// get.
		objs = append(objs, c.proxyNetworkPolicy())
		if c.cfg.Enterprise {
			// The WAF HTTP filter's ServiceAccount and the RoleBinding giving
			// it Gateway API reads. The proxy pod runs as that account on
			// Enterprise. In a custom namespace the GatewayAPI controller
			// creates them instead.
			objs = append(objs,
				rgatewayapi.GatewayNamespaceServiceAccount(c.cfg.GatewayNamespace),
				rgatewayapi.GatewayNamespaceRoleBinding(c.cfg.GatewayNamespace),
			)
		}
	}

	return objs, nil
}

// role lets the operator create, update and delete this component's gateway
// resources in namespace: the cluster-wide ClusterRole keeps the read verbs,
// which the controller-runtime cache needs in every namespace, and the write
// verbs are confined to the namespaces the user configured.
func (c *gatewayComponent) role(namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.ResourcePrefix + "-ingressgateway-access",
			Namespace: namespace,
			Labels:    map[string]string{GatewayLabel: c.cfg.ResourcePrefix},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{gapi.GroupName},
				Resources: []string{"gateways", "httproutes", "referencegrants"},
				Verbs:     []string{"create", "update", "delete"},
			},
			{
				APIGroups: []string{EnvoyGatewayGroup},
				Resources: []string{"backends"},
				Verbs:     []string{"create", "update", "delete"},
			},
		},
	}
}

// roleBinding binds role to the operator's own ServiceAccount, the identity that
// renders the gateway resources.
func (c *gatewayComponent) roleBinding(namespace string) *rbacv1.RoleBinding {
	name := c.cfg.ResourcePrefix + "-ingressgateway-access"
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{GatewayLabel: c.cfg.ResourcePrefix},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     name,
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
			Labels: map[string]string{
				GatewayLabel: c.cfg.ResourcePrefix,
			},
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

	var timeouts *gapi.HTTPRouteTimeouts
	if c.cfg.RouteRequestTimeout != nil {
		timeouts = &gapi.HTTPRouteTimeouts{Request: ptr.To(gapi.Duration(*c.cfg.RouteRequestTimeout))}
	}

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
					Timeouts: timeouts,
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
				c.cfg.BackendNamespace, "calico-gateway-api-controller",
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
						// Envoy Gateway remaps privileged ports by adding 10000,
						// so listener port 443 becomes container port 10443.
						Ports: networkpolicy.Ports(10443),
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   v3.EntityRule{Nets: []string{"::/0"}},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(10443),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// DeletionConfiguration is the minimal config needed to identify gateway
// resources for cleanup. No TLS keypair, hostname, or class is required.
type DeletionConfiguration struct {
	ResourcePrefix   string
	GatewayNamespace string
	BackendNamespace string
	TLSSecretName    string
	Enterprise       bool

	// MoveTargetNamespace, when set, marks this as cleanup after the gateway
	// moved to that namespace while spec.ingressGateway stayed configured. The
	// Backend is kept — it lives in the backend namespace and the new render
	// still routes to it. The ReferenceGrant is deleted only when the target
	// is the backend namespace, where the render no longer emits it; for any
	// other target the render updates it in place.
	MoveTargetNamespace string
}

// DeletionComponent returns a render.Component whose Objects() puts every
// gateway-managed resource into objsToDelete. The objects carry only TypeMeta
// and ObjectMeta — enough for the component handler to issue Delete calls.
func DeletionComponent(cfg *DeletionConfiguration) *gatewayDeletionComponent {
	return &gatewayDeletionComponent{cfg: cfg}
}

type gatewayDeletionComponent struct {
	cfg *DeletionConfiguration
}

func (c *gatewayDeletionComponent) ResolveImages(_ *operatorv1.ImageSet) error { return nil }
func (c *gatewayDeletionComponent) SupportedOSType() rmeta.OSType              { return rmeta.OSTypeLinux }
func (c *gatewayDeletionComponent) Ready() bool                                { return true }

func (c *gatewayDeletionComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	gwNS := c.cfg.GatewayNamespace
	bkNS := c.cfg.BackendNamespace
	prefix := c.cfg.ResourcePrefix

	move := c.cfg.MoveTargetNamespace != ""

	objs := []client.Object{
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: c.cfg.TLSSecretName, Namespace: gwNS},
		},
		&gapi.HTTPRoute{
			TypeMeta:   metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: prefix + "-route", Namespace: gwNS},
		},
	}

	if !move {
		objs = append(objs,
			&envoyapi.Backend{
				TypeMeta:   metav1.TypeMeta{Kind: BackendKind, APIVersion: "gateway.envoyproxy.io/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: prefix + "-backend", Namespace: bkNS},
			},
		)
	}

	if gwNS != bkNS && (!move || c.cfg.MoveTargetNamespace == bkNS) {
		objs = append(objs,
			&gapi.ReferenceGrant{
				TypeMeta:   metav1.TypeMeta{Kind: "ReferenceGrant", APIVersion: "gateway.networking.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: prefix + "-allow-gateway", Namespace: bkNS},
			},
		)
	}

	if gwNS == bkNS {
		// Mirrors the main path: these are only rendered when the Gateway is
		// in the backend namespace. In a custom namespace the SA and
		// RoleBinding belong to the GatewayAPI controller's per-namespace
		// lifecycle — deleting them here could break other Gateways in that
		// namespace.
		objs = append(objs,
			&v3.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      networkpolicy.CalicoComponentPolicyPrefix + prefix + "-gateway-proxy",
					Namespace: gwNS,
				},
			},
		)
		if c.cfg.Enterprise {
			objs = append(objs,
				rgatewayapi.GatewayNamespaceServiceAccount(gwNS),
				rgatewayapi.GatewayNamespaceRoleBinding(gwNS),
			)
		}
	}

	// The Gateway goes after the resources found through it, mirroring the render.
	// If an earlier delete fails, it stays and the next reconcile still finds the
	// leftovers by its label.
	objs = append(objs, &gapi.Gateway{
		TypeMeta:   metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: prefix + "-gateway", Namespace: gwNS},
	})

	// The Role and RoleBinding go last, after the resources they permit deleting,
	// and in the reverse of the render order. On a move the backend namespace
	// keeps its resources, so it keeps its grant.
	objs = append(objs, c.roleBinding(gwNS), c.role(gwNS))
	if gwNS != bkNS && !move {
		objs = append(objs, c.roleBinding(bkNS), c.role(bkNS))
	}

	return nil, objs
}

func (c *gatewayDeletionComponent) role(namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.cfg.ResourcePrefix + "-ingressgateway-access", Namespace: namespace},
	}
}

func (c *gatewayDeletionComponent) roleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.cfg.ResourcePrefix + "-ingressgateway-access", Namespace: namespace},
	}
}
