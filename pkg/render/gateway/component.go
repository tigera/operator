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
	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	EnvoyGatewayGroup = "gateway.envoyproxy.io"
	BackendKind       = "Backend"
)

// Configuration holds everything the shared gateway component needs to render
// Gateway API resources for a UI component (Manager or Whisker).
type Configuration struct {
	Hostname         string
	Port             int32
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
		c.tlsSecret(),
		c.gateway(),
		c.backend(),
		c.httpRoute(),
	}

	if rg := c.referenceGrant(); rg != nil {
		objs = append(objs, rg)
	}

	return objs, nil
}

func (c *gatewayComponent) tlsSecret() *corev1.Secret {
	return c.cfg.TLSKeyPair.Secret(c.cfg.GatewayNamespace)
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
					Port:     gapi.PortNumber(c.cfg.Port),
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

// referenceGrant creates a ReferenceGrant when the gateway namespace differs
// from the backend namespace, allowing the HTTPRoute to reference the Backend
// across namespaces.
func (c *gatewayComponent) referenceGrant() *gapi.ReferenceGrant {
	if c.cfg.GatewayNamespace == c.cfg.BackendNamespace {
		return nil
	}

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
