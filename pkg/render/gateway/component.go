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
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

const (
	gatewayClassName = "tigera-gateway-class"
)

// Configuration holds the parameters needed to render Gateway API resources
// for a Calico UI component (Manager or Whisker).
type Configuration struct {
	// Hostname for the Gateway listener and TLS certificate SAN.
	Hostname string

	// Port the Gateway listens on externally.
	Port int32

	// GatewayNamespace is where the Gateway and Envoy Proxy run.
	GatewayNamespace string

	// BackendService is the name of the backend Service (e.g. "calico-manager", "whisker").
	BackendService string

	// BackendPort is the port on the backend Service.
	BackendPort int32

	// BackendNamespace is the namespace of the backend Service.
	BackendNamespace string

	// ResourcePrefix is used to name all resources (e.g. "calico-manager", "calico-whisker").
	ResourcePrefix string

	// TLSKeyPair provides the TLS certificate for the Gateway listener.
	TLSKeyPair certificatemanagement.KeyPairInterface

	// TrustedCAConfigMap is the name of the ConfigMap containing the CA bundle
	// for BackendTLSPolicy validation (e.g. "tigera-ca-bundle").
	TrustedCAConfigMap string
}

// Objects returns the Gateway API resources to create and the resources to delete.
func Objects(cfg *Configuration) ([]client.Object, []client.Object) {
	objs := []client.Object{
		tlsSecret(cfg),
		newGateway(cfg),
		httpRoute(cfg),
		backendTLSPolicy(cfg),
	}

	if cfg.GatewayNamespace != cfg.BackendNamespace {
		objs = append(objs, referenceGrant(cfg))
	}

	return objs, nil
}

func gwName(cfg *Configuration) string {
	return cfg.ResourcePrefix + "-gateway"
}

func routeName(cfg *Configuration) string {
	return cfg.ResourcePrefix + "-route"
}

func tlsSecretName(cfg *Configuration) string {
	return cfg.ResourcePrefix + "-gateway-tls"
}

func btlsName(cfg *Configuration) string {
	return cfg.ResourcePrefix + "-backend-tls"
}

func refGrantName(cfg *Configuration) string {
	return cfg.ResourcePrefix + "-allow-gateway"
}

func listenerName(cfg *Configuration) string {
	return cfg.ResourcePrefix + "-https"
}

func tlsSecret(cfg *Configuration) *corev1.Secret {
	secret := cfg.TLSKeyPair.Secret(cfg.GatewayNamespace)
	secret.Name = tlsSecretName(cfg)
	secret.Namespace = cfg.GatewayNamespace
	return secret
}

func newGateway(cfg *Configuration) *gapi.Gateway {
	tlsMode := gapi.TLSModeTerminate
	return &gapi.Gateway{
		TypeMeta: metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      gwName(cfg),
			Namespace: cfg.GatewayNamespace,
		},
		Spec: gapi.GatewaySpec{
			GatewayClassName: gatewayClassName,
			Listeners: []gapi.Listener{
				{
					Name:     gapi.SectionName(listenerName(cfg)),
					Protocol: gapi.HTTPSProtocolType,
					Port:     gapi.PortNumber(cfg.Port),
					Hostname: hostnamePtr(cfg.Hostname),
					TLS: &gapi.ListenerTLSConfig{
						Mode: &tlsMode,
						CertificateRefs: []gapi.SecretObjectReference{
							{Name: gapi.ObjectName(tlsSecretName(cfg))},
						},
					},
					AllowedRoutes: &gapi.AllowedRoutes{
						Namespaces: &gapi.RouteNamespaces{
							From: fromPtr(gapi.NamespacesFromSame),
						},
					},
				},
			},
		},
	}
}

func httpRoute(cfg *Configuration) *gapi.HTTPRoute {
	backendPort := gapi.PortNumber(cfg.BackendPort)
	backendNS := gapi.Namespace(cfg.BackendNamespace)

	return &gapi.HTTPRoute{
		TypeMeta: metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      routeName(cfg),
			Namespace: cfg.GatewayNamespace,
		},
		Spec: gapi.HTTPRouteSpec{
			CommonRouteSpec: gapi.CommonRouteSpec{
				ParentRefs: []gapi.ParentReference{
					{
						Name:        gapi.ObjectName(gwName(cfg)),
						SectionName: sectionNamePtr(listenerName(cfg)),
					},
				},
			},
			Rules: []gapi.HTTPRouteRule{
				{
					BackendRefs: []gapi.HTTPBackendRef{
						{
							BackendRef: gapi.BackendRef{
								BackendObjectReference: gapi.BackendObjectReference{
									Name:      gapi.ObjectName(cfg.BackendService),
									Namespace: &backendNS,
									Port:      &backendPort,
								},
							},
						},
					},
				},
			},
		},
	}
}

func backendTLSPolicy(cfg *Configuration) *gapi.BackendTLSPolicy {
	svcHostname := cfg.BackendService + "." + cfg.BackendNamespace + ".svc"
	return &gapi.BackendTLSPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "BackendTLSPolicy", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      btlsName(cfg),
			Namespace: cfg.BackendNamespace,
		},
		Spec: gapi.BackendTLSPolicySpec{
			TargetRefs: []gapi.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gapi.LocalPolicyTargetReference{
						Group: "",
						Kind:  "Service",
						Name:  gapi.ObjectName(cfg.BackendService),
					},
				},
			},
			Validation: gapi.BackendTLSPolicyValidation{
				CACertificateRefs: []gapi.LocalObjectReference{
					{
						Group: "",
						Kind:  "ConfigMap",
						Name:  gapi.ObjectName(cfg.TrustedCAConfigMap),
					},
				},
				Hostname: gapi.PreciseHostname(svcHostname),
			},
		},
	}
}

func referenceGrant(cfg *Configuration) *gatewayv1beta1.ReferenceGrant {
	return &gatewayv1beta1.ReferenceGrant{
		TypeMeta: metav1.TypeMeta{Kind: "ReferenceGrant", APIVersion: "gateway.networking.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      refGrantName(cfg),
			Namespace: cfg.BackendNamespace,
		},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1beta1.Group("gateway.networking.k8s.io"),
					Kind:      gatewayv1beta1.Kind("HTTPRoute"),
					Namespace: gatewayv1beta1.Namespace(cfg.GatewayNamespace),
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Service",
					Name:  objectNamePtr(cfg.BackendService),
				},
			},
		},
	}
}

// ResourceNames returns the names of all gateway resources that may be rendered,
// for use during cleanup when spec.gateway is removed.
func ResourceNames(prefix string) (gateway, route, tlsSecret, backendTLS, refGrant string) {
	return prefix + "-gateway",
		prefix + "-route",
		prefix + "-gateway-tls",
		prefix + "-backend-tls",
		prefix + "-allow-gateway"
}

// ManagerConfig returns a Configuration pre-filled for Enterprise Manager.
func ManagerConfig(hostname string, port int32, gatewayNamespace string, tlsKeyPair certificatemanagement.KeyPairInterface) *Configuration {
	return &Configuration{
		Hostname:           hostname,
		Port:               port,
		GatewayNamespace:   gatewayNamespace,
		BackendService:     "calico-manager",
		BackendPort:        9443,
		BackendNamespace:   common.CalicoNamespace,
		ResourcePrefix:     "calico-manager",
		TLSKeyPair:         tlsKeyPair,
		TrustedCAConfigMap: "tigera-ca-bundle",
	}
}

// WhiskerConfig returns a Configuration pre-filled for OSS Whisker.
func WhiskerConfig(hostname string, port int32, gatewayNamespace string, tlsKeyPair certificatemanagement.KeyPairInterface) *Configuration {
	return &Configuration{
		Hostname:           hostname,
		Port:               port,
		GatewayNamespace:   gatewayNamespace,
		BackendService:     "whisker",
		BackendPort:        8443,
		BackendNamespace:   common.CalicoNamespace,
		ResourcePrefix:     "calico-whisker",
		TLSKeyPair:         tlsKeyPair,
		TrustedCAConfigMap: "tigera-ca-bundle",
	}
}

func hostnamePtr(h string) *gapi.Hostname {
	hostname := gapi.Hostname(h)
	return &hostname
}

func sectionNamePtr(s string) *gapi.SectionName {
	sn := gapi.SectionName(s)
	return &sn
}

func fromPtr(f gapi.FromNamespaces) *gapi.FromNamespaces {
	return &f
}

func objectNamePtr(name string) *gatewayv1beta1.ObjectName {
	n := gatewayv1beta1.ObjectName(name)
	return &n
}
