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

package gateway_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/gateway"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Gateway component render", func() {
	const (
		gwNS       = "calico-system"
		bkNS       = "calico-system"
		hostname   = "manager.example.com"
		prefix     = "calico-manager"
		className  = "calico-gateway"
		svcName    = "calico-manager"
		svcPort    = int32(9443)
		caBundleCM = "tigera-ca-bundle"
		tlsName    = "calico-manager-gateway-tls"
	)

	var (
		cfg      *gateway.Configuration
		toCreate []client.Object
		toDelete []client.Object
	)

	BeforeEach(func() {
		secret, err := certificatemanagement.CreateSelfSignedSecret(tlsName, common.OperatorNamespace(), tlsName, nil)
		Expect(err).NotTo(HaveOccurred())
		kp := certificatemanagement.NewKeyPair(secret, []string{""}, "")

		cfg = &gateway.Configuration{
			Hostname:                     hostname,
			GatewayNamespace:             gwNS,
			GatewayClassName:             className,
			BackendServiceName:           svcName,
			BackendPort:                  svcPort,
			BackendNamespace:             bkNS,
			BackendCABundleConfigMapName: caBundleCM,
			TLSKeyPair:                   kp,
			ResourcePrefix:               prefix,
			Enterprise:                   true,
			OpenShift:                    false,
		}
	})

	Context("same namespace (gateway == backend)", func() {
		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("returns objects to create and nothing to delete", func() {
			Expect(toDelete).To(BeNil())
			Expect(toCreate).NotTo(BeEmpty())
		})

		It("does not include cross-namespace resources", func() {
			for _, obj := range toCreate {
				if _, ok := obj.(*gapi.ReferenceGrant); ok {
					Fail("ReferenceGrant should not be rendered when gateway and backend share a namespace")
				}
			}
		})

		It("renders a TLS secret in the gateway namespace", func() {
			secret := findObject[*corev1.Secret](toCreate, tlsName, gwNS)
			Expect(secret).NotTo(BeNil())
			Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
		})

		It("renders a Gateway with the correct listener", func() {
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(gw).NotTo(BeNil())
			Expect(string(gw.Spec.GatewayClassName)).To(Equal(className))
			Expect(gw.Spec.Listeners).To(HaveLen(1))
			Expect(gw.Spec.Listeners[0].Protocol).To(Equal(gapi.HTTPSProtocolType))
			Expect(gw.Spec.Listeners[0].Port).To(Equal(gapi.PortNumber(443)))
			Expect(*gw.Spec.Listeners[0].TLS.Mode).To(Equal(gapi.TLSModeTerminate))
		})

		It("renders an HTTPRoute targeting the Backend", func() {
			route := findObject[*gapi.HTTPRoute](toCreate, prefix+"-route", gwNS)
			Expect(route).NotTo(BeNil())
			Expect(route.Spec.Rules).To(HaveLen(1))
			backendRef := route.Spec.Rules[0].BackendRefs[0]
			Expect(string(backendRef.Name)).To(Equal(prefix + "-backend"))
			Expect(*backendRef.Kind).To(Equal(gapi.Kind("Backend")))
		})

		It("renders a Backend with TLS to the service", func() {
			backend := findObject[*envoyapi.Backend](toCreate, prefix+"-backend", bkNS)
			Expect(backend).NotTo(BeNil())
			Expect(backend.Spec.Endpoints).To(HaveLen(1))
			Expect(backend.Spec.Endpoints[0].FQDN.Hostname).To(Equal(svcName + "." + bkNS + ".svc"))
			Expect(backend.Spec.Endpoints[0].FQDN.Port).To(Equal(svcPort))
			Expect(backend.Spec.TLS).NotTo(BeNil())
			Expect(backend.Spec.TLS.CACertificateRefs).To(HaveLen(1))
			Expect(string(backend.Spec.TLS.CACertificateRefs[0].Name)).To(Equal(caBundleCM))
		})
	})

	Context("Enterprise resources", func() {
		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("renders SA, RoleBinding, and NetworkPolicy when Enterprise is true", func() {
			sa := findObject[*corev1.ServiceAccount](toCreate, "waf-http-filter", gwNS)
			Expect(sa).NotTo(BeNil())
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
		})

		It("includes IPv4 and IPv6 ingress rules in the proxy NetworkPolicy", func() {
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
			Expect(np.Spec.Ingress).To(HaveLen(2))
			Expect(np.Spec.Ingress[0].Source.Nets).To(ConsistOf("0.0.0.0/0"))
			Expect(np.Spec.Ingress[0].Destination.Ports).To(Equal(networkpolicy.Ports(10443)))
			Expect(np.Spec.Ingress[1].Source.Nets).To(ConsistOf("::/0"))
			Expect(np.Spec.Ingress[1].Destination.Ports).To(Equal(networkpolicy.Ports(10443)))
		})

		Context("when Enterprise is false", func() {
			BeforeEach(func() {
				cfg.Enterprise = false
			})

			It("skips SA and NetworkPolicy", func() {
				for _, obj := range toCreate {
					if _, ok := obj.(*corev1.ServiceAccount); ok {
						Fail("ServiceAccount should not be rendered when Enterprise is false")
					}
					if _, ok := obj.(*v3.NetworkPolicy); ok {
						Fail("NetworkPolicy should not be rendered when Enterprise is false")
					}
				}
			})
		})
	})

	Context("cross-namespace (gateway != backend)", func() {
		BeforeEach(func() {
			cfg.GatewayNamespace = "custom-gateway-ns"
		})

		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("includes ReferenceGrant in the backend namespace", func() {
			rg := findObject[*gapi.ReferenceGrant](toCreate, prefix+"-allow-gateway", bkNS)
			Expect(rg).NotTo(BeNil())
			Expect(rg.Spec.From).To(HaveLen(1))
			Expect(string(rg.Spec.From[0].Namespace)).To(Equal("custom-gateway-ns"))
		})

		It("does not include operator Roles", func() {
			for _, obj := range toCreate {
				if _, ok := obj.(*rbacv1.Role); ok {
					Fail("Role should not be rendered — operator uses ClusterRole")
				}
			}
		})
	})

	Context("OpenShift", func() {
		BeforeEach(func() {
			cfg.OpenShift = true
		})

		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("includes OpenShift DNS egress rules in NetworkPolicy", func() {
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
			Expect(len(np.Spec.Egress)).To(BeNumerically(">", 2))
		})
	})

	Context("component interface", func() {
		It("implements ResolveImages without error", func() {
			Expect(gateway.Component(cfg).ResolveImages(nil)).To(Succeed())
		})

		It("reports Ready", func() {
			Expect(gateway.Component(cfg).Ready()).To(BeTrue())
		})

		It("reports Linux OS type", func() {
			Expect(string(gateway.Component(cfg).SupportedOSType())).To(Equal("linux"))
		})
	})

	Context("Gateway listener hostname", func() {
		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("sets the hostname on the listener", func() {
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(gw.Spec.Listeners[0].Hostname).To(Equal(ptr.To(gapi.Hostname(hostname))))
		})

		It("sets AllowedRoutes to Same namespace", func() {
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(*gw.Spec.Listeners[0].AllowedRoutes.Namespaces.From).To(Equal(gapi.NamespacesFromSame))
		})
	})
})

var _ = Describe("Gateway deletion component", func() {
	const (
		gwNS      = "calico-system"
		bkNS      = "calico-system"
		prefix    = "calico-manager"
		tlsSecret = "calico-manager-gateway-tls"
	)

	var (
		delCfg   *gateway.DeletionConfiguration
		toCreate []client.Object
		toDelete []client.Object
	)

	BeforeEach(func() {
		delCfg = &gateway.DeletionConfiguration{
			ResourcePrefix:   prefix,
			GatewayNamespace: gwNS,
			BackendNamespace: bkNS,
			TLSSecretName:    tlsSecret,
			Enterprise:       true,
		}
	})

	JustBeforeEach(func() {
		comp := gateway.DeletionComponent(delCfg)
		toCreate, toDelete = comp.Objects()
	})

	Context("same namespace", func() {
		It("returns all objects in objsToDelete and nothing in objsToCreate", func() {
			Expect(toCreate).To(BeNil())
			Expect(toDelete).NotTo(BeEmpty())
		})

		It("targets the correct resource names", func() {
			names := objectNames(toDelete)
			Expect(names).To(ContainElements(
				prefix+"-gateway",
				prefix+"-route",
				prefix+"-backend",
				tlsSecret,
			))
		})

		It("does not include cross-namespace resources", func() {
			for _, obj := range toDelete {
				if _, ok := obj.(*gapi.ReferenceGrant); ok {
					Fail("ReferenceGrant should not appear when namespaces match")
				}
			}
		})

		It("includes Enterprise resources", func() {
			sa := findObject[*corev1.ServiceAccount](toDelete, "waf-http-filter", gwNS)
			Expect(sa).NotTo(BeNil())
			np := findObject[*v3.NetworkPolicy](toDelete, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
		})
	})

	Context("Enterprise false", func() {
		BeforeEach(func() {
			delCfg.Enterprise = false
		})

		It("skips Enterprise resources", func() {
			for _, obj := range toDelete {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					Fail("ServiceAccount should not appear when Enterprise is false")
				}
				if _, ok := obj.(*v3.NetworkPolicy); ok {
					Fail("NetworkPolicy should not appear when Enterprise is false")
				}
			}
		})
	})

	Context("cross-namespace", func() {
		BeforeEach(func() {
			delCfg.GatewayNamespace = "custom-gateway-ns"
			delCfg.Enterprise = false
		})

		It("includes ReferenceGrant in the backend namespace", func() {
			rg := findObject[*gapi.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)
			Expect(rg).NotTo(BeNil())
		})
	})

	Context("component interface", func() {
		It("implements ResolveImages without error", func() {
			Expect(gateway.DeletionComponent(delCfg).ResolveImages(nil)).To(Succeed())
		})

		It("reports Ready", func() {
			Expect(gateway.DeletionComponent(delCfg).Ready()).To(BeTrue())
		})
	})
})

func findObject[T client.Object](objs []client.Object, name, ns string) T {
	for _, obj := range objs {
		if t, ok := obj.(T); ok && obj.GetName() == name && obj.GetNamespace() == ns {
			return t
		}
	}
	var zero T
	return zero
}

func objectNames(objs []client.Object) []string {
	names := make([]string, len(objs))
	for i, obj := range objs {
		names[i] = obj.GetName()
	}
	return names
}
