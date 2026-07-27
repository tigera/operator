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
		svcName    = "tigera-manager"
		svcPort    = int32(9443)
		caBundleCM = "tigera-ca-bundle"
		tlsName    = "calico-manager-gateway-tls"
	)

	var (
		cfg *gateway.Configuration
		kp  certificatemanagement.KeyPairInterface
	)

	BeforeEach(func() {
		secret, err := certificatemanagement.CreateSelfSignedSecret(tlsName, common.OperatorNamespace(), tlsName, nil)
		Expect(err).NotTo(HaveOccurred())
		kp = certificatemanagement.NewKeyPair(secret, []string{""}, "")

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
		It("returns objects to create and nothing to delete", func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete := comp.Objects()
			Expect(toDelete).To(BeNil())
			Expect(toCreate).NotTo(BeEmpty())
		})

		It("does not include cross-namespace resources", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			for _, obj := range toCreate {
				if _, ok := obj.(*gapi.ReferenceGrant); ok {
					Fail("ReferenceGrant should not be rendered when gateway and backend share a namespace")
				}
			}
		})

		It("renders the operator Role with gateway and backend rules", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			role := findObject[*rbacv1.Role](toCreate, gateway.OperatorGatewayRoleName, gwNS)
			Expect(role).NotTo(BeNil())
			Expect(role.Rules).To(HaveLen(2))
			Expect(role.Rules[0].Resources).To(ConsistOf("gateways", "httproutes"))
			Expect(role.Rules[1].Resources).To(ConsistOf("backends"))
		})

		It("binds the Role to the operator service account", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			rb := findObject[*rbacv1.RoleBinding](toCreate, gateway.OperatorGatewayRoleName, gwNS)
			Expect(rb).NotTo(BeNil())
			Expect(rb.RoleRef.Name).To(Equal(gateway.OperatorGatewayRoleName))
			Expect(rb.Subjects).To(HaveLen(1))
			Expect(rb.Subjects[0].Name).To(Equal(common.OperatorServiceAccount()))
			Expect(rb.Subjects[0].Namespace).To(Equal(common.OperatorNamespace()))
		})

		It("renders a TLS secret in the gateway namespace", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			secret := findObject[*corev1.Secret](toCreate, tlsName, gwNS)
			Expect(secret).NotTo(BeNil())
			Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
		})

		It("renders a Gateway with the correct listener", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(gw).NotTo(BeNil())
			Expect(string(gw.Spec.GatewayClassName)).To(Equal(className))
			Expect(gw.Spec.Listeners).To(HaveLen(1))
			Expect(gw.Spec.Listeners[0].Protocol).To(Equal(gapi.HTTPSProtocolType))
			Expect(gw.Spec.Listeners[0].Port).To(Equal(gapi.PortNumber(443)))
			Expect(*gw.Spec.Listeners[0].TLS.Mode).To(Equal(gapi.TLSModeTerminate))
		})

		It("renders an HTTPRoute targeting the Backend", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			route := findObject[*gapi.HTTPRoute](toCreate, prefix+"-route", gwNS)
			Expect(route).NotTo(BeNil())
			Expect(route.Spec.Rules).To(HaveLen(1))
			backendRef := route.Spec.Rules[0].BackendRefs[0]
			Expect(string(backendRef.Name)).To(Equal(prefix + "-backend"))
			Expect(*backendRef.Kind).To(Equal(gapi.Kind("Backend")))
		})

		It("renders a Backend with TLS to the service", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
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
		It("renders SA, RoleBinding, and NetworkPolicy when Enterprise is true", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			sa := findObject[*corev1.ServiceAccount](toCreate, "waf-http-filter", gwNS)
			Expect(sa).NotTo(BeNil())
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
		})

		It("skips Enterprise resources when Enterprise is false", func() {
			cfg.Enterprise = false
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			for _, obj := range toCreate {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					Fail("ServiceAccount should not be rendered when Enterprise is false")
				}
				if _, ok := obj.(*v3.NetworkPolicy); ok {
					Fail("NetworkPolicy should not be rendered when Enterprise is false")
				}
			}
		})

		It("includes IPv4 and IPv6 ingress rules in the proxy NetworkPolicy", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
			Expect(np.Spec.Ingress).To(HaveLen(2))
			Expect(np.Spec.Ingress[0].Source.Nets).To(ConsistOf("0.0.0.0/0"))
			Expect(np.Spec.Ingress[1].Source.Nets).To(ConsistOf("::/0"))
		})
	})

	Context("cross-namespace (gateway != backend)", func() {
		BeforeEach(func() {
			cfg.GatewayNamespace = "custom-gateway-ns"
		})

		It("includes ReferenceGrant in the backend namespace", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			rg := findObject[*gapi.ReferenceGrant](toCreate, prefix+"-allow-gateway", bkNS)
			Expect(rg).NotTo(BeNil())
			Expect(rg.Spec.From).To(HaveLen(1))
			Expect(string(rg.Spec.From[0].Namespace)).To(Equal("custom-gateway-ns"))
		})

		It("creates a separate backend Role in the backend namespace", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			roles := findAllObjects[*rbacv1.Role](toCreate)
			gwRole := findObject[*rbacv1.Role](toCreate, gateway.OperatorGatewayRoleName, "custom-gateway-ns")
			bkRole := findObject[*rbacv1.Role](toCreate, gateway.OperatorGatewayRoleName, bkNS)
			Expect(gwRole).NotTo(BeNil())
			Expect(bkRole).NotTo(BeNil())
			Expect(roles).To(HaveLen(2))

			// Gateway Role should only have gateways + httproutes (no backends).
			Expect(gwRole.Rules).To(HaveLen(1))
			Expect(gwRole.Rules[0].Resources).To(ConsistOf("gateways", "httproutes"))

			// Backend Role should have backends + referencegrants.
			Expect(bkRole.Rules).To(HaveLen(2))
			Expect(bkRole.Rules[0].Resources).To(ConsistOf("backends"))
			Expect(bkRole.Rules[1].Resources).To(ConsistOf("referencegrants"))
		})

		It("creates a backend RoleBinding in the backend namespace", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			rb := findObject[*rbacv1.RoleBinding](toCreate, gateway.OperatorGatewayRoleName, bkNS)
			Expect(rb).NotTo(BeNil())
			Expect(rb.Subjects[0].Name).To(Equal(common.OperatorServiceAccount()))
		})
	})

	Context("OpenShift", func() {
		It("includes OpenShift DNS egress rules in NetworkPolicy", func() {
			cfg.OpenShift = true
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
			Expect(len(np.Spec.Egress)).To(BeNumerically(">", 2))
		})
	})

	Context("component interface", func() {
		It("implements ResolveImages without error", func() {
			comp := gateway.Component(cfg)
			Expect(comp.ResolveImages(nil)).To(Succeed())
		})

		It("reports Ready", func() {
			comp := gateway.Component(cfg)
			Expect(comp.Ready()).To(BeTrue())
		})

		It("reports Linux OS type", func() {
			comp := gateway.Component(cfg)
			Expect(string(comp.SupportedOSType())).To(Equal("linux"))
		})
	})

	Context("Gateway listener hostname", func() {
		It("sets the hostname on the listener", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(gw.Spec.Listeners[0].Hostname).To(Equal(ptr.To(gapi.Hostname(hostname))))
		})

		It("sets AllowedRoutes to Same namespace", func() {
			comp := gateway.Component(cfg)
			toCreate, _ := comp.Objects()
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

	Context("same namespace", func() {
		It("returns all objects in objsToDelete and nothing in objsToCreate", func() {
			comp := gateway.DeletionComponent(&gateway.DeletionConfiguration{
				ResourcePrefix:   prefix,
				GatewayNamespace: gwNS,
				BackendNamespace: bkNS,
				TLSSecretName:    tlsSecret,
				Enterprise:       true,
			})
			toCreate, toDelete := comp.Objects()
			Expect(toCreate).To(BeNil())
			Expect(toDelete).NotTo(BeEmpty())
		})

		It("targets the correct resource names", func() {
			comp := gateway.DeletionComponent(&gateway.DeletionConfiguration{
				ResourcePrefix:   prefix,
				GatewayNamespace: gwNS,
				BackendNamespace: bkNS,
				TLSSecretName:    tlsSecret,
				Enterprise:       true,
			})
			_, toDelete := comp.Objects()
			names := objectNames(toDelete)
			Expect(names).To(ContainElements(
				prefix+"-gateway",
				prefix+"-route",
				prefix+"-backend",
				gateway.OperatorGatewayRoleName,
				tlsSecret,
			))
		})

		It("does not include cross-namespace resources", func() {
			comp := gateway.DeletionComponent(&gateway.DeletionConfiguration{
				ResourcePrefix:   prefix,
				GatewayNamespace: gwNS,
				BackendNamespace: bkNS,
				TLSSecretName:    tlsSecret,
				Enterprise:       true,
			})
			_, toDelete := comp.Objects()
			for _, obj := range toDelete {
				if _, ok := obj.(*gapi.ReferenceGrant); ok {
					Fail("ReferenceGrant should not appear when namespaces match")
				}
			}
		})

		It("includes Enterprise resources when Enterprise is true", func() {
			comp := gateway.DeletionComponent(&gateway.DeletionConfiguration{
				ResourcePrefix:   prefix,
				GatewayNamespace: gwNS,
				BackendNamespace: bkNS,
				TLSSecretName:    tlsSecret,
				Enterprise:       true,
			})
			_, toDelete := comp.Objects()
			sa := findObject[*corev1.ServiceAccount](toDelete, "waf-http-filter", gwNS)
			Expect(sa).NotTo(BeNil())
			np := findObject[*v3.NetworkPolicy](toDelete, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
		})

		It("skips Enterprise resources when Enterprise is false", func() {
			comp := gateway.DeletionComponent(&gateway.DeletionConfiguration{
				ResourcePrefix:   prefix,
				GatewayNamespace: gwNS,
				BackendNamespace: bkNS,
				TLSSecretName:    tlsSecret,
				Enterprise:       false,
			})
			_, toDelete := comp.Objects()
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
		const customGWNS = "custom-gateway-ns"

		It("includes ReferenceGrant and backend-namespace Role/RoleBinding", func() {
			comp := gateway.DeletionComponent(&gateway.DeletionConfiguration{
				ResourcePrefix:   prefix,
				GatewayNamespace: customGWNS,
				BackendNamespace: bkNS,
				TLSSecretName:    tlsSecret,
				Enterprise:       false,
			})
			_, toDelete := comp.Objects()
			rg := findObject[*gapi.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)
			Expect(rg).NotTo(BeNil())
			bkRole := findObject[*rbacv1.Role](toDelete, gateway.OperatorGatewayRoleName, bkNS)
			Expect(bkRole).NotTo(BeNil())
			bkRB := findObject[*rbacv1.RoleBinding](toDelete, gateway.OperatorGatewayRoleName, bkNS)
			Expect(bkRB).NotTo(BeNil())
		})
	})

	Context("component interface", func() {
		It("implements ResolveImages without error", func() {
			comp := gateway.DeletionComponent(&gateway.DeletionConfiguration{
				ResourcePrefix:   prefix,
				GatewayNamespace: gwNS,
				BackendNamespace: bkNS,
				TLSSecretName:    tlsSecret,
			})
			Expect(comp.ResolveImages(nil)).To(Succeed())
		})

		It("reports Ready", func() {
			comp := gateway.DeletionComponent(&gateway.DeletionConfiguration{
				ResourcePrefix:   prefix,
				GatewayNamespace: gwNS,
				BackendNamespace: bkNS,
				TLSSecretName:    tlsSecret,
			})
			Expect(comp.Ready()).To(BeTrue())
		})
	})
})

// findObject returns the first object of type T matching name and namespace.
func findObject[T client.Object](objs []client.Object, name, ns string) T {
	for _, obj := range objs {
		if t, ok := obj.(T); ok && obj.GetName() == name && obj.GetNamespace() == ns {
			return t
		}
	}
	var zero T
	return zero
}

// findAllObjects returns all objects of type T.
func findAllObjects[T client.Object](objs []client.Object) []T {
	var result []T
	for _, obj := range objs {
		if t, ok := obj.(T); ok {
			result = append(result, t)
		}
	}
	return result
}

// objectNames returns all object names from a slice.
func objectNames(objs []client.Object) []string {
	names := make([]string, len(objs))
	for i, obj := range objs {
		names[i] = obj.GetName()
	}
	return names
}
