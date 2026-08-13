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

		It("labels the Gateway for label-driven cleanup", func() {
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(gw).NotTo(BeNil())
			Expect(gw.Labels).To(HaveKeyWithValue(gateway.GatewayLabel, prefix))
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

			It("skips SA and RoleBinding but keeps the proxy NetworkPolicy", func() {
				for _, obj := range toCreate {
					if _, ok := obj.(*corev1.ServiceAccount); ok {
						Fail("ServiceAccount should not be rendered when Enterprise is false")
					}
					if rb, ok := obj.(*rbacv1.RoleBinding); ok && rb.Name != prefix+"-ingressgateway-access" {
						Fail("only the gateway access RoleBinding should be rendered when Enterprise is false")
					}
				}
				np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
				Expect(np).NotTo(BeNil())
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

		It("grants itself write access in both namespaces it writes to", func() {
			accessName := prefix + "-ingressgateway-access"
			for _, ns := range []string{"custom-gateway-ns", bkNS} {
				role := findObject[*rbacv1.Role](toCreate, accessName, ns)
				Expect(role).NotTo(BeNil(), "expected a access Role in %s", ns)
				Expect(role.Rules).To(HaveLen(2))
				Expect(role.Rules[0].Resources).To(ConsistOf("gateways", "httproutes", "referencegrants"))
				Expect(role.Rules[0].Verbs).To(ConsistOf("create", "update", "delete"))
				Expect(role.Rules[1].Resources).To(ConsistOf("backends"))
				Expect(findObject[*rbacv1.RoleBinding](toCreate, accessName, ns)).NotTo(BeNil(),
					"expected a access RoleBinding in %s", ns)
			}
			for _, obj := range toCreate {
				if r, ok := obj.(*rbacv1.Role); ok {
					Expect(r.Name).To(Equal(accessName), "the access Role is the only Role this component renders")
				}
			}
		})

		It("leaves SA, RoleBinding, and NetworkPolicy to the GatewayAPI controller even when Enterprise is true", func() {
			for _, obj := range toCreate {
				switch o := obj.(type) {
				case *corev1.ServiceAccount:
					Fail("ServiceAccount should not be rendered for a custom gateway namespace")
				case *rbacv1.RoleBinding:
					Expect(o.Name).To(Equal(prefix+"-ingressgateway-access"),
						"only the gateway access RoleBinding belongs to this component in a custom namespace")
				case *v3.NetworkPolicy:
					Fail("NetworkPolicy should not be rendered for a custom gateway namespace")
				}
			}
		})

		It("grants write access before rendering anything it has to write", func() {
			Expect(toCreate).NotTo(BeEmpty())
			accessName := prefix + "-ingressgateway-access"
			role, ok := toCreate[0].(*rbacv1.Role)
			Expect(ok).To(BeTrue(), "the access Role must come first — nothing else can be created without it")
			Expect(role.Name).To(Equal(accessName))

			gatewayIdx, otherIdx := -1, -1
			for i, obj := range toCreate {
				switch obj.(type) {
				case *gapi.Gateway:
					gatewayIdx = i
				case *gapi.HTTPRoute, *envoyapi.Backend, *corev1.Secret:
					if otherIdx == -1 {
						otherIdx = i
					}
				}
			}
			Expect(gatewayIdx).To(BeNumerically(">=", 0))
			Expect(otherIdx).To(BeNumerically(">", gatewayIdx),
				"the Gateway carries the cleanup label, so it must precede the resources cleanup finds through it")
		})

		It("renders the ReferenceGrant before the HTTPRoute", func() {
			grantIdx, routeIdx := -1, -1
			for i, obj := range toCreate {
				switch obj.(type) {
				case *gapi.ReferenceGrant:
					grantIdx = i
				case *gapi.HTTPRoute:
					routeIdx = i
				}
			}
			Expect(grantIdx).To(BeNumerically(">=", 0))
			Expect(routeIdx).To(BeNumerically(">", grantIdx),
				"the grant must exist before the route so its cross-namespace backendRef resolves on the first pass")
		})

		It("renders the TLS secret after the Gateway", func() {
			gatewayIdx, secretIdx := -1, -1
			for i, obj := range toCreate {
				switch obj.(type) {
				case *gapi.Gateway:
					gatewayIdx = i
				case *corev1.Secret:
					secretIdx = i
				}
			}
			Expect(gatewayIdx).To(BeNumerically(">=", 0))
			Expect(secretIdx).To(BeNumerically(">", gatewayIdx),
				"the Gateway must be created before the TLS secret so the GatewayAPI controller can grant the operator secret access in the custom namespace")
		})
	})

	Context("route request timeout", func() {
		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("omits timeouts by default", func() {
			route := findObject[*gapi.HTTPRoute](toCreate, prefix+"-route", gwNS)
			Expect(route.Spec.Rules[0].Timeouts).To(BeNil())
		})

		Context("when RouteRequestTimeout is set", func() {
			BeforeEach(func() {
				cfg.RouteRequestTimeout = ptr.To("0s")
			})

			It("sets the request timeout on the route", func() {
				route := findObject[*gapi.HTTPRoute](toCreate, prefix+"-route", gwNS)
				Expect(route.Spec.Rules[0].Timeouts).NotTo(BeNil())
				Expect(*route.Spec.Rules[0].Timeouts.Request).To(Equal(gapi.Duration("0s")))
			})
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
		It("returns everything in objsToDelete and nothing in objsToCreate", func() {
			Expect(toCreate).To(BeNil())
			Expect(toDelete).NotTo(BeEmpty())
		})

		It("drops the access grant last, after the resources it permits deleting", func() {
			// RoleBinding then Role, so losing the grant cannot strand an
			// earlier delete.
			last := toDelete[len(toDelete)-1]
			secondLast := toDelete[len(toDelete)-2]
			Expect(last).To(BeAssignableToTypeOf(&rbacv1.Role{}))
			Expect(secondLast).To(BeAssignableToTypeOf(&rbacv1.RoleBinding{}))
			Expect(findObject[*rbacv1.Role](toDelete, prefix+"-ingressgateway-access", gwNS)).NotTo(BeNil())
		})

		It("deletes the Gateway after the resources found through it", func() {
			gatewayIdx, lastResourceIdx := -1, -1
			for i, obj := range toDelete {
				switch obj.(type) {
				case *gapi.Gateway:
					gatewayIdx = i
				case *gapi.HTTPRoute, *envoyapi.Backend, *corev1.Secret, *v3.NetworkPolicy:
					lastResourceIdx = i
				}
			}
			Expect(gatewayIdx).To(BeNumerically(">", lastResourceIdx),
				"an earlier failed delete must leave the labeled Gateway in place so the next reconcile finds the leftovers")
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

		It("skips SA and RoleBinding but keeps the proxy NetworkPolicy", func() {
			for _, obj := range toDelete {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					Fail("ServiceAccount should not appear when Enterprise is false")
				}
				if rb, ok := obj.(*rbacv1.RoleBinding); ok && rb.Name != prefix+"-ingressgateway-access" {
					Fail("only the gateway access RoleBinding should appear when Enterprise is false")
				}
			}
			np := findObject[*v3.NetworkPolicy](toDelete, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
		})
	})

	Context("cross-namespace", func() {
		BeforeEach(func() {
			delCfg.GatewayNamespace = "custom-gateway-ns"
		})

		It("includes ReferenceGrant in the backend namespace", func() {
			rg := findObject[*gapi.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)
			Expect(rg).NotTo(BeNil())
		})

		It("does not delete GatewayAPI-controller-owned resources even when Enterprise is true", func() {
			for _, obj := range toDelete {
				switch o := obj.(type) {
				case *corev1.ServiceAccount:
					Fail("ServiceAccount in a custom namespace belongs to the GatewayAPI controller and must not be deleted here")
				case *rbacv1.RoleBinding:
					Expect(o.Name).To(Equal(prefix+"-ingressgateway-access"),
						"the tigera-operator-secrets RoleBinding belongs to the GatewayAPI controller and must not be deleted here")
				case *v3.NetworkPolicy:
					Fail("NetworkPolicy is not rendered for a custom namespace and must not be deleted here")
				}
			}
		})
	})

	Context("namespace move cleanup", func() {
		BeforeEach(func() {
			delCfg.GatewayNamespace = "old-ns"
			delCfg.MoveTargetNamespace = "new-ns"
		})

		It("deletes the gateway-namespace objects", func() {
			Expect(findObject[*gapi.Gateway](toDelete, prefix+"-gateway", "old-ns")).NotTo(BeNil())
			Expect(findObject[*gapi.HTTPRoute](toDelete, prefix+"-route", "old-ns")).NotTo(BeNil())
			Expect(findObject[*corev1.Secret](toDelete, tlsSecret, "old-ns")).NotTo(BeNil())
		})

		It("never deletes the Backend on a move", func() {
			for _, obj := range toDelete {
				if _, ok := obj.(*envoyapi.Backend); ok {
					Fail("Backend must not be deleted on a namespace move — the new render still routes to it")
				}
			}
		})

		It("keeps the ReferenceGrant when moving between custom namespaces", func() {
			Expect(findObject[*gapi.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)).To(BeNil())
		})

		It("keeps the backend namespace's access grant, and drops the old namespace's", func() {
			accessName := prefix + "-ingressgateway-access"
			Expect(findObject[*rbacv1.Role](toDelete, accessName, "old-ns")).NotTo(BeNil(),
				"the old namespace is no longer written to, so its grant goes")
			Expect(findObject[*rbacv1.Role](toDelete, accessName, bkNS)).To(BeNil(),
				"the backend namespace keeps its resources on a move, so it keeps the grant that writes them")
			Expect(findObject[*rbacv1.RoleBinding](toDelete, accessName, bkNS)).To(BeNil())
		})

		Context("moving into the backend namespace", func() {
			BeforeEach(func() {
				delCfg.MoveTargetNamespace = bkNS
			})

			It("deletes the ReferenceGrant, which is no longer rendered", func() {
				Expect(findObject[*gapi.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)).NotTo(BeNil())
			})

			It("still keeps the backend namespace's access grant", func() {
				// The new render writes the Backend there, so the grant stays
				// even though this pass deletes the ReferenceGrant.
				accessName := prefix + "-ingressgateway-access"
				Expect(findObject[*rbacv1.Role](toDelete, accessName, bkNS)).To(BeNil())
				Expect(findObject[*rbacv1.RoleBinding](toDelete, accessName, bkNS)).To(BeNil())
			})
		})

		Context("moving out of the backend namespace", func() {
			BeforeEach(func() {
				delCfg.GatewayNamespace = bkNS
				delCfg.MoveTargetNamespace = "new-ns"
			})

			It("deletes the Enterprise SA, RoleBinding, and NetworkPolicy from the backend namespace", func() {
				Expect(findObject[*corev1.ServiceAccount](toDelete, "waf-http-filter", bkNS)).NotTo(BeNil())
				np := findObject[*v3.NetworkPolicy](toDelete, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", bkNS)
				Expect(np).NotTo(BeNil())
			})

			It("still keeps the Backend", func() {
				for _, obj := range toDelete {
					if _, ok := obj.(*envoyapi.Backend); ok {
						Fail("Backend must not be deleted on a namespace move")
					}
				}
			})
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
