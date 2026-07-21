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

package apiserver_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/contexts"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/enterprise"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/extensions/extensionstest"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const apiServerClusterDomain = "cluster.local"

// apiServerControllerContext builds a controller context for the API server controller,
// seeded with a fake client that holds objs. The returned context carries a real
// certificate manager and trusted bundle, so ExtendContext can create the query server
// cert and the bundle the modifiers consume.
func apiServerControllerContext(variant operatorv1.ProductVariant, install *operatorv1.InstallationSpec, objs ...client.Object) contexts.ControllerContext {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	for _, o := range objs {
		Expect(c.Create(context.Background(), o)).NotTo(HaveOccurred())
	}

	if install == nil {
		install = &operatorv1.InstallationSpec{Variant: variant}
	}

	certManager, err := certificatemanager.Create(c, install, apiServerClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	return contexts.ControllerContext{
		RenderContext: render.RenderContext{
			Installation:  install,
			ClusterDomain: apiServerClusterDomain,
			TrustedBundle: certManager.CreateTrustedBundle(),
		},
		Controller:         contexts.APIServerController,
		Ctx:                context.Background(),
		Client:             c,
		CertificateManager: certManager,
	}
}

// apiServerKeyPair issues the API server TLS keypair from the context's certificate
// manager, the way the controller does before rendering.
func apiServerKeyPair(cc contexts.ControllerContext) certificatemanagement.KeyPairInterface {
	dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, cc.ClusterDomain)
	kp, err := cc.CertificateManager.GetOrCreateKeyPair(cc.Client, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
	Expect(err).NotTo(HaveOccurred())
	return kp
}

var _ = Describe("API server enterprise controller extension", func() {
	managementCluster := func() *operatorv1.ManagementCluster {
		return &operatorv1.ManagementCluster{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			Spec: operatorv1.ManagementClusterSpec{
				Address: "example.com:1234",
				TLS:     &operatorv1.TLS{SecretName: render.VoltronTunnelSecretName},
			},
		}
	}

	tunnelSecret := func() *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: render.VoltronTunnelSecretName, Namespace: common.OperatorNamespace()},
			Data:       map[string][]byte{"cert": []byte("a"), "key": []byte("b")},
		}
	}

	managementClusterConnection := func() *operatorv1.ManagementClusterConnection {
		return &operatorv1.ManagementClusterConnection{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
		}
	}

	Describe("Validate", func() {
		It("accepts a cluster with neither a ManagementCluster nor a ManagementClusterConnection", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil)
			Expect(ext.Validate(cc)).NotTo(HaveOccurred())
		})

		It("accepts a management cluster", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil, managementCluster(), tunnelSecret())
			Expect(ext.Validate(cc)).NotTo(HaveOccurred())
		})

		It("accepts a managed cluster", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil, managementClusterConnection())
			Expect(ext.Validate(cc)).NotTo(HaveOccurred())
		})

		It("rejects a cluster that is both a management cluster and a managed cluster", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil, managementCluster(), tunnelSecret(), managementClusterConnection())
			Expect(ext.Validate(cc)).To(HaveOccurred())
		})
	})
})

var _ = Describe("API server enterprise modifier", func() {
	// renderAPIServer builds the base API server objects and applies the enterprise
	// modifier, the way the component handler does. It returns the create and delete
	// lists after the modifier ran.
	renderAPIServer := func(cc contexts.ControllerContext, rc render.RenderContext, kp certificatemanagement.KeyPairInterface) ([]client.Object, []client.Object) {
		cfg := &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              cc.Installation,
			APIServer:                 &operatorv1.APIServerSpec{},
			TLSKeyPair:                kp,
			TrustedBundle:             rc.TrustedBundle,
			KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
		}
		comp, err := render.APIServer(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()

		ec := comp.(render.ExtensionContextProvider).ExtensionContext()
		return extensionstest.ApplyExtensionsWithContext(ext, render.ComponentNameAPIServer, rc, ec, create, del)
	}

	apiServerDeployment := func(objs []client.Object) *appsv1.Deployment {
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, render.APIServerName)
		Expect(ok).To(BeTrue())
		return dp
	}

	container := func(dp *appsv1.Deployment, name string) *corev1.Container {
		for i := range dp.Spec.Template.Spec.Containers {
			if dp.Spec.Template.Spec.Containers[i].Name == name {
				return &dp.Spec.Template.Spec.Containers[i]
			}
		}
		return nil
	}

	It("is a no-op for the Calico variant (no enterprise objects added)", func() {
		cc := apiServerControllerContext(operatorv1.Calico, nil)
		ecc, _, err := ext.ExtendContext(cc)
		rc := ecc.RenderContext
		Expect(err).NotTo(HaveOccurred())

		objs, _ := renderAPIServer(cc, rc, apiServerKeyPair(cc))

		// No enterprise objects. (The Calico variant cleanup is registered on the base
		// render component, not exercised here.)
		_, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
		Expect(ok).To(BeFalse())
		dp := apiServerDeployment(objs)
		Expect(container(dp, string(render.TigeraAPIServerQueryServerContainerName))).To(BeNil())
	})

	It("layers the query server, enterprise RBAC, audit policy, and query server port on", func() {
		cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil)
		ecc, _, err := ext.ExtendContext(cc)
		rc := ecc.RenderContext
		Expect(err).NotTo(HaveOccurred())

		objs, _ := renderAPIServer(cc, rc, apiServerKeyPair(cc))

		// The query server container is layered onto the deployment.
		dp := apiServerDeployment(objs)
		Expect(container(dp, string(render.TigeraAPIServerQueryServerContainerName))).NotTo(BeNil())

		// Enterprise RBAC.
		for _, name := range []string{"calico-apiserver", "tigera-ui-user", "tigera-network-admin", "calico-uisettingsgroup-getter", "calico-uisettings-passthrough"} {
			_, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, name)
			Expect(ok).To(BeTrue(), "expected ClusterRole %q", name)
		}

		// The user and network-admin roles grant access to WAF policy resources.
		uiUser, found := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
		Expect(found).To(BeTrue())
		Expect(uiUser.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"globalwafpolicies",
				"globalwafplugins",
				"globalwafvalidationpolicies",
				"wafpolicies",
				"wafplugins",
				"wafvalidationpolicies",
			},
			Verbs: []string{"get", "watch", "list"},
		}))

		networkAdmin, found := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-network-admin")
		Expect(found).To(BeTrue())
		Expect(networkAdmin.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"globalwafpolicies",
				"globalwafplugins",
				"globalwafvalidationpolicies",
				"wafpolicies",
				"wafplugins",
				"wafvalidationpolicies",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		}))

		// Audit policy configmap.
		_, ok := extensions.FindObject[*corev1.ConfigMap](objs, "calico-audit-policy")
		Expect(ok).To(BeTrue())

		// The query server port is added to the Service.
		svc, ok := extensions.FindObject[*corev1.Service](objs, render.APIServerServiceName)
		Expect(ok).To(BeTrue())
		Expect(svc.Spec.Ports).To(ContainElement(HaveField("Name", render.QueryServerPortName)))
	})

	It("queues the enterprise RBAC for deletion when not a management cluster", func() {
		cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil)
		ecc, _, err := ext.ExtendContext(cc)
		rc := ecc.RenderContext
		Expect(err).NotTo(HaveOccurred())

		_, del := renderAPIServer(cc, rc, apiServerKeyPair(cc))
		_, ok := extensions.FindObject[*rbacv1.ClusterRole](del, render.ManagedClustersWatchClusterRoleName)
		Expect(ok).To(BeTrue())
	})

	Context("management cluster", func() {
		It("adds the tunnel args and the managed-cluster-watch and secrets RBAC", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil,
				&operatorv1.ManagementCluster{
					ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
					Spec: operatorv1.ManagementClusterSpec{
						Address: "example.com:1234",
						TLS:     &operatorv1.TLS{SecretName: render.VoltronTunnelSecretName},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: render.VoltronTunnelSecretName, Namespace: common.OperatorNamespace()},
					Data:       map[string][]byte{"cert": []byte("a"), "key": []byte("b")},
				},
			)
			ecc, _, err := ext.ExtendContext(cc)
			rc := ecc.RenderContext
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderAPIServer(cc, rc, apiServerKeyPair(cc))

			dp := apiServerDeployment(objs)
			apiCtr := container(dp, string(render.APIServerContainerName))
			Expect(apiCtr).NotTo(BeNil())
			Expect(apiCtr.Args).To(ContainElement("--enable-managed-clusters-create-api=true"))
			Expect(apiCtr.Args).To(ContainElement("--managementClusterAddr=example.com:1234"))
			Expect(apiCtr.Args).To(ContainElement("--tunnelSecretName=" + render.VoltronTunnelSecretName))

			_, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, render.ManagedClustersWatchClusterRoleName)
			Expect(ok).To(BeTrue())
			_, ok = extensions.FindObject[*rbacv1.Role](objs, render.APIServerSecretsRBACName)
			Expect(ok).To(BeTrue())
		})
	})

	Context("managed cluster", func() {
		It("adds the external Linseed rolebinding and the query server token volume", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil,
				&operatorv1.ManagementClusterConnection{
					ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
				},
			)
			ecc, _, err := ext.ExtendContext(cc)
			rc := ecc.RenderContext
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderAPIServer(cc, rc, apiServerKeyPair(cc))

			_, ok := extensions.FindObject[*rbacv1.RoleBinding](objs, "tigera-linseed")
			Expect(ok).To(BeTrue())

			dp := apiServerDeployment(objs)
			Expect(dp.Spec.Template.Spec.Volumes).To(ContainElement(HaveField("Name", render.LinseedTokenVolumeName)))
			qs := container(dp, string(render.TigeraAPIServerQueryServerContainerName))
			Expect(qs).NotTo(BeNil())
			Expect(qs.Env).To(ContainElement(HaveField("Name", "LINSEED_TOKEN")))
		})
	})

	Context("multi-tenant management cluster", func() {
		// renderMultiTenantAPIServer mirrors renderAPIServer but sets MultiTenant on the render
		// config, so the modifier takes the multi-tenant RBAC branch.
		renderMultiTenantAPIServer := func(cc contexts.ControllerContext, rc render.RenderContext, kp certificatemanagement.KeyPairInterface) ([]client.Object, []client.Object) {
			cfg := &render.APIServerConfiguration{
				RequiresAggregationServer: true,
				K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
				Installation:              cc.Installation,
				APIServer:                 &operatorv1.APIServerSpec{},
				TLSKeyPair:                kp,
				TrustedBundle:             rc.TrustedBundle,
				KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
				MultiTenant:               true,
			}
			comp, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			create, del := comp.Objects()

			ec := comp.(render.ExtensionContextProvider).ExtensionContext()
			return extensionstest.ApplyExtensionsWithContext(ext, render.ComponentNameAPIServer, rc, ec, create, del)
		}

		tenant := func(namespace string) *operatorv1.Tenant {
			return &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: namespace},
				Spec:       operatorv1.TenantSpec{ID: namespace},
			}
		}

		// multiTenantExt builds an enterprise Set whose computed options report multi-tenant
		// mode. ExtendContext reads the mode off the Set's options (not cc.Options, which it
		// overwrites), so the tenant-namespace lookup only runs when the Set carries it.
		multiTenantExt := func() *extensions.Set {
			s := enterprise.New()
			s.RegisterOptions(func(context.Context, kubernetes.Interface) (any, error) {
				return eoptions.Options{MultiTenant: true}, nil
			})
			Expect(s.ComputeOptions(context.Background(), nil)).NotTo(HaveOccurred())
			return s
		}

		It("grants each tenant's calico-apiserver service account least-privilege Linseed access", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil, tenant("tenant-a"), tenant("tenant-b"))
			ecc, _, err := multiTenantExt().ExtendContext(cc)
			rc := ecc.RenderContext
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderMultiTenantAPIServer(cc, rc, apiServerKeyPair(cc))

			// A dedicated, Linseed-only ClusterRole.
			role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "calico-apiserver-linseed-access")
			Expect(ok).To(BeTrue())
			Expect(role.Rules).To(ConsistOf(rbacv1.PolicyRule{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"policyactivity"},
				Verbs:     []string{"get"},
			}))

			// A single ClusterRoleBinding with one calico-apiserver ServiceAccount subject per tenant
			// namespace. Linseed authorizes with a cluster-scoped SubjectAccessReview, so this must be a
			// ClusterRoleBinding.
			crb, ok := extensions.FindObject[*rbacv1.ClusterRoleBinding](objs, "calico-apiserver-linseed-access")
			Expect(ok).To(BeTrue())
			Expect(crb.RoleRef.Name).To(Equal("calico-apiserver-linseed-access"))
			Expect(crb.Subjects).To(ConsistOf(
				rbacv1.Subject{Kind: "ServiceAccount", Name: render.APIServerServiceAccountName, Namespace: "tenant-a"},
				rbacv1.Subject{Kind: "ServiceAccount", Name: render.APIServerServiceAccountName, Namespace: "tenant-b"},
			))

			// The zero-tenant user/network-admin roles are not installed in multi-tenant mode.
			_, ok = extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
			Expect(ok).To(BeFalse())
		})

		It("queues the Linseed-access RBAC for deletion in zero-tenant mode", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil)
			ecc, _, err := ext.ExtendContext(cc)
			rc := ecc.RenderContext
			Expect(err).NotTo(HaveOccurred())

			_, del := renderAPIServer(cc, rc, apiServerKeyPair(cc))
			_, ok := extensions.FindObject[*rbacv1.ClusterRole](del, "calico-apiserver-linseed-access")
			Expect(ok).To(BeTrue())
			_, ok = extensions.FindObject[*rbacv1.ClusterRoleBinding](del, "calico-apiserver-linseed-access")
			Expect(ok).To(BeTrue())
		})
	})

	Context("v3-CRD mode (no aggregation server)", func() {
		It("renders the deployment skeleton with the query server and pulls it out of the delete list", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil)
			ecc, _, err := ext.ExtendContext(cc)
			rc := ecc.RenderContext
			Expect(err).NotTo(HaveOccurred())

			cfg := &render.APIServerConfiguration{
				RequiresAggregationServer: false,
				K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
				Installation:              cc.Installation,
				APIServer:                 &operatorv1.APIServerSpec{},
				TLSKeyPair:                apiServerKeyPair(cc),
				TrustedBundle:             rc.TrustedBundle,
				KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
			}
			comp, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			create, del := comp.Objects()

			// The base queues the deployment objects for deletion in v3-CRD mode.
			_, ok := extensions.FindObject[*appsv1.Deployment](del, render.APIServerName)
			Expect(ok).To(BeTrue())

			ec := comp.(render.ExtensionContextProvider).ExtensionContext()
			create, del = extensionstest.ApplyExtensionsWithContext(ext, render.ComponentNameAPIServer, rc, ec, create, del)

			// After the modifier, the deployment (with the query server container) is in the
			// create list and out of the delete list.
			dp, ok := extensions.FindObject[*appsv1.Deployment](create, render.APIServerName)
			Expect(ok).To(BeTrue())
			Expect(container(dp, string(render.TigeraAPIServerQueryServerContainerName))).NotTo(BeNil())
			_, ok = extensions.FindObject[*appsv1.Deployment](del, render.APIServerName)
			Expect(ok).To(BeFalse())
		})
	})

	Context("sidecar / L7 injection", func() {
		applicationLayerSidecar := func() *operatorv1.ApplicationLayer {
			enabled := operatorv1.SidecarEnabled
			return &operatorv1.ApplicationLayer{
				ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
				Spec:       operatorv1.ApplicationLayerSpec{SidecarInjection: &enabled},
			}
		}

		It("adds the L7 admission controller container, the sidecar webhook, and the L7 service port", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil, applicationLayerSidecar())
			ecc, _, err := ext.ExtendContext(cc)
			rc := ecc.RenderContext
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderAPIServer(cc, rc, apiServerKeyPair(cc))

			dp := apiServerDeployment(objs)
			Expect(container(dp, string(render.L7AdmissionControllerContainerName))).NotTo(BeNil())

			_, ok := extensions.FindObject[*admregv1.MutatingWebhookConfiguration](objs, common.SidecarMutatingWebhookConfigName)
			Expect(ok).To(BeTrue())

			svc, ok := extensions.FindObject[*corev1.Service](objs, render.APIServerServiceName)
			Expect(ok).To(BeTrue())
			Expect(svc.Spec.Ports).To(ContainElement(HaveField("Name", render.L7AdmissionControllerPortName)))
		})

		It("pulls the sidecar webhook out of the delete list", func() {
			cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil, applicationLayerSidecar())
			ecc, _, err := ext.ExtendContext(cc)
			rc := ecc.RenderContext
			Expect(err).NotTo(HaveOccurred())

			_, del := renderAPIServer(cc, rc, apiServerKeyPair(cc))
			_, ok := extensions.FindObject[*admregv1.MutatingWebhookConfiguration](del, common.SidecarMutatingWebhookConfigName)
			Expect(ok).To(BeFalse())
		})
	})
})

var _ = Describe("API server enterprise policy modifier", func() {
	applyPolicy := func(cc contexts.ControllerContext, rc render.RenderContext) *v3.NetworkPolicy {
		cfg := &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              cc.Installation,
			APIServer:                 &operatorv1.APIServerSpec{},
		}
		comp := render.APIServerPolicy(cfg)
		create, del := comp.Objects()
		ec := comp.(render.ExtensionContextProvider).ExtensionContext()
		objs, _ := extensionstest.ApplyExtensionsWithContext(ext, render.ComponentNameAPIServerPolicy, rc, ec, create, del)
		policy, ok := extensions.FindObject[*v3.NetworkPolicy](objs, render.APIServerPolicyName)
		Expect(ok).To(BeTrue())
		return policy
	}

	It("leaves the egress rules as the base when no OIDC key validator is configured", func() {
		cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil)
		ecc, _, err := ext.ExtendContext(cc)
		rc := ecc.RenderContext
		Expect(err).NotTo(HaveOccurred())

		policy := applyPolicy(cc, rc)
		// The trailing rule remains the Pass rule (no OIDC egress rule inserted).
		n := len(policy.Spec.Egress)
		Expect(n).To(BeNumerically(">", 0))
		Expect(policy.Spec.Egress[n-1].Action).To(Equal(v3.Pass))
	})

	It("adds the L7 admission controller ingress port when sidecar injection is enabled", func() {
		enabled := operatorv1.SidecarEnabled
		cc := apiServerControllerContext(operatorv1.CalicoEnterprise, nil, &operatorv1.ApplicationLayer{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			Spec:       operatorv1.ApplicationLayerSpec{SidecarInjection: &enabled},
		})
		ecc, _, err := ext.ExtendContext(cc)
		rc := ecc.RenderContext
		Expect(err).NotTo(HaveOccurred())

		policy := applyPolicy(cc, rc)
		// Every ingress rule should carry the L7 admission controller port.
		found := false
		for _, rule := range policy.Spec.Ingress {
			for _, p := range rule.Destination.Ports {
				if p.MinPort == uint16(render.L7AdmissionControllerPort) {
					found = true
				}
			}
		}
		Expect(found).To(BeTrue(), "expected the L7 admission controller ingress port")
	})
})

// cleanupAPIServer behaviour for the Calico variant: the base render component carries
// the enterprise cleanup modifier, which queues the enterprise RBAC for deletion.
var _ = Describe("API server Calico-variant cleanup", func() {
	It("queues the enterprise RBAC for deletion", func() {
		cc := apiServerControllerContext(operatorv1.Calico, nil)
		ecc, _, err := ext.ExtendContext(cc)
		rc := ecc.RenderContext
		Expect(err).NotTo(HaveOccurred())

		cfg := &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              cc.Installation,
			APIServer:                 &operatorv1.APIServerSpec{},
			TLSKeyPair:                apiServerKeyPair(cc),
			KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
		}
		comp, err := render.APIServer(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()
		ec := comp.(render.ExtensionContextProvider).ExtensionContext()
		_, del = extensionstest.ApplyExtensionsWithContext(ext, render.ComponentNameAPIServer, rc, ec, create, del)

		_, ok := extensions.FindObject[*rbacv1.ClusterRole](del, "tigera-ui-user")
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*rbacv1.ClusterRole](del, "calico-apiserver")
		Expect(ok).To(BeTrue())
	})
})
