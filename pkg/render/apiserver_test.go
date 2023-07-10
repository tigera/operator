// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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

package render_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	"github.com/openshift/library-go/pkg/crypto"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var _ = Describe("API server rendering tests (Calico Enterprise)", func() {
	apiServerPolicy := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/apiserver.json")
	apiServerPolicyForOCP := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/apiserver_ocp.json")
	var (
		instance           *operatorv1.InstallationSpec
		apiserver          *operatorv1.APIServerSpec
		managementCluster  = &operatorv1.ManagementCluster{Spec: operatorv1.ManagementClusterSpec{Address: "example.com:1234"}}
		replicas           int32
		cfg                *render.APIServerConfiguration
		tunnelKeyPair      certificatemanagement.KeyPairInterface
		trustedBundle      certificatemanagement.TrustedBundle
		dnsNames           []string
		cli                client.Client
		certificateManager certificatemanager.CertificateManager
	)

	BeforeEach(func() {
		instance = &operatorv1.InstallationSpec{
			ControlPlaneReplicas: &replicas,
			Registry:             "testregistry.com/",
			Variant:              operatorv1.TigeraSecureEnterprise,
		}
		apiserver = &operatorv1.APIServerSpec{}
		dnsNames = dns.GetServiceDNSNames(render.ProjectCalicoAPIServerServiceName(instance.Variant), rmeta.APIServerNamespace(instance.Variant), clusterDomain)
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.ProjectCalicoAPIServerTLSSecretName(instance.Variant), common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		tunnelSecret, err := certificatemanagement.CreateSelfSignedSecret(render.VoltronTunnelSecretName, common.OperatorNamespace(), "tigera-voltron", []string{"voltron"})
		Expect(err).NotTo(HaveOccurred())
		tunnelKeyPair = certificatemanagement.NewKeyPair(tunnelSecret, []string{""}, "")
		trustedBundle = certificatemanagement.CreateTrustedBundle()
		replicas = 2

		cfg = &render.APIServerConfiguration{
			K8SServiceEndpoint: k8sapi.ServiceEndpoint{},
			Installation:       instance,
			APIServer:          apiserver,
			Openshift:          openshift,
			TLSKeyPair:         kp,
			TrustedBundle:      trustedBundle,
			UsePSP:             true,
		}
	})

	DescribeTable("should render an API server with default configuration", func(clusterDomain string) {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-ca-bundle", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}
		dnsNames := dns.GetServiceDNSNames(render.ProjectCalicoAPIServerServiceName(instance.Variant), rmeta.APIServerNamespace(instance.Variant), clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.ProjectCalicoAPIServerTLSSecretName(instance.Variant), common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		cfg.TLSKeyPair = kp
		// APIServer(registry string, tlsKeyPair *corev1.Secret, pullSecrets []*corev1.Secret, openshift bool
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		// Should render the correct resources.
		// - 1 namespace
		// - 1 ConfigMap audit Policy
		// - 1 ConfigMap Tigera CA bundle
		// - 1 Service account
		// - 2 ServiceAccount ClusterRole and binding for calico CRDs
		// - 2 ServiceAccount ClusterRole and binding for tigera CRDs
		// - 2 ClusterRole and binding for auth configmap
		// - 2 tiered policy passthru ClusterRole and binding
		// - 1 delegate auth binding
		// - 1 auth reader binding
		// - 2 webhook reader ClusterRole and binding
		// - 2 cert secrets
		// - 1 api server
		// - 1 service registration
		// - 1 Server service
		Expect(resources).To(HaveLen(len(expectedResources)))

		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		ns := rtest.GetResource(resources, "tigera-system", "", "", "v1", "Namespace").(*corev1.Namespace)
		rtest.ExpectResource(ns, "tigera-system", "", "", "v1", "Namespace")
		meta := ns.GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("tigera-system"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))

		apiService, ok := rtest.GetResource(resources, "v3.projectcalico.org", "", "apiregistration.k8s.io", "v1", "APIService").(*apiregv1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1.APIService")
		verifyAPIService(apiService, true, clusterDomain)

		d := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(d.Name).To(Equal("tigera-apiserver"))
		Expect(len(d.Labels)).To(Equal(1))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(2))
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Name).To(Equal("tigera-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("tigera-system"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(1))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("tigera-apiserver"))

		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateControlPlane))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(2))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s:%s", components.ComponentAPIServer.Image, components.ComponentAPIServer.Version),
		))

		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/tigera-apiserver-certs/tls.key",
			"--tls-cert-file=/tigera-apiserver-certs/tls.crt",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		}
		Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
		Expect(len(d.Spec.Template.Spec.Containers[0].Env)).To(Equal(1))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom).To(BeNil())

		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/var/log/calico/audit"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("tigera-audit-logs"))

		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Path).To(Equal("/version"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("5443"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.InitialDelaySeconds).To(BeEquivalentTo(90))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(10))

		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(d.Spec.Template.Spec.Containers[1].Name).To(Equal("tigera-queryserver"))
		Expect(d.Spec.Template.Spec.Containers[1].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s:%s", components.ComponentQueryServer.Image, components.ComponentQueryServer.Version),
		))
		Expect(d.Spec.Template.Spec.Containers[1].Args).To(BeEmpty())

		Expect(d.Spec.Template.Spec.Containers[1].Env).To(HaveLen(7))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Name).To(Equal("LOGLEVEL"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Value).To(Equal("info"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[2].Name).To(Equal("LISTEN_ADDR"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[2].Value).To(Equal(":8080"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[2].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[3].Name).To(Equal("TLS_CERT"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[3].Value).To(Equal("/tigera-apiserver-certs/tls.crt"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[3].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[4].Name).To(Equal("TLS_KEY"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[4].Value).To(Equal("/tigera-apiserver-certs/tls.key"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[4].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[5].Name).To(Equal("FIPS_MODE_ENABLED"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[5].Value).To(Equal("false"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[6].Name).To(Equal("TRUSTED_BUNDLE_PATH"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[6].Value).To(Equal("/etc/pki/tls/certs/tigera-ca-bundle.crt"))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(d.Spec.Template.Spec.Containers[1].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(d.Spec.Template.Spec.Containers[1].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts).To(HaveLen(2))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].Name).To(Equal("tigera-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].MountPath).To(Equal("/tigera-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].ReadOnly).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].SubPath).To(Equal(""))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].MountPropagation).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].SubPathExpr).To(Equal(""))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].Name).To(Equal("tigera-ca-bundle"))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].ReadOnly).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].SubPath).To(Equal(""))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].MountPropagation).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].SubPathExpr).To(Equal(""))

		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Path).To(Equal("/version"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("8080"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.InitialDelaySeconds).To(BeEquivalentTo(90))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(10))

		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.Privileged).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(d.Spec.Template.Spec.Containers[1].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(d.Spec.Template.Spec.Containers[1].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(d.Spec.Template.Spec.Volumes).To(HaveLen(4))
		Expect(d.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal("tigera-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-audit-logs"))
		Expect(d.Spec.Template.Spec.Volumes[1].HostPath.Path).To(Equal("/var/log/calico/audit"))
		Expect(*d.Spec.Template.Spec.Volumes[1].HostPath.Type).To(BeEquivalentTo("DirectoryOrCreate"))
		Expect(d.Spec.Template.Spec.Volumes[2].Name).To(Equal("tigera-audit-policy"))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Name).To(Equal("tigera-audit-policy"))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Items).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Items[0].Key).To(Equal("config"))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Items[0].Path).To(Equal("policy.conf"))
		Expect(d.Spec.Template.Spec.Volumes[3].Name).To(Equal("tigera-ca-bundle"))
		Expect(d.Spec.Template.Spec.Volumes[3].ConfigMap.Name).To(Equal("tigera-ca-bundle"))

		clusterRole := rtest.GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf(networkAdminPolicyRules))

		clusterRole = rtest.GetResource(resources, "tigera-ui-user", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf(uiUserPolicyRules))

		clusterRoleBinding := rtest.GetResource(resources, "tigera-extension-apiserver-auth-access", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef.Name).To(Equal("tigera-extension-apiserver-auth-access"))

		svc := rtest.GetResource(resources, "tigera-api", "tigera-system", "", "v1", "Service").(*corev1.Service)
		Expect(svc.GetObjectMeta().GetLabels()).To(HaveLen(1))
		Expect(svc.GetObjectMeta().GetLabels()).To(HaveKeyWithValue("k8s-app", "tigera-api"))
	},
		Entry("default cluster domain", dns.DefaultClusterDomain),
		Entry("custom cluster domain", "custom-domain.internal"),
	)

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component, err := render.APIServer(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
		}
	})

	It("should render the env variable for queryserver when FIPS is enabled", func() {
		fipsEnabled := operatorv1.FIPSModeEnabled
		cfg.Installation.FIPSMode = &fipsEnabled
		component, err := render.APIServer(cfg)
		Expect(err).NotTo(HaveOccurred())
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Containers[1].Name).To(Equal("tigera-queryserver"))
		Expect(d.Spec.Template.Spec.Containers[1].Env).To(ContainElement(corev1.EnvVar{Name: "FIPS_MODE_ENABLED", Value: "true"}))
	})

	It("should render an API server with custom configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-ca-bundle", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should render the correct resources.
		// Expect same number as above
		Expect(resources).To(HaveLen(len(expectedResources)))

		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		rtest.ExpectResource(dep, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		d := dep.(*appsv1.Deployment)

		Expect(d.Spec.Template.Spec.Volumes).To(HaveLen(4))
	})

	It("should render needed resources for k8s kube-controller", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-ca-bundle", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		Expect(resources).To(HaveLen(len(expectedResources)))

		// Should render the correct resources.
		cr := rtest.GetResource(resources, "tigera-tier-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(1))
		Expect(cr.Rules[0].Resources[0]).To(Equal("tiers"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(1))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))

		crb := rtest.GetResource(resources, "tigera-tier-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("tigera-tier-getter"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("User"))
		Expect(crb.Subjects[0].Name).To(Equal("system:kube-controller-manager"))

		cr = rtest.GetResource(resources, "tigera-uisettingsgroup-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(1))
		Expect(cr.Rules[0].Resources[0]).To(Equal("uisettingsgroups"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(1))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))

		crb = rtest.GetResource(resources, "tigera-uisettingsgroup-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("tigera-uisettingsgroup-getter"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("User"))
		Expect(crb.Subjects[0].Name).To(Equal("system:kube-controller-manager"))
	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-ca-bundle", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		Expect(resources).To(HaveLen(len(expectedResources)))

		d := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		tol := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
			Effect:   corev1.TaintEffectNoExecute,
		}
		cfg.Installation.ControlPlaneTolerations = []corev1.Toleration{tol}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, tol)))
	})

	It("should include a ClusterRole and ClusterRoleBindings for reading webhook configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-ca-bundle", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		Expect(resources).To(HaveLen(len(expectedResources)))

		// Should render the correct resources.
		cr := rtest.GetResource(resources, "tigera-webhook-reader", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(2))
		Expect(cr.Rules[0].Resources[0]).To(Equal("mutatingwebhookconfigurations"))
		Expect(cr.Rules[0].Resources[1]).To(Equal("validatingwebhookconfigurations"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(3))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))
		Expect(cr.Rules[0].Verbs[1]).To(Equal("list"))
		Expect(cr.Rules[0].Verbs[2]).To(Equal("watch"))

		crb := rtest.GetResource(resources, "tigera-apiserver-webhook-reader", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("tigera-webhook-reader"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(crb.Subjects[0].Name).To(Equal("tigera-apiserver"))
		Expect(crb.Subjects[0].Namespace).To(Equal("tigera-system"))
	})

	It("should set TIGERA_*_SECURITY_GROUP variables on queryserver when AmazonCloudIntegration is defined", func() {
		cfg.AmazonCloudIntegration = &operatorv1.AmazonCloudIntegration{
			Spec: operatorv1.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIDs: []string{"sg-nodeid", "sg-masterid"},
				PodSecurityGroupID:   "sg-podsgid",
			},
		}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		d := deploymentResource.(*appsv1.Deployment)

		Expect(d.Spec.Template.Spec.Containers[1].Name).To(Equal("tigera-queryserver"))
		qc := d.Spec.Template.Spec.Containers[1]

		// Assert on expected env vars.
		expectedEnvVars := []corev1.EnvVar{
			{Name: "TIGERA_DEFAULT_SECURITY_GROUPS", Value: "sg-nodeid,sg-masterid"},
			{Name: "TIGERA_POD_SECURITY_GROUP", Value: "sg-podsgid"},
		}
		for _, v := range expectedEnvVars {
			Expect(qc.Env).To(ContainElement(v))
		}
	})

	It("should set KUBERENETES_SERVICE_... variables if host networked", func() {
		cfg.K8SServiceEndpoint.Host = "k8shost"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.ForceHostNetwork = true
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not set KUBERENETES_SERVICE_... variables if not host networked on Docker EE with proxy.local", func() {
		cfg.K8SServiceEndpoint.Host = "proxy.local"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})

	It("should set KUBERENETES_SERVICE_... variables if not host networked on Docker EE with non-proxy address", func() {
		cfg.K8SServiceEndpoint.Host = "k8shost"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should render an API server with custom configuration with MCM enabled at startup", func() {
		cfg.ManagementCluster = managementCluster
		cfg.TunnelCASecret = tunnelKeyPair
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-ca-bundle", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
		Expect(resources).To(HaveLen(len(expectedResources)))

		By("Validating the newly created tunnel secret")
		tunnelSecret, err := certificatemanagement.CreateSelfSignedSecret(render.VoltronTunnelSecretName, common.OperatorNamespace(), "tigera-voltron", []string{"voltron"})
		Expect(err).ToNot(HaveOccurred())
		tunnelKeyPair = certificatemanagement.NewKeyPair(tunnelSecret, []string{""}, "")

		// Use the x509 package to validate that the cert was signed with the privatekey
		validateTunnelSecret(tunnelSecret)

		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		By("Validating startup args")
		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/tigera-apiserver-certs/tls.key",
			"--tls-cert-file=/tigera-apiserver-certs/tls.crt",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-managed-clusters-create-api=true",
			"--set-managed-clusters-ca-cert=/tigera-management-cluster-connection/tls.crt",
			"--set-managed-clusters-ca-key=/tigera-management-cluster-connection/tls.key",
			"--managementClusterAddr=example.com:1234",
		}
		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
	})

	It("should render an API server with custom configuration with MCM enabled at restart", func() {
		cfg.ManagementCluster = managementCluster
		cfg.TunnelCASecret = tunnelKeyPair
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-ca-bundle", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}
		Expect(resources).To(HaveLen(len(expectedResources)))

		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		By("Validating startup args")
		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/tigera-apiserver-certs/tls.key",
			"--tls-cert-file=/tigera-apiserver-certs/tls.crt",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-managed-clusters-create-api=true",
			"--set-managed-clusters-ca-cert=/tigera-management-cluster-connection/tls.crt",
			"--set-managed-clusters-ca-key=/tigera-management-cluster-connection/tls.key",
			"--managementClusterAddr=example.com:1234",
		}
		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
	})

	It("should render an API server with signed ca bundles enabled", func() {
		cfg.ManagementCluster = managementCluster
		cfg.TunnelCASecret = tunnelKeyPair
		cfg.ManagementCluster.Spec.TLS = &operatorv1.TLS{
			SecretName: render.ManagerTLSSecretName,
		}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)

		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ContainElement("--managementClusterCAType=Public"))
	})

	It("should add an init container if certificate management is enabled", func() {
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cfg.TLSKeyPair.GetCertificatePEM()}
		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.ProjectCalicoAPIServerTLSSecretName(instance.Variant), common.OperatorNamespace(), dnsNames)
		cfg.TLSKeyPair = kp
		Expect(err).NotTo(HaveOccurred())
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-ca-bundle", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettings-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-uisettingsgroup-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}

		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
		Expect(resources).To(HaveLen(len(expectedResources)))
		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())
		deploy, ok := dep.(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].Name).To(Equal("calico-apiserver-certs-key-cert-provisioner"))
		rtest.ExpectEnv(deploy.Spec.Template.Spec.InitContainers[0].Env, "SIGNER", "a.b/c")
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		cfg.Installation.ControlPlaneReplicas = &replicas
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		cfg.Installation.ControlPlaneReplicas = &replicas
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-apiserver", "tigera-system")))
	})

	Context("allow-tigera rendering", func() {
		policyName := types.NamespacedName{Name: "allow-tigera.cnx-apiserver-access", Namespace: "tigera-system"}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.Openshift = scenario.Openshift
				if scenario.ManagedCluster {
					cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
				} else {
					cfg.ManagementClusterConnection = nil
				}

				component := render.APIServerPolicy(cfg)
				resources, _ := component.Objects()

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := testutils.SelectPolicyByProvider(scenario, apiServerPolicy, apiServerPolicyForOCP)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}),
		)
	})

	Context("With APIServer Deployment overrides", func() {
		rr1 := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}

		rr2 := corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		It("should handle APIServerDeployment overrides", func() {
			var minReadySeconds int32 = 20

			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.APIServerDeploymentSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Containers: []operatorv1.APIServerDeploymentContainer{
								{
									Name:      "calico-apiserver",
									Resources: &rr1,
								},
								{
									Name:      "tigera-queryserver",
									Resources: &rr2,
								},
							},
							InitContainers: []operatorv1.APIServerDeploymentInitContainer{
								{
									Name:      "calico-apiserver-certs-key-cert-provisioner",
									Resources: &rr2,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
								{
									MaxSkew: 1,
								},
							},
							Affinity:    affinity,
							Tolerations: []corev1.Toleration{toleration},
						},
					},
				},
			}
			// Enable certificate management.
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cfg.TLSKeyPair.GetCertificatePEM()}
			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			// Create and add the TLS keypair so the initContainer is rendered.
			dnsNames := dns.GetServiceDNSNames(render.ProjectCalicoAPIServerServiceName(instance.Variant), rmeta.APIServerNamespace(instance.Variant), clusterDomain)
			kp, err := certificateManager.GetOrCreateKeyPair(cli, render.ProjectCalicoAPIServerTLSSecretName(instance.Variant), common.OperatorNamespace(), dnsNames)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			cfg.TLSKeyPair = kp

			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			resources, _ := component.Objects()

			d, ok := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())

			// API server has apiserver: true label
			Expect(d.Labels).To(HaveLen(2))
			Expect(d.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(1))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-apiserver". But the APIServer
			// deployment object produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(2))
			Expect(d.Spec.Template.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 2 template-level annotations
			// - 1 added by the operator by default
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(2))
			Expect(d.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/tigera-apiserver-certs"))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))
			Expect(d.Spec.Template.Spec.Containers[1].Name).To(Equal("tigera-queryserver"))
			Expect(d.Spec.Template.Spec.Containers[1].Resources).To(Equal(rr2))

			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.InitContainers[0].Name).To(Equal("calico-apiserver-certs-key-cert-provisioner"))
			Expect(d.Spec.Template.Spec.InitContainers[0].Resources).To(Equal(rr2))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.TopologySpreadConstraints).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.TopologySpreadConstraints[0].MaxSkew).To(Equal(int32(1)))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
		})

		It("should override a ControlPlaneNodeSelector when specified", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			// nodeSelectors are merged
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))
		})

		It("should override ControlPlaneTolerations when specified", func() {
			cfg.Installation.ControlPlaneTolerations = rmeta.TolerateControlPlane

			tol := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Tolerations: []corev1.Toleration{tol},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(tol))
		})
	})
})

func verifyAPIService(service *apiregv1.APIService, enterprise bool, clusterDomain string) {
	Expect(service.Name).To(Equal("v3.projectcalico.org"))
	Expect(service.Spec.Group).To(Equal("projectcalico.org"))
	Expect(service.Spec.Version).To(Equal("v3"))
	Expect(service.Spec.GroupPriorityMinimum).To(BeEquivalentTo(1500))
	Expect(service.Spec.VersionPriority).To(BeEquivalentTo(200))
	Expect(service.Spec.InsecureSkipTLSVerify).To(BeFalse())

	ca := service.Spec.CABundle
	var expectedDNSNames []string
	if enterprise {
		expectedDNSNames = []string{
			"tigera-api",
			"tigera-api.tigera-system",
			"tigera-api.tigera-system.svc",
			"tigera-api.tigera-system.svc." + clusterDomain,
		}
	} else {
		expectedDNSNames = []string{
			"calico-api",
			"calico-api.calico-apiserver",
			"calico-api.calico-apiserver.svc",
			"calico-api.calico-apiserver.svc." + clusterDomain,
		}
	}
	test.VerifyCertSANs(ca, expectedDNSNames...)
}

func validateTunnelSecret(voltronSecret *corev1.Secret) {
	var newCert *x509.Certificate

	cert := voltronSecret.Data[corev1.TLSCertKey]
	key := voltronSecret.Data[corev1.TLSPrivateKeyKey]
	_, err := tls.X509KeyPair(cert, key)
	Expect(err).ShouldNot(HaveOccurred())

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(cert))
	Expect(ok).To(BeTrue())

	block, _ := pem.Decode([]byte(cert))
	Expect(err).ShouldNot(HaveOccurred())
	Expect(block).To(Not(BeNil()))

	newCert, err = x509.ParseCertificate(block.Bytes)
	Expect(err).ShouldNot(HaveOccurred())

	opts := x509.VerifyOptions{
		DNSName: "voltron",
		Roots:   roots,
	}

	_, err = newCert.Verify(opts)
	Expect(err).ShouldNot(HaveOccurred())

	opts = x509.VerifyOptions{
		DNSName:     "voltron",
		Roots:       x509.NewCertPool(),
		CurrentTime: time.Now().AddDate(0, 0, crypto.DefaultCACertificateLifetimeInDays+1),
	}
	_, err = newCert.Verify(opts)
	Expect(err).Should(HaveOccurred())
}

var (
	uiUserPolicyRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
				"",
			},
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"namespaces",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"policyrecommendationscopes",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:tigera-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authorizationreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups"},
			Verbs:         []string{"get"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"get", "list", "watch"},
			ResourceNames: []string{"cluster-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"user-settings"},
		},
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "recommendations",
			},
			Verbs: []string{"get"},
		},
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}
	networkAdminPolicyRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
			},
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"packetcaptures",
				"policyrecommendationscopes",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"watch", "list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:tigera-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports/status"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authorizationreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups"},
			Verbs:         []string{"get", "patch", "update"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "elasticsearch_superuser", "recommendations",
			},
			Verbs: []string{"get"},
		},
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers"},
			Verbs:     []string{"get", "update", "patch", "create"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
	}
)

var _ = Describe("API server rendering tests (Calico)", func() {
	var instance *operatorv1.InstallationSpec
	var apiserver *operatorv1.APIServerSpec
	var replicas int32
	var cfg *render.APIServerConfiguration
	var certificateManager certificatemanager.CertificateManager
	var cli client.Client

	BeforeEach(func() {
		instance = &operatorv1.InstallationSpec{
			ControlPlaneReplicas: &replicas,
			Registry:             "testregistry.com/",
			Variant:              operatorv1.Calico,
		}
		apiserver = &operatorv1.APIServerSpec{}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		dnsNames := dns.GetServiceDNSNames(render.ProjectCalicoAPIServerServiceName(instance.Variant), rmeta.APIServerNamespace(instance.Variant), clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.ProjectCalicoAPIServerTLSSecretName(instance.Variant), common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		replicas = 2
		cfg = &render.APIServerConfiguration{
			K8SServiceEndpoint: k8sapi.ServiceEndpoint{},
			Installation:       instance,
			APIServer:          apiserver,
			Openshift:          openshift,
			TLSKeyPair:         kp,
			UsePSP:             true,
		}
	})

	DescribeTable("should render an API server with default configuration", func(clusterDomain string) {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-apiserver", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-apiserver", ns: "calico-apiserver", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "calico-apiserver", ns: "calico-apiserver", group: "apps", version: "v1", kind: "Deployment"},
			{name: "calico-api", ns: "calico-apiserver", group: "", version: "v1", kind: "Service"},
			{name: "calico-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "allow-apiserver", ns: "calico-apiserver", group: "networking.k8s.io", version: "v1", kind: "NetworkPolicy"},
		}
		dnsNames := dns.GetServiceDNSNames(render.ProjectCalicoAPIServerServiceName(instance.Variant), rmeta.APIServerNamespace(instance.Variant), clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.ProjectCalicoAPIServerTLSSecretName(instance.Variant), common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		cfg.TLSKeyPair = kp
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))

		ns := rtest.GetResource(resources, "calico-apiserver", "", "", "v1", "Namespace").(*corev1.Namespace)
		rtest.ExpectResource(ns, "calico-apiserver", "", "", "v1", "Namespace")
		meta := ns.GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("calico-apiserver"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))

		apiService, ok := rtest.GetResource(resources, "v3.projectcalico.org", "", "apiregistration.k8s.io", "v1", "APIService").(*apiregv1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1.APIService")
		verifyAPIService(apiService, false, clusterDomain)

		d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(d.Name).To(Equal("calico-apiserver"))
		Expect(len(d.Labels)).To(Equal(1))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(2))
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("calico-apiserver"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(1))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("calico-apiserver"))

		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateControlPlane))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(1))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s:%s", components.ComponentCalicoAPIServer.Image, components.ComponentCalicoAPIServer.Version),
		))

		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/calico-apiserver-certs/tls.key",
			"--tls-cert-file=/calico-apiserver-certs/tls.crt",
		}
		Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
		Expect(len(d.Spec.Template.Spec.Containers[0].Env)).To(Equal(1))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom).To(BeNil())

		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))

		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Path).To(Equal("/version"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("5443"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.InitialDelaySeconds).To(BeEquivalentTo(90))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(10))

		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(1))

		clusterRole := rtest.GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		Expect(clusterRole).To(BeNil())

		clusterRole = rtest.GetResource(resources, "tigera-ui-user", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		Expect(clusterRole).To(BeNil())

		clusterRoleBinding := rtest.GetResource(resources, "calico-extension-apiserver-auth-access", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef.Name).To(Equal("calico-extension-apiserver-auth-access"))
	},
		Entry("default cluster domain", dns.DefaultClusterDomain),
		Entry("custom cluster domain", "custom-domain.internal"),
	)

	It("should render an API server with custom configuration", func() {
		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{APIVersion: "apiregistration.k8s.io/v1", Kind: "APIService"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "policy/v1beta1", Kind: "PodSecurityPolicy"}},
			&netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-apiserver", Namespace: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should render the correct resources.
		By("Checking each expected resource is actually rendered")
		for _, e := range expectedResources {
			gvk := e.GetObjectKind().GroupVersionKind()
			rtest.ExpectResourceInList(resources, e.GetName(), e.GetNamespace(), gvk.Group, gvk.Version, gvk.Kind)
		}

		By("Checking each rendered resource is actually expected")
		for _, r := range resources {
			gvk := r.GetObjectKind().GroupVersionKind()
			rtest.ExpectResourceInList(expectedResources, r.GetName(), r.GetNamespace(), gvk.Group, gvk.Version, gvk.Kind)
		}

		// Expect same number as above
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment")
		rtest.ExpectResource(dep, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment")
		d := dep.(*appsv1.Deployment)
		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(1))
	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		tol := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
			Effect:   corev1.TaintEffectNoExecute,
		}
		cfg.Installation.ControlPlaneTolerations = []corev1.Toleration{tol}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, tol)))
	})

	It("should set KUBERNETES_SERVICE_... variables if host networked", func() {
		cfg.K8SServiceEndpoint.Host = "k8shost"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE
		cfg.ForceHostNetwork = true

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not set KUBERNETES_SERVICE_... variables if Docker EE using proxy.local", func() {
		cfg.K8SServiceEndpoint.Host = "proxy.local"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})

	It("should not set KUBERNETES_SERVICE_... variables if Docker EE using non-proxy address", func() {
		cfg.K8SServiceEndpoint.Host = "k8shost"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		cfg.Installation.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		cfg.Installation.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("calico-apiserver", "calico-apiserver")))
	})

	Context("With APIServer Deployment overrides", func() {
		rr1 := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}

		rr2 := corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		It("should handle APIServerDeployment overrides", func() {
			var minReadySeconds int32 = 20

			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.APIServerDeploymentSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Containers: []operatorv1.APIServerDeploymentContainer{
								{
									Name:      "calico-apiserver",
									Resources: &rr1,
								},
							},
							InitContainers: []operatorv1.APIServerDeploymentInitContainer{
								{
									Name:      "calico-apiserver-certs-key-cert-provisioner",
									Resources: &rr2,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							Affinity:    affinity,
							Tolerations: []corev1.Toleration{toleration},
						},
					},
				},
			}
			// Enable certificate management.
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cfg.TLSKeyPair.GetCertificatePEM()}
			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace())
			Expect(err).NotTo(HaveOccurred())

			// Create and add the TLS keypair so the initContainer is rendered.
			dnsNames := dns.GetServiceDNSNames(render.ProjectCalicoAPIServerServiceName(instance.Variant), rmeta.APIServerNamespace(instance.Variant), clusterDomain)
			kp, err := certificateManager.GetOrCreateKeyPair(cli, render.ProjectCalicoAPIServerTLSSecretName(instance.Variant), common.OperatorNamespace(), dnsNames)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			cfg.TLSKeyPair = kp

			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			resources, _ := component.Objects()

			d, ok := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())

			// API server has apiserver: true label
			Expect(d.Labels).To(HaveLen(2))
			Expect(d.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(1))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-apiserver". But the APIServer
			// deployment object produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(2))
			Expect(d.Spec.Template.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 2 template-level annotations
			// - 1 added by the operator by default
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(2))
			Expect(d.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/calico-apiserver-certs"))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))

			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.InitContainers[0].Name).To(Equal("calico-apiserver-certs-key-cert-provisioner"))
			Expect(d.Spec.Template.Spec.InitContainers[0].Resources).To(Equal(rr2))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
		})

		It("should override a ControlPlaneNodeSelector when specified", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
			// nodeSelectors are merged
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))
		})

		It("should override ControlPlaneTolerations when specified", func() {
			cfg.Installation.ControlPlaneTolerations = rmeta.TolerateControlPlane

			tol := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Tolerations: []corev1.Toleration{tol},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(tol))
		})
		It("should render the correct env and/or images when FIPS mode is enabled (OSS)", func() {
			fipsEnabled := operatorv1.FIPSModeEnabled
			cfg.Installation.FIPSMode = &fipsEnabled

			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())

			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Containers[0].Image).To(ContainSubstring("-fips"))
		})

	})
})
