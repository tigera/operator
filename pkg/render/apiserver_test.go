// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/test"
)

var _ = Describe("API server rendering tests (Calico Enterprise)", func() {
	var instance *operatorv1.InstallationSpec
	var managementCluster = &operatorv1.ManagementCluster{Spec: operatorv1.ManagementClusterSpec{Address: "example.com:1234"}}
	var k8sServiceEp k8sapi.ServiceEndpoint
	var replicas int32

	BeforeEach(func() {
		instance = &operatorv1.InstallationSpec{
			ControlPlaneReplicas: &replicas,
			Registry:             "testregistry.com/",
			Variant:              operatorv1.TigeraSecureEnterprise,
		}
		k8sServiceEp = k8sapi.ServiceEndpoint{}
		replicas = 2
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
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		// APIServer(registry string, tlsKeyPair *corev1.Secret, pullSecrets []*corev1.Secret, openshift bool
		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, clusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		// Should render the correct resources.
		// - 1 namespace
		// - 1 ConfigMap audit Policy
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
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ns := rtest.GetResource(resources, "tigera-system", "", "", "v1", "Namespace").(*corev1.Namespace)
		rtest.ExpectResource(ns, "tigera-system", "", "", "v1", "Namespace")
		meta := ns.GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("tigera-system"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))

		expectedDNSNames := dns.GetServiceDNSNames("tigera-api", "tigera-system", clusterDomain)
		operatorCert, ok := rtest.GetResource(resources, "tigera-apiserver-certs", "tigera-operator", "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue(), "Expected v1.Secret")
		test.VerifyCert(operatorCert, "apiserver.key", "apiserver.crt", expectedDNSNames...)

		tigeraCert, ok := rtest.GetResource(resources, "tigera-apiserver-certs", "tigera-system", "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue(), "Expected v1.Secret")
		test.VerifyCert(tigeraCert, "apiserver.key", "apiserver.crt", expectedDNSNames...)

		apiService, ok := rtest.GetResource(resources, "v3.projectcalico.org", "", "apiregistration.k8s.io", "v1", "APIService").(*apiregv1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1.APIService")
		verifyAPIService(apiService, true, clusterDomain)

		d := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(d.Name).To(Equal("tigera-apiserver"))
		Expect(len(d.Labels)).To(Equal(2))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Labels).To(HaveKeyWithValue("k8s-app", "tigera-apiserver"))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(2))
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Name).To(Equal("tigera-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("tigera-system"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(2))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("k8s-app", "tigera-apiserver"))

		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("tigera-apiserver"))

		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateMaster))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(2))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("tigera-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s:%s", components.ComponentAPIServer.Image, components.ComponentAPIServer.Version),
		))

		expectedArgs := []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		}
		Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
		Expect(len(d.Spec.Template.Spec.Containers[0].Env)).To(Equal(1))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom).To(BeNil())

		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/var/log/calico/audit"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-audit-logs"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/etc/tigera/audit"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("tigera-audit-policy"))

		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Path).To(Equal("/version"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("5443"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.InitialDelaySeconds).To(BeEquivalentTo(90))
		Expect(d.Spec.Template.Spec.Containers[0].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(10))

		Expect(*(d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged)).To(BeTrue())

		Expect(d.Spec.Template.Spec.Containers[1].Name).To(Equal("tigera-queryserver"))
		Expect(d.Spec.Template.Spec.Containers[1].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s:%s", components.ComponentQueryServer.Image, components.ComponentQueryServer.Version),
		))
		Expect(d.Spec.Template.Spec.Containers[1].Args).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers[1].Env)).To(Equal(2))

		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Name).To(Equal("LOGLEVEL"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Value).To(Equal("info"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].ValueFrom).To(BeNil())

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(d.Spec.Template.Spec.Containers[1].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(d.Spec.Template.Spec.Containers[1].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts).To(BeEmpty())
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Path).To(Equal("/version"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("8080"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.InitialDelaySeconds).To(BeEquivalentTo(90))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.PeriodSeconds).To(BeEquivalentTo(10))

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Volumes[0].Name).To(Equal("tigera-audit-logs"))
		Expect(d.Spec.Template.Spec.Volumes[0].HostPath.Path).To(Equal("/var/log/calico/audit"))
		Expect(*d.Spec.Template.Spec.Volumes[0].HostPath.Type).To(BeEquivalentTo("DirectoryOrCreate"))
		Expect(d.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-audit-policy"))
		Expect(d.Spec.Template.Spec.Volumes[1].ConfigMap.Name).To(Equal("tigera-audit-policy"))
		Expect(d.Spec.Template.Spec.Volumes[1].ConfigMap.Items[0].Key).To(Equal("config"))
		Expect(d.Spec.Template.Spec.Volumes[1].ConfigMap.Items[0].Path).To(Equal("policy.conf"))
		Expect(len(d.Spec.Template.Spec.Volumes[1].ConfigMap.Items)).To(Equal(1))

		clusterRole := rtest.GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf(networkAdminPolicyRules))

		clusterRole = rtest.GetResource(resources, "tigera-ui-user", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf(uiUserPolicyRules))

		clusterRoleBinding := rtest.GetResource(resources, "tigera-extension-apiserver-auth-access", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef.Name).To(Equal("tigera-extension-apiserver-auth-access"))

	},
		Entry("default cluster domain", dns.DefaultClusterDomain),
		Entry("custom cluster domain", "custom-domain.internal"),
	)

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
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should render the correct resources.
		// Expect same number as above
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		rtest.ExpectResource(dep, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		d := dep.(*appsv1.Deployment)

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(3))
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
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		Expect(len(resources)).To(Equal(len(expectedResources)))

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
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		instance.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		Expect(len(resources)).To(Equal(len(expectedResources)))

		d := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		tol := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
			Effect:   corev1.TaintEffectNoExecute,
		}
		instance.ControlPlaneTolerations = []corev1.Toleration{tol}
		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(tol, rmeta.TolerateMaster))
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
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		Expect(len(resources)).To(Equal(len(expectedResources)))

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
		aci := &operatorv1.AmazonCloudIntegration{
			Spec: operatorv1.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIDs: []string{"sg-nodeid", "sg-masterid"},
				PodSecurityGroupID:   "sg-podsgid",
			},
		}
		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, aci, nil, nil, openshift, nil, dns.DefaultClusterDomain)
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
		k8sServiceEp.Host = "k8shost"
		k8sServiceEp.Port = "1234"

		component, err := render.APIServer(k8sServiceEp, instance, true, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not set KUBERENETES_SERVICE_... variables if not host networked on Docker EE with proxy.local", func() {
		k8sServiceEp.Host = "proxy.local"
		k8sServiceEp.Port = "1234"
		instance.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})

	It("should set KUBERENETES_SERVICE_... variables if not host networked on Docker EE with non-proxy address", func() {
		k8sServiceEp.Host = "k8shost"
		k8sServiceEp.Port = "1234"
		instance.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should render an API server with custom configuration with MCM enabled at startup", func() {
		component, err := render.APIServer(k8sServiceEp, instance, false, managementCluster, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		// Should render the correct resources.
		// - 1 namespace
		// - 1 ConfigMap audit Policy
		// - 1 Service account
		// - 2 ServiceAccount ClusterRole and binding
		// - 2 ClusterRole and binding for auth configmap
		// - 2 tiered policy passthru ClusterRole and binding
		// - 1 delegate auth binding
		// - 1 auth reader binding
		// - 2 webhook reader ClusterRole and binding
		// - 4 cert secrets
		// - 1 api server
		// - 1 service registration
		// - 1 Server service

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: render.VoltronTunnelSecretName, ns: common.OperatorNamespace(), group: "", version: "v1", kind: "Secret"},
			{name: render.VoltronTunnelSecretName, ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		By("Validating the newly created tunnel secret")
		// Use the x509 package to validate that the cert was signed with the privatekey
		operatorTunnelSec := rtest.GetResource(resources, render.VoltronTunnelSecretName, common.OperatorNamespace(), "", "v1", "Secret")
		apiServerTunnelSec := rtest.GetResource(resources, render.VoltronTunnelSecretName, "tigera-system", "", "v1", "Secret")
		validateTunnelSecret(operatorTunnelSec.(*corev1.Secret))
		validateTunnelSecret(apiServerTunnelSec.(*corev1.Secret))

		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		By("Validating startup args")
		expectedArgs := []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-managed-clusters-create-api=true",
			"--managementClusterAddr=example.com:1234",
		}
		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
	})

	It("should render an API server with custom configuration with MCM enabled at restart", func() {
		component, err := render.APIServer(k8sServiceEp, instance, false, managementCluster, nil, nil, nil, nil, openshift, &testutils.VoltronTunnelSecret, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		// Should render the correct resources.
		// - 1 namespace
		// - 1 ConfigMap audit Policy
		// - 1 Service account
		// - 2 ServiceAccount ClusterRole and binding
		// - 2 ClusterRole and binding for auth configmap
		// - 2 tiered policy passthru ClusterRole and binding
		// - 1 delegate auth binding
		// - 1 auth reader binding
		// - 2 webhook reader ClusterRole and binding
		// - 3 cert secrets
		// - 1 api server
		// - 1 service registration
		// - 1 Server service

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-system", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: render.VoltronTunnelSecretName, ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		By("Validating startup args")
		expectedArgs := []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-managed-clusters-create-api=true",
			"--managementClusterAddr=example.com:1234",
		}
		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
	})

	It("should add an init container if certificate management is enabled", func() {
		instance.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c"}
		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
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
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-apiserver-access-calico-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "tigera-apiserver:csr-creator", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))
		dep := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())
		deploy, ok := dep.(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].Name).To(Equal(render.CSRInitContainerName))
		rtest.ExpectEnv(deploy.Spec.Template.Spec.InitContainers[0].Env, "SIGNER", "a.b/c")
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		instance.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		instance.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "tigera-apiserver", "tigera-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-apiserver", "tigera-system")))
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

	cert := voltronSecret.Data["cert"]
	key := voltronSecret.Data["key"]
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
		DNSName: render.VoltronDnsName,
		Roots:   roots,
	}

	_, err = newCert.Verify(opts)
	Expect(err).ShouldNot(HaveOccurred())

	opts = x509.VerifyOptions{
		DNSName:     render.VoltronDnsName,
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
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptureslist"},
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
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			ResourceNames: []string{"default"},
			Verbs:         []string{"get"},
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
			Resources: []string{"authenticationreviews", "authorizationreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "kibana_login",
			},
			Verbs: []string{"get"},
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
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptureslist"},
			Verbs:     []string{"get", "list", "watch"},
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
			Resources: []string{"authenticationreviews", "authorizationreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "elasticsearch_superuser",
			},
			Verbs: []string{"get"},
		},
	}
)

var _ = Describe("API server rendering tests (Calico)", func() {
	var instance *operatorv1.InstallationSpec
	var k8sServiceEp k8sapi.ServiceEndpoint
	var replicas int32

	BeforeEach(func() {
		instance = &operatorv1.InstallationSpec{
			ControlPlaneReplicas: &replicas,
			Registry:             "testregistry.com/",
			Variant:              operatorv1.Calico,
		}
		k8sServiceEp = k8sapi.ServiceEndpoint{}
		replicas = 2
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
			{name: "calico-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "calico-apiserver-certs", ns: "calico-apiserver", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1", kind: "APIService"},
			{name: "calico-apiserver", ns: "calico-apiserver", group: "apps", version: "v1", kind: "Deployment"},
			{name: "calico-api", ns: "calico-apiserver", group: "", version: "v1", kind: "Service"},
			{name: "calico-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "allow-apiserver", ns: "calico-apiserver", group: "networking.k8s.io", version: "v1", kind: "NetworkPolicy"},
		}

		// APIServer(registry string, tlsKeyPair *corev1.Secret, pullSecrets []*corev1.Secret, openshift bool
		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, clusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceInList(resources, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))

		ns := rtest.GetResource(resources, "calico-apiserver", "", "", "v1", "Namespace").(*corev1.Namespace)
		rtest.ExpectResource(ns, "calico-apiserver", "", "", "v1", "Namespace")
		meta := ns.GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("calico-apiserver"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))

		expectedDNSNames := dns.GetServiceDNSNames("calico-api", "calico-apiserver", clusterDomain)
		operatorCert, ok := rtest.GetResource(resources, "calico-apiserver-certs", "tigera-operator", "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue(), "Expected v1.Secret")
		test.VerifyCert(operatorCert, "apiserver.key", "apiserver.crt", expectedDNSNames...)

		tigeraCert, ok := rtest.GetResource(resources, "calico-apiserver-certs", "calico-apiserver", "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue(), "Expected v1.Secret")
		test.VerifyCert(tigeraCert, "apiserver.key", "apiserver.crt", expectedDNSNames...)

		apiService, ok := rtest.GetResource(resources, "v3.projectcalico.org", "", "apiregistration.k8s.io", "v1", "APIService").(*apiregv1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1.APIService")
		verifyAPIService(apiService, false, clusterDomain)

		d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(d.Name).To(Equal("calico-apiserver"))
		Expect(len(d.Labels)).To(Equal(2))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Labels).To(HaveKeyWithValue("k8s-app", "calico-apiserver"))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(2))
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("calico-apiserver"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(2))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("k8s-app", "calico-apiserver"))

		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("calico-apiserver"))

		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateMaster))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(1))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s:%s", components.ComponentCalicoAPIServer.Image, components.ComponentCalicoAPIServer.Version),
		))

		expectedArgs := []string{
			"--secure-port=5443",
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

		Expect(*(d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged)).To(BeTrue())

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
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-certs", Namespace: "tigera-operator"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-certs", Namespace: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{APIVersion: "apiregistration.k8s.io/v1", Kind: "APIService"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-apiserver", Namespace: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}},
		}

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
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
		instance.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		tol := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
			Effect:   corev1.TaintEffectNoExecute,
		}
		instance.ControlPlaneTolerations = []corev1.Toleration{tol}
		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(tol, rmeta.TolerateMaster))
	})

	It("should set KUBERNETES_SERVICE_... variables if host networked", func() {
		k8sServiceEp.Host = "k8shost"
		k8sServiceEp.Port = "1234"
		instance.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(k8sServiceEp, instance, true, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not set KUBERNETES_SERVICE_... variables if Docker EE using proxy.local", func() {
		k8sServiceEp.Host = "proxy.local"
		k8sServiceEp.Port = "1234"
		instance.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})

	It("should not set KUBERNETES_SERVICE_... variables if Docker EE using non-proxy address", func() {
		k8sServiceEp.Host = "k8shost"
		k8sServiceEp.Port = "1234"
		instance.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
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
		instance.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		instance.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(k8sServiceEp, instance, false, nil, nil, nil, nil, nil, openshift, nil, dns.DefaultClusterDomain)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-apiserver", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("calico-apiserver", "calico-apiserver")))
	})
})
