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
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	"github.com/openshift/library-go/pkg/crypto"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

var _ = Describe("API server rendering tests", func() {
	var instance *operator.InstallationSpec
	var managementCluster = &operator.ManagementCluster{Spec: operator.ManagementClusterSpec{Address: "example.com:1234"}}
	BeforeEach(func() {
		instance = &operator.InstallationSpec{
			Registry: "testregistry.com/",
		}
	})

	It("should render an API server with default configuration", func() {
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
			{name: "tigera-apiserver-access-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "Deployment"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1beta1", kind: "APIService"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		//APIServer(registry string, tlsKeyPair *corev1.Secret, pullSecrets []*corev1.Secret, openshift bool
		component, err := render.APIServer(instance, nil, nil, nil, nil, nil, openshift, nil)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)

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
		// - 2 cert secrets
		// - 1 api server
		// - 1 service registration
		// - 1 Server service
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ns := GetResource(resources, "tigera-system", "", "", "v1", "Namespace").(*corev1.Namespace)
		ExpectResource(ns, "tigera-system", "", "", "v1", "Namespace")
		meta := ns.GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("tigera-system"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))

		operatorCert, ok := GetResource(resources, "tigera-apiserver-certs", "tigera-operator", "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue(), "Expected v1.Secret")
		verifyCert(operatorCert)

		tigeraCert, ok := GetResource(resources, "tigera-apiserver-certs", "tigera-system", "", "v1", "Secret").(*corev1.Secret)
		Expect(ok).To(BeTrue(), "Expected v1.Secret")
		verifyCert(tigeraCert)

		apiService, ok := GetResource(resources, "v3.projectcalico.org", "", "apiregistration.k8s.io", "v1beta1", "APIService").(*v1beta1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1beta1.APIService")
		verifyAPIService(apiService)

		d := GetResource(resources, "tigera-apiserver", "tigera-system", "", "v1", "Deployment").(*v1.Deployment)

		Expect(d.Name).To(Equal("tigera-apiserver"))
		Expect(len(d.Labels)).To(Equal(2))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Labels).To(HaveKeyWithValue("k8s-app", "tigera-apiserver"))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(1))
		Expect(d.Spec.Strategy.Type).To(Equal(v1.RecreateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Name).To(Equal("tigera-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("tigera-system"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(2))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("k8s-app", "tigera-apiserver"))

		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("tigera-apiserver"))

		expectedTolerations := []corev1.Toleration{
			{Key: "node-role.kubernetes.io/master", Effect: "NoSchedule"},
		}
		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))

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

		clusterRole := GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf(networkAdminPolicyRules))

		clusterRole = GetResource(resources, "tigera-ui-user", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf(uiUserPolicyRules))

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
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "Deployment"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1beta1", kind: "APIService"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component, err := render.APIServer(instance, nil, nil, nil, nil, nil, openshift, nil)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		// Should render the correct resources.
		// Expect same number as above
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dep := GetResource(resources, "tigera-apiserver", "tigera-system", "", "v1", "Deployment")
		ExpectResource(dep, "tigera-apiserver", "tigera-system", "", "v1", "Deployment")
		d := dep.(*v1.Deployment)

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
			{name: "tigera-apiserver-access-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "Deployment"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1beta1", kind: "APIService"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component, err := render.APIServer(instance, nil, nil, nil, nil, nil, openshift, nil)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		cr := GetResource(resources, "tigera-tier-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(1))
		Expect(cr.Rules[0].Resources[0]).To(Equal("tiers"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(1))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))

		crb := GetResource(resources, "tigera-tier-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
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
			{name: "tigera-apiserver-access-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "Deployment"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1beta1", kind: "APIService"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		instance.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(instance, nil, nil, nil, nil, nil, openshift, nil)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		Expect(len(resources)).To(Equal(len(expectedResources)))

		d := GetResource(resources, "tigera-apiserver", "tigera-system", "", "v1", "Deployment").(*v1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
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
			{name: "tigera-apiserver-access-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "Deployment"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1beta1", kind: "APIService"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tier-getter", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-ui-user", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-network-admin", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-webhook-reader", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component, err := render.APIServer(instance, nil, nil, nil, nil, nil, openshift, nil)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		cr := GetResource(resources, "tigera-webhook-reader", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(2))
		Expect(cr.Rules[0].Resources[0]).To(Equal("mutatingwebhookconfigurations"))
		Expect(cr.Rules[0].Resources[1]).To(Equal("validatingwebhookconfigurations"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(3))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))
		Expect(cr.Rules[0].Verbs[1]).To(Equal("list"))
		Expect(cr.Rules[0].Verbs[2]).To(Equal("watch"))

		crb := GetResource(resources, "tigera-apiserver-webhook-reader", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("tigera-webhook-reader"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(crb.Subjects[0].Name).To(Equal("tigera-apiserver"))
		Expect(crb.Subjects[0].Namespace).To(Equal("tigera-system"))
	})

	It("should set TIGERA_*_SECURITY_GROUP variables on queryserver when AmazonCloudIntegration is defined", func() {
		aci := &operator.AmazonCloudIntegration{
			Spec: operator.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIDs: []string{"sg-nodeid", "sg-masterid"},
				PodSecurityGroupID:   "sg-podsgid",
			},
		}
		component, err := render.APIServer(instance, nil, nil, aci, nil, nil, openshift, nil)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploymentResource := GetResource(resources, "tigera-apiserver", "tigera-system", "", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		d := deploymentResource.(*v1.Deployment)

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

	It("should render an API server with custom configuration with MCM enabled at startup", func() {
		component, err := render.APIServer(instance, managementCluster, nil, nil, nil, nil, openshift, nil)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)

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
			{name: "tigera-apiserver-access-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: render.VoltronTunnelSecretName, ns: render.OperatorNamespace(), group: "", version: "v1", kind: "Secret"},
			{name: render.VoltronTunnelSecretName, ns: render.APIServerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "Deployment"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1beta1", kind: "APIService"},
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
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		By("Validating the newly created tunnel secret")
		// Use the x509 package to validate that the cert was signed with the privatekey
		operatorTunnelSec := GetResource(resources, render.VoltronTunnelSecretName, render.OperatorNamespace(), "", "v1", "Secret")
		apiServerTunnelSec := GetResource(resources, render.VoltronTunnelSecretName, render.APIServerNamespace, "", "v1", "Secret")
		validateTunnelSecret(operatorTunnelSec.(*corev1.Secret))
		validateTunnelSecret(apiServerTunnelSec.(*corev1.Secret))

		dep := GetResource(resources, "tigera-apiserver", render.APIServerNamespace, "", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		By("Validating startup args")
		expectedArgs := []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-managed-clusters-create-api=true",
			"--managementClusterAddr=example.com:1234",
		}
		Expect((dep.(*v1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
	})

	It("should render an API server with custom configuration with MCM enabled at restart", func() {
		component, err := render.APIServer(instance, managementCluster, nil, nil, nil, nil, openshift, &voltronTunnelSecret)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)

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
			{name: "tigera-apiserver-access-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-extension-apiserver-auth-access", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "tigera-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
			{name: render.VoltronTunnelSecretName, ns: render.APIServerNamespace, group: "", version: "v1", kind: "Secret"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "Deployment"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1beta1", kind: "APIService"},
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
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		dep := GetResource(resources, "tigera-apiserver", render.APIServerNamespace, "", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		By("Validating startup args")
		expectedArgs := []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-managed-clusters-create-api=true",
			"--managementClusterAddr=example.com:1234",
		}
		Expect((dep.(*v1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
	})
})

func verifyAPIService(service *v1beta1.APIService) {
	Expect(service.Name).To(Equal("v3.projectcalico.org"))
	Expect(service.Spec.Group).To(Equal("projectcalico.org"))
	Expect(service.Spec.Version).To(Equal("v3"))
	Expect(service.Spec.GroupPriorityMinimum).To(BeEquivalentTo(1500))
	Expect(service.Spec.VersionPriority).To(BeEquivalentTo(200))
	Expect(service.Spec.InsecureSkipTLSVerify).To(BeFalse())

	ca := service.Spec.CABundle
	verifyCertSANs(ca)
}

func verifyCert(secret *corev1.Secret) {
	Expect(secret.Data).To(HaveKey("apiserver.crt"))
	Expect(secret.Data).To(HaveKey("apiserver.key"))

	verifyCertSANs(secret.Data["apiserver.crt"])
}

func verifyCertSANs(certBytes []byte) {
	pemBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	Expect(err).To(BeNil(), "Error parsing bytes from secret into certificate")
	Expect(cert.DNSNames).To(ConsistOf([]string{"tigera-api.tigera-system.svc"}), "Expect cert SAN's to match extension API server service DNS name")
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
				"flows", "audit*", "events", "dns", "kibana_login",
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
				"flows", "audit*", "events", "dns", "elasticsearch_superuser",
			},
			Verbs: []string{"get"},
		},
	}
)
