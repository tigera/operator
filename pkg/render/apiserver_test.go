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
	"crypto/x509"
	"encoding/pem"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

var _ = Describe("API server rendering tests", func() {
	var instance *operator.Installation

	BeforeEach(func() {
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				ClusterManagementType: operator.ClusterManagementTypeManagement,
				Registry:              "testregistry.com/",
			},
		}
	})

	It("should render an API server with default configuration", func() {
		//APIServer(registry string, tlsKeyPair *corev1.Secret, pullSecrets []*corev1.Secret, openshift bool, enableAdmissionControllerSupport bool
		component, err := render.APIServer(instance, nil, nil, openshift, false)
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
		// - 2 cert secrets
		// - 1 api server
		// - 1 service registration
		// - 1 Server service
		Expect(len(resources)).To(Equal(20))
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
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ns := resources[0].(*corev1.Namespace)
		ExpectResource(ns, "tigera-system", "", "", "v1", "Namespace")
		meta := ns.GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("tigera-system"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))

		ExpectResource(resources[13], "tigera-apiserver", "tigera-system", "", "v1", "Deployment")

		operatorCert, ok := resources[11].(*corev1.Secret)
		Expect(ok).To(BeTrue(), "Expected v1.Secret")
		verifyCert(operatorCert)

		tigeraCert, ok := resources[12].(*corev1.Secret)
		Expect(ok).To(BeTrue(), "Expected v1.Secret")
		verifyCert(tigeraCert)

		apiService, ok := resources[14].(*v1beta1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1beta1.APIService")
		verifyAPIService(apiService)

		d := resources[13].(*v1.Deployment)

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

		Expect(len(d.Spec.Template.Spec.NodeSelector)).To(Equal(1))
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("beta.kubernetes.io/os", "linux"))
		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("tigera-apiserver"))

		expectedTolerations := []corev1.Toleration{
			{Key: "node-role.kubernetes.io/master", Effect: "NoSchedule"},
		}
		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(2))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("tigera-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s@%s", components.ComponentAPIServer.Image, components.ComponentAPIServer.Digest),
		))

		expectedArgs := []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-admission-controller-support=false",
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
			fmt.Sprintf("testregistry.com/%s@%s", components.ComponentQueryServer.Image, components.ComponentQueryServer.Digest),
		))
		Expect(d.Spec.Template.Spec.Containers[1].Args).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers[1].Env)).To(Equal(2))

		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Name).To(Equal("LOGLEVEL"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Value).To(Equal("info"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].ValueFrom).To(BeNil())

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
	})

	It("should render an API server with custom configuration", func() {
		component, err := render.APIServer(instance, nil, nil, openshift, false)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		// Should render the correct resources.
		// Expect same number as above
		Expect(len(resources)).To(Equal(20))
		ExpectResource(resources[13], "tigera-apiserver", "tigera-system", "", "v1", "Deployment")

		d := resources[13].(*v1.Deployment)

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(3))
	})

	It("should render needed resources for k8s kube-controller", func() {
		component, err := render.APIServer(instance, nil, nil, openshift, false)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		Expect(len(resources)).To(Equal(20))

		// Should render the correct resources.
		cr := resources[16].(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(1))
		Expect(cr.Rules[0].Resources[0]).To(Equal("tiers"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(1))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))

		crb := resources[17].(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("tigera-tier-getter"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("User"))
		Expect(crb.Subjects[0].Name).To(Equal("system:kube-controller-manager"))
	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		instance.Spec.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(instance, nil, nil, openshift, false)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		Expect(len(resources)).To(Equal(20))
		ExpectResource(resources[13], "tigera-apiserver", "tigera-system", "", "v1", "Deployment")

		d := resources[13].(*v1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should render apiserver RBAC for reading webhooks and enable admission control support parameters when requested", func() {
		component, err := render.APIServer(instance, nil, nil, openshift, true)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		d := resources[13].(*v1.Deployment)

		Expect(d.Name).To(Equal("tigera-apiserver"))

		Expect(len(resources)).To(Equal(22))
		expectedArgs := []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-admission-controller-support=true",
		}
		Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))

		// Should render the correct resources.
		cr := resources[20].(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(2))
		Expect(cr.Rules[0].Resources[0]).To(Equal("mutatingwebhookconfigurations"))
		Expect(cr.Rules[0].Resources[1]).To(Equal("validatingwebhookconfigurations"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(3))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))
		Expect(cr.Rules[0].Verbs[1]).To(Equal("list"))
		Expect(cr.Rules[0].Verbs[2]).To(Equal("watch"))

		crb := resources[21].(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("tigera-webhook-reader"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(crb.Subjects[0].Name).To(Equal("tigera-apiserver"))
		Expect(crb.Subjects[0].Namespace).To(Equal("tigera-system"))
	})
})

func verifyAPIService(service *v1beta1.APIService) {
	Expect(service.Name).To(Equal("v3.projectcalico.org"))
	Expect(service.Spec.Group).To(Equal("projectcalico.org"))
	Expect(service.Spec.Version).To(Equal("v3"))
	Expect(service.Spec.GroupPriorityMinimum).To(BeEquivalentTo(200))
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
