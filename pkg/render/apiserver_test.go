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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("API server rendering tests", func() {
	var instance *operator.Installation
	var client client.Client
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				Variant: operator.TigeraSecureEnterprise,
				IPPools: []operator.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Registry:  "testregistry.com/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
				Components: operator.ComponentsSpec{
					APIServer: operator.APIServerSpec{},
				},
			},
		}
		client = fake.NewFakeClient()
	})

	It("should render an API server with default configuration", func() {
		component := render.APIServer(instance, client)
		resources := component.Objects()

		// Should render the correct resources.
		Expect(len(resources)).To(Equal(13))
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "Deployment"},
			{name: "tigera-audit-policy", ns: "tigera-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-apiserver", ns: "tigera-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-api", ns: "tigera-system", group: "", version: "v1", kind: "Service"},
			{name: "tigera-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-apiserver-access-crds", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-tiered-policy-passthrough", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-apiserver-delegate-auth", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-auth-reader", ns: "kube-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "cnx-apiserver-certs", ns: "tigera-operator", group: "", version: "v1", kind: "Secret"},
			{name: "v3.projectcalico.org", ns: "", group: "apiregistration.k8s.io", version: "v1beta1", kind: "APIService"},
			{name: "cnx-apiserver-certs", ns: "tigera-system", group: "", version: "v1", kind: "Secret"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ExpectResource(resources[0], "tigera-apiserver", "tigera-system", "", "v1", "Deployment")

		d := resources[0].(*v1.Deployment)

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
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal("testregistry.com/cnx-apiserver:v2.4.0"))

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
		Expect(d.Spec.Template.Spec.Containers[1].Image).To(Equal("testregistry.com/cnx-queryserver:v2.4.0"))
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
		// TODO
		instance.Spec.Components.APIServer = operator.APIServerSpec{}

		component := render.APIServer(instance, client)
		resources := component.Objects()

		// Should render the correct resources.
		Expect(len(resources)).To(Equal(13))
		ExpectResource(resources[0], "tigera-apiserver", "tigera-system", "", "v1", "Deployment")

		d := resources[0].(*v1.Deployment)

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(3))
	})
})
