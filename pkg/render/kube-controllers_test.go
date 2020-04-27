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
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/components"
	v1 "k8s.io/api/core/v1"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	apps "k8s.io/api/apps/v1"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var instance *operator.Installation

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.

		miMode := operator.MultiInterfaceModeNone
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools:            []operator.IPPool{{CIDR: "192.168.1.0/16"}},
					MultiInterfaceMode: &miMode,
				},
				Registry: "test-reg/",
			},
		}

	})

	It("should render all resources for a custom configuration", func() {
		component := render.KubeControllers(instance, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(4))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-kube-controllers", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")

		// The Deployment should have the correct configuration.
		ds := resources[3].(*apps.Deployment)

		// Image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("test-reg/%s:%s", components.ComponentCalicoKubeControllers.Image, components.ComponentCalicoKubeControllers.Version),
		))

		// Verify env
		expectedEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "ENABLED_CONTROLLERS", Value: "node"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// Verify tolerations.
		expectedTolerations := []v1.Toleration{
			{Key: "CriticalAddonsOnly", Operator: v1.TolerationOpExists},
			{Key: "node-role.kubernetes.io/master", Effect: v1.TaintEffectNoSchedule},
		}
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise", func() {
		instance.Spec.Variant = operator.TigeraSecureEnterprise

		component := render.KubeControllers(instance, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(4))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-kube-controllers", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")

		// The Deployment should have the correct configuration.
		ds := resources[3].(*apps.Deployment)

		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise and ClusterType is Management", func() {
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		instance.Spec.ClusterManagementType = operator.ClusterManagementTypeManagement

		var managerTLSSecret = v1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ManagerTLSSecretName,
				Namespace: render.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"cert": []byte("cert"),
				"key":  []byte("key"),
			},
		}
		component := render.KubeControllers(instance, &managerTLSSecret)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-kube-controllers", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")
		ExpectResource(resources[4], render.ManagerTLSSecretName, "calico-system", "", "v1", "Secret")

		// The Deployment should have the correct configuration.
		ds := resources[3].(*apps.Deployment)

		Expect(len(ds.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("manager-cert"))
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/manager-tls"))

		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/kube-controllers:" + components.ComponentTigeraKubeControllers.Version))
	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		instance.Spec.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		component := render.KubeControllers(instance, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(4))

		d := resources[3].(*apps.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})
})
