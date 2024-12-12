// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package render

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	operatorv1 "github.com/tigera/operator/api/v1"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Gateway API rendering tests", func() {

	It("should read Gateway API resources from YAML", func() {
		resources := GatewayAPIResources()
		Expect(resources.namespace.Name).To(Equal("tigera-gateway-system"))
	})

	It("should apply overrides from GatewayControllerDeployment", func() {
		installation := &operatorv1.InstallationSpec{}
		five := int32(5)
		affinity := &corev1.Affinity{}
		resourceRequirements := &corev1.ResourceRequirements{}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayControllerDeployment: &operatorv1.GatewayControllerDeployment{
					Metadata: &operatorv1.Metadata{
						Labels: map[string]string{
							"x":     "y",
							"white": "black",
						},
						Annotations: map[string]string{
							"up":    "down",
							"round": "flat",
						},
					},
					Spec: &operatorv1.GatewayControllerDeploymentSpec{
						MinReadySeconds: &five,
						Template: &operatorv1.GatewayControllerDeploymentPodTemplate{
							Metadata: &operatorv1.Metadata{
								Labels: map[string]string{
									"rural": "urban",
								},
								Annotations: map[string]string{
									"haste": "speed",
								},
							},
							Spec: &operatorv1.GatewayControllerDeploymentPodSpec{
								Affinity: affinity,
								Containers: []operatorv1.GatewayControllerDeploymentContainer{{
									Name:      "envoy-gateway",
									Resources: resourceRequirements,
								}},
								NodeSelector: map[string]string{
									"fast": "slow",
								},
								Tolerations: []corev1.Toleration{},
							},
						},
					},
				},
			},
		}
		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		objsToCreate, objsToDelete := gatewayComp.Objects()
		Expect(objsToDelete).To(HaveLen(0))
		rtest.ExpectResources(objsToCreate, []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-system"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway-system"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-config", Namespace: "tigera-gateway-system"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-role"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-rolebinding"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "tigera-gateway-system"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-role", Namespace: "tigera-gateway-system"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "tigera-gateway-system"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-rolebinding", Namespace: "tigera-gateway-system"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway-system"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway-system"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway-system"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway-system"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway-system"}},
			&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway-system"}},
			&envoyapi.EnvoyProxy{ObjectMeta: metav1.ObjectMeta{Name: "envoy-proxy-config", Namespace: "tigera-gateway-system"}},
		})
	})
})
