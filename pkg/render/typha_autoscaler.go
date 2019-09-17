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

package render

import (
	"fmt"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	typhaDisruptionBudget = "calico-typha"
	typhaHSServiceAccount = "typha-horizontal-scaler"
	typhaHSRole           = "typha-horizontal-scaler"
	typhaHSClusterRole    = "typha-horizontal-scaler"
	typhaHSDeployment     = "calico-typha-horizontal-scaler"
	typhaHSConfigMap      = "typha-horizontal-scaler"
)

// Typha creates the typha daemonset and other resources for the daemonset to operate normally.
func TyphaAutoscaler(cr *operator.Installation) Component {
	return &typhaAutoscalerComponent{cr: cr}
}

type typhaAutoscalerComponent struct {
	cr *operator.Installation
}

func (c *typhaAutoscalerComponent) Objects() []runtime.Object {
	return []runtime.Object{
		c.podDisruptionBudget(),
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.role(),
		c.roleBinding(),
		c.configMap(),
		c.deployment(),
	}
}

func (c *typhaAutoscalerComponent) Ready() bool {
	return true
}

// podDisruptionBudget creates the disruption budget so typha can be evicted.
func (c *typhaAutoscalerComponent) podDisruptionBudget() *policyv1beta1.PodDisruptionBudget {
	maxUnavailable := intstr.FromInt(1)
	return &policyv1beta1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      typhaDisruptionBudget,
			Namespace: CalicoNamespace,
		},
		Spec: policyv1beta1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					AppLabelName: TyphaK8sAppName,
				},
			},
		},
	}
}

// typhaServiceAccount creates the typha's service account.
func (c *typhaAutoscalerComponent) serviceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      typhaHSServiceAccount,
			Namespace: CalicoNamespace,
		},
	}
}

// clusterRole creates the clusterrole containing policy rules that allow the typha daemonset to operate normally.
func (c *typhaAutoscalerComponent) clusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: typhaHSClusterRole,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// The CNI plugin needs to get pods, nodes, namespaces.
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"list", "watch"},
			},
		},
	}
	return role
}

// clusterRoleBinding creates the binding for the autoscaler ClusterRole
func (c *typhaAutoscalerComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: typhaHSServiceAccount,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     typhaHSClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      typhaHSServiceAccount,
				Namespace: CalicoNamespace,
			},
		},
	}
}

// role creates the role containing policy rules that allow the typha daemonset to operate normally.
func (c *typhaAutoscalerComponent) role() *rbacv1.Role {
	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      typhaHSRole,
			Namespace: CalicoNamespace,
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"apps", "extensions"},
				Resources: []string{"deployments/scale"},
				Verbs:     []string{"get", "update"},
			},
		},
	}
	return role
}

// roleBinding creates a rolebinding for the Role
func (c *typhaAutoscalerComponent) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      typhaHSRole,
			Namespace: CalicoNamespace,
			Labels:    map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     typhaHSRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      typhaHSServiceAccount,
				Namespace: CalicoNamespace,
			},
		},
	}
}

func (c *typhaAutoscalerComponent) configMap() *v1.ConfigMap {
	return &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      typhaHSConfigMap,
			Namespace: CalicoNamespace,
		},
		Data: map[string]string{
			"ladder": `
{
  "coresToReplicas": [],
  "nodesToReplicas":
  [
    [1, 1],
    [2, 2],
    [3, 3],
    [250, 4],
    [500, 5],
    [1000, 6],
    [1500, 7],
    [2000, 8]
  ]
}`,
		},
	}
}

// typhaDeployment creates the typha deployment.
func (c *typhaAutoscalerComponent) deployment() *apps.Deployment {
	d := apps.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      typhaHSDeployment,
			Namespace: CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: typhaHSDeployment,
			},
		},
		Spec: apps.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{AppLabelName: typhaHSDeployment},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						AppLabelName: typhaHSDeployment,
					},
				},
				Spec: v1.PodSpec{
					NodeSelector:       c.nodeSelector(),
					ImagePullSecrets:   c.cr.Spec.ImagePullSecrets,
					ServiceAccountName: typhaHSServiceAccount,
					HostNetwork:        true,
					Containers:         []v1.Container{c.autoscalerContainer()},
				},
			},
		},
	}
	setCriticalPod(&(d.Spec.Template))
	return &d
}

func (c *typhaAutoscalerComponent) nodeSelector() map[string]string {
	return map[string]string{"beta.kubernetes.io/os": "linux"}
}

// autoscalerContainer creates the main autoscaler container.
func (c *typhaAutoscalerComponent) autoscalerContainer() v1.Container {
	// Select which image to use.
	image := constructImage(HorizontalAutoScalerImageName, c.cr.Spec.Registry)
	return v1.Container{
		Name:      "autoscaler",
		Image:     image,
		Resources: c.resources(),
		Command: []string{
			"/cluster-proportional-autoscaler",
			fmt.Sprintf("--namespace=%s", CalicoNamespace),
			fmt.Sprintf("--configmap=%s", typhaHSConfigMap),
			fmt.Sprintf("--target=deployment/%s", TyphaDeploymentName),
			"--logtostderr=true",
			"--v=2",
		},
		//SecurityContext: &v1.SecurityContext{Privileged: &isPrivileged},
	}
}

// typhaResources creates the typha's resource requirements.
func (c *typhaAutoscalerComponent) resources() v1.ResourceRequirements {
	return v1.ResourceRequirements{}
}
