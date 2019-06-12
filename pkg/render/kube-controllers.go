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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	defaultCalicoKubeControllersImageName = "calico/kube-controllers"
	defaultTigeraKubeControllersImageName = "tigera/kube-controllers"
)

var replicas int32 = 1

func KubeControllers(cr *operator.Installation) []runtime.Object {
	return []runtime.Object{
		controllersServiceAccount(cr),
		controllersRole(cr),
		controllersRoleBinding(cr),
		controllersDeployment(cr),
	}
}

func controllersServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: calicoNamespace,
			Labels:    map[string]string{},
		},
	}
}

func controllersRole(cr *operator.Installation) *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-kube-controllers",
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Nodes are watched to monitor for deletions.
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				// Pods are queried to check for existence.
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
			{
				// IPAM resources are manipulated when nodes are deleted.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"ippools"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"blockaffinities", "ipamblocks", "ipamhandles"},
				Verbs:     []string{"get", "list", "create", "update", "delete"},
			},
			{
				// Needs access to update clusterinformations.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "create", "update"},
			},
		},
	}

	if cr.Spec.Variant == operator.TigeraSecureEnterprise {
		extraRules := []rbacv1.PolicyRule{
			{
				// Needs access to update clusterinformations.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "create", "update"},
			},
			{
				// calico-kube-controllers requires tiers create
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"tiers"},
				Verbs:     []string{"create"},
			},
			{
				// Needed to validate the license
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get"},
			},
		}

		role.Rules = append(role.Rules, extraRules...)
	}
	return role
}

func controllersRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-kube-controllers",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-kube-controllers",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-kube-controllers",
				Namespace: calicoNamespace,
			},
		},
	}
}

func controllersDeployment(cr *operator.Installation) *apps.Deployment {
	imageName := defaultCalicoKubeControllersImageName
	if cr.Spec.Variant == operator.TigeraSecureEnterprise {
		imageName = defaultTigeraKubeControllersImageName
	}
	controllersImage := fmt.Sprintf("%s%s:%s", cr.Spec.Registry, imageName, cr.Spec.Version)
	if len(cr.Spec.Components.KubeControllers.ImageOverride) > 0 {
		controllersImage = cr.Spec.Components.KubeControllers.ImageOverride
	}

	tolerations := []v1.Toleration{
		{Key: "CriticalAddonsOnly", Operator: v1.TolerationOpExists},
		{Key: "node-role.kubernetes.io/master", Effect: v1.TaintEffectNoSchedule},
	}
	tolerations = setCustomTolerations(tolerations, cr.Spec.Components.KubeControllers.Tolerations)

	volumeMounts := []v1.VolumeMount{}
	volumeMounts = setCustomVolumeMounts(volumeMounts, cr.Spec.Components.KubeControllers.ExtraVolumeMounts)

	volumes := []v1.Volume{}
	volumes = setCustomVolumes(volumes, cr.Spec.Components.KubeControllers.ExtraVolumes)

	env := []v1.EnvVar{
		{Name: "ENABLED_CONTROLLERS", Value: "node"},
		{Name: "DATASTORE_TYPE", Value: string(cr.Spec.Datastore.Type)},
	}
	env = setCustomEnv(env, cr.Spec.Components.KubeControllers.ExtraEnv)

	resources := v1.ResourceRequirements{
		Requests: v1.ResourceList{},
		Limits:   v1.ResourceList{},
	}
	if len(cr.Spec.Components.KubeControllers.Resources.Limits) > 0 || len(cr.Spec.Components.KubeControllers.Resources.Requests) > 0 {
		resources.Requests = cr.Spec.Components.KubeControllers.Resources.Requests
		resources.Limits = cr.Spec.Components.KubeControllers.Resources.Limits
	}

	return &apps.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: calicoNamespace,
			Labels: map[string]string{
				"k8s-app": "calico-kube-controllers",
			},
			Annotations: map[string]string{
				"scheduler.alpha.kubernetes.io/critical-pod": "",
			},
		},
		Spec: apps.DeploymentSpec{
			Replicas: &replicas,
			Strategy: apps.DeploymentStrategy{
				Type: apps.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "calico-kube-controllers",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-kube-controllers",
					Namespace: calicoNamespace,
					Labels: map[string]string{
						"k8s-app": "calico-kube-controllers",
					},
				},
				Spec: v1.PodSpec{
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					Tolerations:        tolerations,
					ImagePullSecrets:   cr.Spec.ImagePullSecretsRef,
					ServiceAccountName: "calico-kube-controllers",
					Containers: []v1.Container{
						{
							Name:         "calico-kube-controllers",
							Image:        controllersImage,
							Resources:    resources,
							Env:          env,
							VolumeMounts: volumeMounts,
							ReadinessProbe: &v1.Probe{
								Handler: v1.Handler{
									Exec: &v1.ExecAction{
										Command: []string{
											"/usr/bin/check-status",
											"-r",
										},
									},
								},
							},
						},
					},
					Volumes: volumes,
				},
			},
		},
	}
}
