package render

import (
	"fmt"

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
	"k8s.io/api/extensions/v1beta1"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var replicas int32 = 1

func Controllers(cr *operatorv1alpha1.Core) []runtime.Object {
	return []runtime.Object{
		controllersServiceAccount(cr),
		controllersRole(cr),
		controllersRoleBinding(cr),
		controllersDeployment(cr),
	}
}

func controllersServiceAccount(cr *operatorv1alpha1.Core) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: "kube-system",
			Labels:    map[string]string{},
		},
	}
}

func controllersRole(cr *operatorv1alpha1.Core) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
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
}

func controllersRoleBinding(cr *operatorv1alpha1.Core) *rbacv1.ClusterRoleBinding {
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
				Namespace: "kube-system",
			},
		},
	}
}

func controllersDeployment(cr *operatorv1alpha1.Core) *v1beta1.Deployment {
	controllersImage := fmt.Sprintf("%scalico/kube-controllers:%s", cr.Spec.Registry, cr.Spec.Version)

	return &v1beta1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "extensions/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: "kube-system",
			Labels: map[string]string{
				"k8s-app": "calico-kube-controllers",
			},
			Annotations: map[string]string{
				"scheduler.alpha.kubernetes.io/critical-pod": "",
			},
		},
		Spec: v1beta1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: v1beta1.DeploymentStrategy{
				Type: v1beta1.RecreateDeploymentStrategyType,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-kube-controllers",
					Namespace: "kube-system",
					Labels: map[string]string{
						"k8s-app": "calico-kube-controllers",
					},
				},
				Spec: v1.PodSpec{
					NodeSelector: map[string]string{
						"kubernetes.io/os": "linux",
					},
					Tolerations: []v1.Toleration{
						{Key: "CriticalAddonsOnly", Operator: v1.TolerationOpExists},
						{Key: "node-role.kubernetes.io/master", Effect: v1.TaintEffectNoSchedule},
					},
					ServiceAccountName: "calico-kube-controllers",
					Containers: []v1.Container{
						{
							Name:  "calico-kube-controllers",
							Image: controllersImage,
							Env: []v1.EnvVar{
								{Name: "ENABLED_CONTROLLERS", Value: "node"},
								{Name: "DATASTORE_TYPE", Value: "kubernetes"},
							},
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
				},
			},
		},
	}
}
