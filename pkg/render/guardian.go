// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

// This renderer is responsible for all resources related to a Guardian Deployment in a
// multicluster setup.
package render

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// The names of the components related to the Guardian related rendered objects.
const (
	GuardianName                   = "tigera-guardian"
	GuardianNamespace              = GuardianName
	GuardianServiceAccountName     = GuardianName
	GuardianClusterRoleName        = GuardianName
	GuardianClusterRoleBindingName = GuardianName
	GuardianDeploymentName         = GuardianName
	GuardianServiceName            = "tigera-guardian"
	GuardianVolumeName             = "tigera-guardian-certs"
	GuardianSecretName             = "tigera-managed-cluster-connection"
)

func Guardian(
	url string,
	pullSecrets []*corev1.Secret,
	openshift bool,
	installation *operatorv1.InstallationSpec,
	tunnelSecret *corev1.Secret,
) Component {
	return &GuardianComponent{
		url:          url,
		pullSecrets:  pullSecrets,
		openshift:    openshift,
		installation: installation,
		tunnelSecret: tunnelSecret,
	}
}

type GuardianComponent struct {
	url          string
	pullSecrets  []*v1.Secret
	openshift    bool
	installation *operatorv1.InstallationSpec
	tunnelSecret *corev1.Secret
}

func (c *GuardianComponent) SupportedOSType() OSType {
	return OSTypeLinux
}

func (c *GuardianComponent) Objects() ([]runtime.Object, []runtime.Object) {
	objs := []runtime.Object{
		createNamespace(GuardianNamespace, c.openshift),
	}
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, GuardianNamespace)...)
	objs = append(objs,
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.deployment(),
		c.service(),
		CopySecrets(GuardianNamespace, c.tunnelSecret)[0],
		// Add tigera-manager service account for impersonation
		createNamespace(ManagerNamespace, c.openshift),
		managerServiceAccount(),
		managerClusterRole(false, true, c.openshift),
		managerClusterRoleBinding(),
	)

	return objs, nil
}

func (c *GuardianComponent) Ready() bool {
	return true
}

func (c *GuardianComponent) service() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianServiceName,
			Namespace: GuardianNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": GuardianName,
			},
			Ports: []corev1.ServicePort{
				{
					Name: "elasticsearch",
					Port: 9200,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
					Protocol: corev1.ProtocolTCP,
				},
				{
					Name: "kibana",
					Port: 5601,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *GuardianComponent) serviceAccount() runtime.Object {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianServiceAccountName, Namespace: GuardianNamespace},
	}
}

func (c *GuardianComponent) clusterRole() runtime.Object {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}
}

func (c *GuardianComponent) clusterRoleBinding() runtime.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     GuardianClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GuardianServiceAccountName,
				Namespace: GuardianNamespace,
			},
		},
	}
}

func (c *GuardianComponent) deployment() runtime.Object {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianDeploymentName,
			Namespace: GuardianNamespace,
			Labels: map[string]string{
				"k8s-app": GuardianName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": GuardianName,
				},
			},
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      GuardianDeploymentName,
					Namespace: ManagerNamespace,
					Labels: map[string]string{
						"k8s-app": GuardianName,
					},
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: GuardianServiceAccountName,
					Tolerations:        c.tolerations(),
					ImagePullSecrets:   getImagePullSecretReferenceList(c.pullSecrets),
					Containers:         c.container(),
					Volumes:            c.volumes(),
				},
			},
		},
	}
}

func (c *GuardianComponent) tolerations() []v1.Toleration {
	return []v1.Toleration{
		{
			Key:    "node-role.kubernetes.io/master",
			Effect: v1.TaintEffectNoSchedule,
		},
		// Allow this pod to be rescheduled while the node is in "critical add-ons only" mode.
		// This, along with the annotation above marks this pod as a critical add-on.
		{
			Key:      "CriticalAddonsOnly",
			Operator: v1.TolerationOpExists,
		},
	}
}

func (c *GuardianComponent) volumes() []v1.Volume {
	return []v1.Volume{
		{
			Name: GuardianVolumeName,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: GuardianSecretName,
				},
			},
		},
	}
}

func (c *GuardianComponent) container() []v1.Container {
	return []corev1.Container{
		{
			Name:  GuardianDeploymentName,
			Image: components.GetReference(components.ComponentGuardian, c.installation.Registry, c.installation.ImagePath),
			Env: []corev1.EnvVar{
				{Name: "GUARDIAN_PORT", Value: "9443"},
				{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
				{Name: "GUARDIAN_VOLTRON_URL", Value: c.url},
			},
			VolumeMounts: []corev1.VolumeMount{{
				Name:      GuardianVolumeName,
				MountPath: "/certs/",
				ReadOnly:  true,
			}},
			LivenessProbe: &corev1.Probe{
				Handler: corev1.Handler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 90,
				PeriodSeconds:       10,
			},
			ReadinessProbe: &corev1.Probe{
				Handler: corev1.Handler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 10,
				PeriodSeconds:       5,
			},
			SecurityContext: securityContext(),
		},
	}
}
