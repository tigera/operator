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
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	tigeraEsConfigMapName = "tigera-es-config"
)

func IntrusionDetection(cr *operator.Installation) Component {
	if cr.Spec.Variant != operator.TigeraSecureEnterprise {
		return nil
	}

	return &intrusionDetectionComponent{cr: cr}
}

type intrusionDetectionComponent struct {
	cr *operator.Installation
}

func (c *intrusionDetectionComponent) GetObjects() []runtime.Object {
	return []runtime.Object{
		c.intrusionDetectionServiceAccount(),
		c.intrusionDetectionClusterRole(),
		c.intrusionDetectionClusterRoleBinding(),
		c.intrusionDetectionRole(),
		c.intrusionDetectionRoleBinding(),
		c.intrusionDetectionDeployment(),
		c.intrusionDetectionElasticsearchJob(),
	}
}

func (c *intrusionDetectionComponent) GetComponentDeps() []runtime.Object {
	// Intrusion Detection depends on the configmap tigera-es-config to exist but we don't need to explicitly
	// check if the configmap exists. The resources depending on the configmap will be pending.
	return nil
}

func (c *intrusionDetectionComponent) Ready(client client.Client) bool {
	return true
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchJob() *batchv1.Job {
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-es-job-installer",
			Namespace: "calico-monitoring",
		},
		Spec: batchv1.JobSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"job-name": "intrusion-detection-es-job-installer",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"job-name": "intrusion-detection-es-job-installer"},
				},
				Spec: v1.PodSpec{
					RestartPolicy:    v1.RestartPolicyOnFailure,
					ImagePullSecrets: c.cr.Spec.ImagePullSecrets,
					Containers:       []v1.Container{c.intrusionDetectionJobContainer()},
				},
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionJobContainer() v1.Container {
	return corev1.Container{
		Name:  "elasticsearch-job-installer",
		Image: c.cr.Spec.Components.IntrusionDetection.Controller.Image,
		Env: []corev1.EnvVar{
			{
				Name:      "ELASTIC_HOST",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.host"),
			},
			{
				Name:      "ELASTIC_PORT",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.port"),
			},
			{
				Name:      "ELASTIC_SCHEME",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.scheme"),
			},
			{
				Name:      "KIBANA_HOST",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.kibana.host"),
			},
			{
				Name:      "KIBANA_PORT",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.kibana.port"),
			},
			{
				Name:      "ELASTIC_SCHEME",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.kibana.scheme"),
			},
			{
				Name:      "START_XPACK_TRIAL",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.startXPackTrial"),
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: "calico-monitoring",
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "intrusion-detection-controller",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"projectcalico.org",
				},
				Resources: []string{
					"globalthreatfeeds",
					"globalthreatfeeds/status",
					"globalnetworksets",
				},
				Verbs: []string{
					"*",
				},
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "intrusion-detection-controller",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "intrusion-detection-controller",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "intrusion-detection-controller",
				Namespace: "calico-monitoring",
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: "calico-monitoring",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"secrets",
					"configmaps",
				},
				Verbs: []string{
					"get",
				},
			},
		},
	}
}
func (c *intrusionDetectionComponent) intrusionDetectionRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: "calico-monitoring",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "intrusion-detection-controller",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "intrusion-detection-controller",
				Namespace: "calico-monitoring",
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionDeployment() *appsv1.Deployment {
	var replicas int32 = 1

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: "calico-monitoring",
			Labels: map[string]string{
				"k8s-app": "intrusion-detection-controller",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "intrusion-detection-controller"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "intrusion-detection-controller",
					Namespace: "calico-monitoring",
					Labels: map[string]string{
						"k8s-app": "intrusion-detection-controller",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "intrusion-detection-controller",
					ImagePullSecrets:   c.cr.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						c.intrusionDetectionControllerContainer(),
					},
					Volumes: []v1.Volume{
						{
							Name: "es-config",
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{
										Name: tigeraEsConfigMapName,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return d
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerContainer() v1.Container {
	return corev1.Container{
		Name:  "controller",
		Image: c.cr.Spec.Components.IntrusionDetection.Controller.Image,
		Env: []corev1.EnvVar{
			{
				Name:      "CLUSTER_NAME",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.cluster-name"),
			},
			{
				Name:      "ELASTIC_HOST",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.host"),
			},
			{
				Name:      "ELASTIC_PORT",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.port"),
			},
			{
				Name:      "ELASTIC_SCHEME",
				ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.scheme"),
			},
		},
		// Needed for permissions to write to the audit log
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/healthz",
						"liveness",
					},
				},
			},
			InitialDelaySeconds: 5,
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/healthz",
						"readiness",
					},
				},
			},
			InitialDelaySeconds: 5,
		},
	}
}
