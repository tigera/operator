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
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	tigeraEsConfigMapName       = "tigera-es-config"
	IntrusionDetectionNamespace = "tigera-intrusion-detection"
)

func IntrusionDetection(
	registry string,
	m *operatorv1.MonitoringConfiguration,
	pullSecrets []*corev1.Secret,
	openshift bool,
) Component {
	return &intrusionDetectionComponent{
		registry:    registry,
		monitoring:  m,
		pullSecrets: pullSecrets,
		openshift:   openshift,
	}
}

type intrusionDetectionComponent struct {
	registry    string
	monitoring  *operatorv1.MonitoringConfiguration
	pullSecrets []*corev1.Secret
	openshift   bool
}

func (c *intrusionDetectionComponent) Objects() []runtime.Object {

	objs := []runtime.Object{createNamespace(IntrusionDetectionNamespace, c.openshift)}
	objs = append(objs, c.imagePullSecrets()...)
	return append(objs,
		c.intrusionDetectionServiceAccount(),
		c.intrusionDetectionClusterRole(),
		c.intrusionDetectionClusterRoleBinding(),
		c.intrusionDetectionRole(),
		c.intrusionDetectionRoleBinding(),
		c.intrusionDetectionDeployment(),
		c.intrusionDetectionElasticsearchJob(),
	)
}

func (c *intrusionDetectionComponent) Ready() bool {
	return true
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchJob() *batchv1.Job {
	ps := []corev1.LocalObjectReference{}
	for _, x := range c.pullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-es-job-installer",
			Namespace: IntrusionDetectionNamespace,
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
					ImagePullSecrets: ps,
					Containers:       []v1.Container{c.intrusionDetectionJobContainer()},
				},
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionJobContainer() v1.Container {
	esScheme, esHost, esPort, _ := ParseEndpoint(c.monitoring.Spec.Elasticsearch.Endpoint)
	kScheme, kHost, kPort, _ := ParseEndpoint(c.monitoring.Spec.Kibana.Endpoint)
	return corev1.Container{
		Name:  "elasticsearch-job-installer",
		Image: constructImage(IntrusionDetectionJobInstallerImageName, c.registry),
		Env: []corev1.EnvVar{
			{
				Name:  "ELASTIC_HOST",
				Value: esHost,
			},
			{
				Name:  "ELASTIC_PORT",
				Value: esPort,
			},
			{
				Name:  "ELASTIC_SCHEME",
				Value: esScheme,
			},
			{
				Name:  "KIBANA_HOST",
				Value: kHost,
			},
			{
				Name:  "KIBANA_PORT",
				Value: kPort,
			},
			{
				Name:  "KIBANA_SCHEME",
				Value: kScheme,
			},
			{
				Name:  "START_XPACK_TRIAL",
				Value: "true",
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
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
				Namespace: IntrusionDetectionNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
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
			Namespace: IntrusionDetectionNamespace,
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
				Namespace: IntrusionDetectionNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionDeployment() *appsv1.Deployment {
	var replicas int32 = 1
	ps := []corev1.LocalObjectReference{}
	for _, x := range c.pullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
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
					ImagePullSecrets:   ps,
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
	esScheme, esHost, esPort, _ := ParseEndpoint(c.monitoring.Spec.Elasticsearch.Endpoint)
	return corev1.Container{
		Name:  "controller",
		Image: constructImage(IntrusionDetectionControllerImageName, c.registry),
		Env: []corev1.EnvVar{
			{
				Name:  "CLUSTER_NAME",
				Value: c.monitoring.Spec.ClusterName,
			},
			{
				Name:  "ELASTIC_HOST",
				Value: esHost,
			},
			{
				Name:  "ELASTIC_PORT",
				Value: esPort,
			},
			{
				Name:  "ELASTIC_SCHEME",
				Value: esScheme,
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

func (c *intrusionDetectionComponent) imagePullSecrets() []runtime.Object {
	secrets := []runtime.Object{}
	for _, s := range c.pullSecrets {
		s.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: IntrusionDetectionNamespace}

		secrets = append(secrets, s)
	}
	return secrets
}
