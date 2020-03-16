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
	"github.com/tigera/operator/pkg/components"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	IntrusionDetectionNamespace = "tigera-intrusion-detection"

	ElasticsearchIntrusionDetectionUserSecret    = "tigera-ee-intrusion-detection-elasticsearch-access"
	ElasticsearchIntrusionDetectionJobUserSecret = "tigera-ee-installer-elasticsearch-access"

	IntrusionDetectionInstallerJobName = "intrusion-detection-es-job-installer"
)

func IntrusionDetection(
	esSecrets []*corev1.Secret,
	kibanaCertSecret *corev1.Secret,
	installation *operator.Installation,
	esClusterConfig *ElasticsearchClusterConfig,
	pullSecrets []*corev1.Secret,
	openshift bool,
) Component {
	return &intrusionDetectionComponent{
		esSecrets:        esSecrets,
		kibanaCertSecret: kibanaCertSecret,
		installation:     installation,
		esClusterConfig:  esClusterConfig,
		pullSecrets:      pullSecrets,
		openshift:        openshift,
	}
}

type intrusionDetectionComponent struct {
	esSecrets        []*corev1.Secret
	kibanaCertSecret *corev1.Secret
	installation     *operator.Installation
	esClusterConfig  *ElasticsearchClusterConfig
	pullSecrets      []*corev1.Secret
	openshift        bool
}

func (c *intrusionDetectionComponent) Objects() ([]runtime.Object, []runtime.Object) {
	objs := []runtime.Object{createNamespace(IntrusionDetectionNamespace, c.openshift)}
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, IntrusionDetectionNamespace)...)
	objs = append(objs, secretsToRuntimeObjects(CopySecrets(IntrusionDetectionNamespace, c.esSecrets...)...)...)
	objs = append(objs, secretsToRuntimeObjects(CopySecrets(IntrusionDetectionNamespace, c.kibanaCertSecret)...)...)
	objs = append(objs, c.intrusionDetectionServiceAccount(),
		c.intrusionDetectionClusterRole(),
		c.intrusionDetectionClusterRoleBinding(),
		c.intrusionDetectionRole(),
		c.intrusionDetectionRoleBinding(),
		c.intrusionDetectionDeployment(),
		c.intrusionDetectionElasticsearchJob())

	return objs, nil
}

func (c *intrusionDetectionComponent) Ready() bool {
	return true
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchJob() *batchv1.Job {
	podTemplate := ElasticsearchDecorateAnnotations(&v1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"job-name": IntrusionDetectionInstallerJobName},
		},
		Spec: ElasticsearchPodSpecDecorate(v1.PodSpec{
			RestartPolicy:    v1.RestartPolicyOnFailure,
			ImagePullSecrets: getImagePullSecretReferenceList(c.pullSecrets),
			Containers: []v1.Container{
				ElasticsearchContainerDecorate(c.intrusionDetectionJobContainer(), c.esClusterConfig.ClusterName(), ElasticsearchIntrusionDetectionJobUserSecret),
			},
			Volumes: []corev1.Volume{{
				Name: "kibana-ca-cert-volume",
				VolumeSource: v1.VolumeSource{
					Secret: &v1.SecretVolumeSource{
						SecretName: KibanaPublicCertSecret,
						Items: []v1.KeyToPath{
							{Key: "tls.crt", Path: "ca.pem"},
						},
					},
				},
			}},
		}),
	}, c.esClusterConfig, c.esSecrets).(*v1.PodTemplateSpec)

	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerJobName,
			Namespace: IntrusionDetectionNamespace,
		},
		Spec: batchv1.JobSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"job-name": IntrusionDetectionInstallerJobName,
				},
			},
			Template: *podTemplate,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionJobContainer() v1.Container {
	kScheme, kHost, kPort, _ := ParseEndpoint(KibanaHTTPSEndpoint)
	secretName := ElasticsearchIntrusionDetectionJobUserSecret
	return corev1.Container{
		Name:  "elasticsearch-job-installer",
		Image: components.GetReference(components.ComponentElasticTseeInstaller, c.installation.Spec.Registry, c.installation.Spec.ImagePath),
		Env: []corev1.EnvVar{
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
				// We no longer need to start the xpack trial from the installer pod. Logstorage
				// now takes care of this in combination with the ECK operator (v1).
				Name:  "START_XPACK_TRIAL",
				Value: "false",
			},
			{
				Name:      "USER",
				ValueFrom: envVarSourceFromSecret(secretName, "username", false),
			},
			{
				Name:      "PASSWORD",
				ValueFrom: envVarSourceFromSecret(secretName, "password", false),
			},
			{
				Name:  "KB_CA_CERT",
				Value: KibanaDefaultCertPath,
			},
			{
				Name:  "CLUSTER_NAME",
				Value: c.esClusterConfig.ClusterName(),
			},
		},
		VolumeMounts: []corev1.VolumeMount{{
			Name:      "kibana-ca-cert-volume",
			MountPath: "/etc/ssl/kibana/",
		}},
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
					"globalalerts",
					"globalalerts/status",
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

	return &appsv1.Deployment{
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
			Template: *c.deploymentPodTemplate(),
		},
	}
}

func (c *intrusionDetectionComponent) deploymentPodTemplate() *corev1.PodTemplateSpec {
	ps := []corev1.LocalObjectReference{}
	for _, x := range c.pullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}

	return ElasticsearchDecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
			Labels: map[string]string{
				"k8s-app": "intrusion-detection-controller",
			},
		},
		Spec: ElasticsearchPodSpecDecorate(corev1.PodSpec{
			ServiceAccountName: "intrusion-detection-controller",
			ImagePullSecrets:   ps,
			Containers: []corev1.Container{
				ElasticsearchContainerDecorateIndexCreator(
					ElasticsearchContainerDecorate(c.intrusionDetectionControllerContainer(), c.esClusterConfig.ClusterName(), ElasticsearchIntrusionDetectionUserSecret),
					c.esClusterConfig.Replicas(), c.esClusterConfig.Shards()),
			},
		}),
	}, c.esClusterConfig, c.esSecrets).(*corev1.PodTemplateSpec)
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerContainer() v1.Container {
	return corev1.Container{
		Name:  "controller",
		Image: components.GetReference(components.ComponentIntrusionDetectionController, c.installation.Spec.Registry, c.installation.Spec.ImagePath),
		Env: []corev1.EnvVar{
			{
				Name:  "CLUSTER_NAME",
				Value: c.esClusterConfig.ClusterName(),
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
