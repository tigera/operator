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
	ocsv1 "github.com/openshift/api/security/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func Compliance(cr *operator.Installation) Component {
	return &component{
		objs: []runtime.Object{
			complianceControllerServiceAccount(cr),
			complianceControllerRole(cr),
			complianceControllerClusterRole(cr),
			complianceControllerRoleBinding(cr),
			complianceControllerClusterRoleBinding(cr),
			complianceControllerDeployment(cr),

			complianceReporterServiceAccount(cr),
			complianceReporterClusterRole(cr),
			complianceReporterClusterRoleBinding(cr),
			complianceReporterPodTemplate(cr),

			complianceServerServiceAccount(cr),
			complianceServerClusterRole(cr),
			complianceServerClusterRoleBinding(cr),
			complianceServerService(cr),
			complianceServerDeployment(cr),

			complianceSnapshotterServiceAccount(cr),
			complianceSnapshotterClusterRole(cr),
			complianceSnapshotterClusterRoleBinding(cr),
			complianceSnapshotterDeployment(cr),

			complianceBenchmarkerServiceAccount(cr),
			complianceBenchmarkerClusterRole(cr),
			complianceBenchmarkerClusterRoleBinding(cr),
			complianceBenchmarkerDaemonSet(cr),
			complianceBenchmarkerSecurityContextConstraints(cr),

			complianceGlobalReportInventory(cr),
			complianceGlobalReportNetworkAccess(cr),
			complianceGlobalReportPolicyAudit(cr),
			complianceGlobalReportCISBenchmark(cr),
		},
		deps: []runtime.Object{},
	}
}

var complianceBoolTrue = true

var complianceElasticEnvVars = []corev1.EnvVar{
	{Name: "ELASTIC_INDEX_SUFFIX", ValueFrom: &v1.EnvVarSource{
		ConfigMapKeyRef: &v1.ConfigMapKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: "tigera-es-config",
			},
			Key:      "tigera.elasticsearch.cluster-name",
			Optional: &complianceBoolTrue},
	}},
	{Name: "ELASTIC_SCHEME", ValueFrom: &v1.EnvVarSource{
		ConfigMapKeyRef: &v1.ConfigMapKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: "tigera-es-config",
			},
			Key:      "tigera.elasticsearch.scheme",
			Optional: &complianceBoolTrue},
	}},
	{Name: "ELASTIC_HOST", ValueFrom: &v1.EnvVarSource{
		ConfigMapKeyRef: &v1.ConfigMapKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: "tigera-es-config",
			},
			Key:      "tigera.elasticsearch.host",
			Optional: &complianceBoolTrue},
	}},
	{Name: "ELASTIC_PORT", ValueFrom: &v1.EnvVarSource{
		ConfigMapKeyRef: &v1.ConfigMapKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: "tigera-es-config",
			},
			Key:      "tigera.elasticsearch.port",
			Optional: &complianceBoolTrue},
	}},
	{Name: "ELASTIC_SSL_VERIFY", Value: "true"},
	{Name: "ELASTIC_CA", ValueFrom: &v1.EnvVarSource{
		ConfigMapKeyRef: &v1.ConfigMapKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: "tigera-es-config",
			},
			Key:      "tigera.elasticsearch.ca.path",
			Optional: &complianceBoolTrue},
	}},
}

var complianceVolumeMounts = []corev1.VolumeMount{
	{
		Name:      "elastic-ca-cert-volume",
		MountPath: "/etc/ssl/elastic/",
	},
}

var complianceLivenessProbe = &corev1.Probe{
	Handler: corev1.Handler{
		HTTPGet: &corev1.HTTPGetAction{
			Path: "/liveness",
			Port: intstr.FromInt(9099),
			Host: "localhost",
		},
	},
}

var complianceVolumes = []corev1.Volume{
	{
		Name: "elastic-ca-cert-volume",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				Optional: &complianceBoolTrue,
				Items: []corev1.KeyToPath{
					{
						Key:  "tigera.elasticsearch.ca",
						Path: "ca.pem",
					},
				},
				SecretName: "tigera-es-config",
			},
		},
	},
}

// compliance-controller

func complianceControllerServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-controller", Namespace: "calico-monitoring"},
	}
}

func complianceControllerRole(cr *operator.Installation) *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-controller", Namespace: "calico-monitoring"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"batch"},
				Resources: []string{"jobs"},
				Verbs:     []string{"create", "list", "get", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"podTemplates"},
				Verbs:     []string{"get"},
			},
		},
	}
}
func complianceControllerClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-controller"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports/status"},
				Verbs:     []string{"update", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports/finalizers"},
				Verbs:     []string{"update"},
			},
		},
	}
}

func complianceControllerRoleBinding(cr *operator.Installation) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-controller", Namespace: "calico-monitoring"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "tigera-compliance-controller",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-compliance-controller",
				Namespace: "calico-monitoring",
			},
		},
	}
}

func complianceControllerClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-controller"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-compliance-controller",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-compliance-controller",
				Namespace: "calico-monitoring",
			},
		},
	}
}

func complianceControllerDeployment(cr *operator.Installation) *appsv1.Deployment {
	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "TIGERA_COMPLIANCE_MAX_FAILED_JOBS_HISTORY", Value: "3"},
		{Name: "TIGERA_COMPLIANCE_MAX_JOB_RETRIES", Value: "6"},
		{Name: "ELASTIC_USER", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "controller.username",
				Optional: &complianceBoolTrue},
		}},
		{Name: "ELASTIC_PASSWORD", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "controller.password",
				Optional: &complianceBoolTrue},
		}},
	}
	envVars = append(envVars, complianceElasticEnvVars...)

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "compliance-controller",
			Namespace: "calico-monitoring",
			Labels: map[string]string{
				"k8s-app": "compliance-controller",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "compliance-controller"}},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeSelector:       map[string]string{"beta.kubernetes.io/os": "linux"},
					ServiceAccountName: "tigera-compliance-controller",
					Tolerations: []corev1.Toleration{
						{
							Key:    "node-role.kubernetes.io/master",
							Effect: corev1.TaintEffectNoSchedule,
						},
					},
					ImagePullSecrets: cr.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						{
							Name:          "compliance-controller",
							Image:         cr.Spec.Components.Compliance.Controller.Image,
							Env:           envVars,
							VolumeMounts:  complianceVolumeMounts,
							LivenessProbe: complianceLivenessProbe,
						},
					},
					Volumes: complianceVolumes,
				},
			},
		},
	}
}

// compliance-reporter

func complianceReporterServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-reporter", Namespace: "calico-monitoring"},
	}
}

func complianceReporterClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-reporter"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreporttypes", "globalreports"},
				Verbs:     []string{"get"},
			},
		},
	}
}

func complianceReporterClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-reporter"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-compliance-reporter",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-compliance-reporter",
				Namespace: "calico-monitoring",
			},
		},
	}
}

func complianceReporterPodTemplate(cr *operator.Installation) *corev1.PodTemplate {
	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "warning"},
		{Name: "ELASTIC_USER", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "reporter.username",
				Optional: &complianceBoolTrue},
		}},
		{Name: "ELASTIC_PASSWORD", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "reporter.password",
				Optional: &complianceBoolTrue},
		}},
	}
	envVars = append(envVars, complianceElasticEnvVars...)

	return &corev1.PodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera.io.report",
			Namespace: "calico-monitoring",
			Labels: map[string]string{
				"k8s-app": "compliance-reporter",
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera.io.report",
				Namespace: "calico-monitoring",
				Labels: map[string]string{
					"k8s-app": "compliance-reporter",
				},
			},
			Spec: corev1.PodSpec{
				NodeSelector:       map[string]string{"beta.kubernetes.io/os": "linux"},
				ServiceAccountName: "tigera-compliance-reporter",
				Tolerations: []corev1.Toleration{
					{
						Key:    "node-role.kubernetes.io/master",
						Effect: corev1.TaintEffectNoSchedule,
					},
				},
				ImagePullSecrets: cr.Spec.ImagePullSecrets,
				Containers: []corev1.Container{
					{
						Name:          "reporter",
						Image:         cr.Spec.Components.Compliance.Reporter.Image,
						Env:           envVars,
						VolumeMounts:  complianceVolumeMounts,
						LivenessProbe: complianceLivenessProbe,
					},
				},
				Volumes: complianceVolumes,
			},
		},
	}
}

// compliance-server

func complianceServerServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server", Namespace: "calico-monitoring"},
	}
}

func complianceServerClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreporttypes", "globalreports"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

func complianceServerClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-compliance-server",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-compliance-server",
				Namespace: "calico-monitoring",
			},
		},
	}
}

func complianceServerService(cr *operator.Installation) *v1.Service {
	return &v1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "compliance", Namespace: "calico-monitoring"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "compliance-api",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(5443),
				},
			},
			Selector: map[string]string{"k8s-app": "compliance-server"},
		},
	}
}

func complianceServerDeployment(cr *operator.Installation) *appsv1.Deployment {
	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "ELASTIC_USER", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "server.username",
				Optional: &complianceBoolTrue},
		}},
		{Name: "ELASTIC_PASSWORD", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "server.password",
				Optional: &complianceBoolTrue},
		}},
	}
	envVars = append(envVars, complianceElasticEnvVars...)

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "compliance-server",
			Namespace: "calico-monitoring",
			Labels: map[string]string{
				"k8s-app": "compliance-server",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "compliance-server"}},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeSelector:       map[string]string{"beta.kubernetes.io/os": "linux"},
					ServiceAccountName: "tigera-compliance-server",
					Tolerations: []corev1.Toleration{
						{
							Key:    "node-role.kubernetes.io/master",
							Effect: corev1.TaintEffectNoSchedule,
						},
					},
					ImagePullSecrets: cr.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						{
							Name:          "compliance-server",
							Image:         cr.Spec.Components.Compliance.Server.Image,
							Env:           envVars,
							VolumeMounts:  complianceVolumeMounts,
							LivenessProbe: complianceLivenessProbe,
						},
					},
					Volumes: complianceVolumes,
				},
			},
		},
	}
}

// compliance-snapshotter

func complianceSnapshotterServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-snapshotter", Namespace: "calico-monitoring"},
	}
}

func complianceSnapshotterClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-snapshotter"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"extensions", "authentication.k8s.io", ""},
				Resources: []string{"networkpolicies", "nodes", "namespaces", "pods", "serviceaccounts",
					"endpoints", "services"},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalnetworkpolicies", "networkpolicies", "tier.globalnetworkpolicies",
					"tier.networkpolicies", "tiers", "hostendpoints", "globalnetworksets"},
				Verbs: []string{"get", "list"},
			},
		},
	}
}

func complianceSnapshotterClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-snapshotter"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-compliance-snapshotter",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-compliance-snapshotter",
				Namespace: "calico-monitoring",
			},
		},
	}
}

func complianceSnapshotterDeployment(cr *operator.Installation) *appsv1.Deployment {
	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "TIGERA_COMPLIANCE_MAX_FAILED_JOBS_HISTORY", Value: "3"},
		{Name: "TIGERA_COMPLIANCE_SNAPSHOT_HOUR", Value: "0"},
		{Name: "ELASTIC_USER", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "snapshotter.username",
				Optional: &complianceBoolTrue},
		}},
		{Name: "ELASTIC_PASSWORD", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "snapshotter.password",
				Optional: &complianceBoolTrue},
		}},
	}
	envVars = append(envVars, complianceElasticEnvVars...)

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "compliance-snapshotter",
			Namespace: "calico-monitoring",
			Labels: map[string]string{
				"k8s-app": "compliance-snapshotter",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "compliance-snapshotter"}},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeSelector:       map[string]string{"beta.kubernetes.io/os": "linux"},
					ServiceAccountName: "tigera-compliance-snapshotter",
					Tolerations: []corev1.Toleration{
						{
							Key:    "node-role.kubernetes.io/master",
							Effect: corev1.TaintEffectNoSchedule,
						},
					},
					ImagePullSecrets: cr.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						{
							Name:          "compliance-controller",
							Image:         cr.Spec.Components.Compliance.Controller.Image,
							Env:           envVars,
							VolumeMounts:  complianceVolumeMounts,
							LivenessProbe: complianceLivenessProbe,
						},
					},
					Volumes: complianceVolumes,
				},
			},
		},
	}
}

// compliance-benchmarker

func complianceBenchmarkerServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-benchmarker", Namespace: "calico-monitoring"},
	}
}

func complianceBenchmarkerClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-benchmarker"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get"},
			},
		},
	}
}

func complianceBenchmarkerClusterRoleBinding(cr *operator.Installation) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-benchmarker", Namespace: "calico-monitoring"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-compliance-benchmarker",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-compliance-benchmarker",
				Namespace: "calico-monitoring",
			},
		},
	}
}

func complianceBenchmarkerDaemonSet(cr *operator.Installation) *appsv1.DaemonSet {
	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{Name: "ELASTIC_USER", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "snapshotter.username",
				Optional: &complianceBoolTrue},
		}},
		{Name: "ELASTIC_PASSWORD", ValueFrom: &v1.EnvVarSource{
			ConfigMapKeyRef: &v1.ConfigMapKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "elastic-compliance-user",
				},
				Key:      "snapshotter.password",
				Optional: &complianceBoolTrue},
		}},
	}
	envVars = append(envVars, complianceElasticEnvVars...)

	volMounts := []corev1.VolumeMount{
		{Name: "var-lib-etcd", MountPath: "/var/lib/etcd", ReadOnly: true},
		{Name: "var-lib-kubelet", MountPath: "/var/lib/kubelet", ReadOnly: true},
		{Name: "etc-systemd", MountPath: "/etc/systemd", ReadOnly: true},
		{Name: "etc-kubernetes", MountPath: "/etcd/kubernetes", ReadOnly: true},
		{Name: "usr-bin", MountPath: "/usr/bin", ReadOnly: true},
	}
	volMounts = append(volMounts, complianceVolumeMounts...)

	vols := []corev1.Volume{
		{
			Name:         "var-lib-etcd",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/etcd"}},
		},
		{
			Name:         "var-lib-kubelet",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet"}},
		},
		{
			Name:         "etcd-systemd",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/systemd"}},
		},
		{
			Name:         "etcd-kubernetes",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/kubernetes"}},
		},
		{
			Name:         "usr-bin",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/bin"}},
		},
	}
	vols = append(vols, complianceVolumes...)

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "compliance-benchmarker",
			Namespace: "calico-monitoring",
			Labels:    map[string]string{"k8s-app": "compliance-benchmarker"},
		},

		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "compliance-benchmarker"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "compliance-benchmarker",
					Namespace: "calico-monitoring",
					Labels:    map[string]string{"k8s-app": "compliance-benchmarker"},
				},
				Spec: corev1.PodSpec{
					NodeSelector:       map[string]string{"beta.kubernetes.io/os": "linux"},
					ServiceAccountName: "tigera-compliance-benchmarker",
					HostPID:            true,
					Tolerations: []corev1.Toleration{
						{
							Effect:   corev1.TaintEffectNoSchedule,
							Operator: corev1.TolerationOpExists,
						},
						{
							Key:      "CriticalAddonsOnly",
							Operator: corev1.TolerationOpExists,
						},
						{
							Effect:   corev1.TaintEffectNoExecute,
							Operator: corev1.TolerationOpExists,
						},
					},
					ImagePullSecrets: cr.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						{
							Name:          "compliance-benchmarker",
							Image:         cr.Spec.Components.Compliance.Benchmarker.Image,
							Env:           envVars,
							VolumeMounts:  volMounts,
							LivenessProbe: complianceLivenessProbe,
						},
					},
					Volumes: vols,
				},
			},
		},
	}
}

func complianceBenchmarkerSecurityContextConstraints(cr *operator.Installation) *ocsv1.SecurityContextConstraints {
	return &ocsv1.SecurityContextConstraints{
		TypeMeta:                 metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
		ObjectMeta:               metav1.ObjectMeta{Name: "tigera-compliance-benchmarker"},
		AllowHostDirVolumePlugin: true,
		AllowHostIPC:             false,
		AllowHostNetwork:         false,
		AllowHostPID:             true,
		AllowHostPorts:           false,
		AllowPrivilegeEscalation: &complianceBoolTrue,
		AllowPrivilegedContainer: true,
		FSGroup:                  ocsv1.FSGroupStrategyOptions{Type: ocsv1.FSGroupStrategyRunAsAny},
		ReadOnlyRootFilesystem:   false,
		SELinuxContext:           ocsv1.SELinuxContextStrategyOptions{Type: ocsv1.SELinuxStrategyMustRunAs},
		SupplementalGroups:       ocsv1.SupplementalGroupsStrategyOptions{Type: ocsv1.SupplementalGroupsStrategyRunAsAny},
		Users:                    []string{"system:serviceaccount:calico-monitoring:tigera-compliance-benchmarker"},
		Groups:                   []string{"system:authenticated"},
		Volumes:                  []ocsv1.FSType{"*"},
	}
}

// compliance-report-types

func complianceGlobalReportInventory(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalReportType", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "inventory",
			Labels: map[string]string{
				"global-report-type": "inventory",
			},
		},
		Spec: v3.ReportTypeSpec{
			DownloadTemplates: []v3.ReportTemplate{
				{
					Name:     "summary.csv",
					Template: "{{ $c := csv }} {{- $c := $c.AddColumn \"startTime\"                     \"{{ dateRfc3339 .StartTime }}\" }} {{- $c := $c.AddColumn \"endTime\"                       \"{{ dateRfc3339 .EndTime }}\" }} {{- $c := $c.AddColumn \"endpointSelector\"              \"{{ if .ReportSpec.Endpoints }}{{ .ReportSpec.Endpoints.Selector }}{{ end }}\" }} {{- $c := $c.AddColumn \"namespaceNames\"                \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ join \";\" .ReportSpec.Endpoints.Namespaces.Names }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"namespaceSelector\"             \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ .ReportSpec.Endpoints.Namespaces.Selector }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"serviceAccountNames\"           \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ join \";\" .ReportSpec.Endpoints.ServiceAccounts.Names }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"serviceAccountSelectors\"       \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ .ReportSpec.Endpoints.ServiceAccounts.Selector }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"endpointsNumInScope\"           \"{{ .EndpointsSummary.NumTotal }}\" }} {{- $c := $c.AddColumn \"endpointsNumIngressProtected\"  \"{{ .EndpointsSummary.NumIngressProtected }}\" }} {{- $c := $c.AddColumn \"endpointsNumEgressProtected\"   \"{{ .EndpointsSummary.NumEgressProtected }}\" }} {{- $c := $c.AddColumn \"namespacesNumInScope\"          \"{{ .NamespacesSummary.NumTotal }}\" }} {{- $c := $c.AddColumn \"namespacesNumIngressProtected\" \"{{ .NamespacesSummary.NumIngressProtected }}\" }} {{- $c := $c.AddColumn \"namespacesNumEgressProtected\"  \"{{ .NamespacesSummary.NumEgressProtected }}\" }} {{- $c := $c.AddColumn \"serviceAccountsNumInScope\"     \"{{ .EndpointsSummary.NumServiceAccounts }}\" }}",
				},
				{
					Name:     "endpoints.csv",
					Template: "{{ $c := csv }} {{- $c := $c.AddColumn \"endpoint\"         \"{{ .Endpoint }}\" }} {{- $c := $c.AddColumn \"ingressProtected\" \"{{ .IngressProtected }}\" }} {{- $c := $c.AddColumn \"egressProtected\"  \"{{ .EgressProtected }}\" }} {{- $c := $c.AddColumn \"envoyEnabled\"     \"{{ .EnvoyEnabled }}\" }} {{- $c := $c.AddColumn \"appliedPolicies\"  \"{{ join \";\" .AppliedPolicies }}\" }} {{- $c := $c.AddColumn \"services\"         \"{{ join \";\" .Services }}\" }} {{- $c.Render .Endpoints }} ",
				},
				{
					Name:     "namespaces.csv",
					Template: "{{ $c := csv }} {{- $c := $c.AddColumn \"namespace\"        \"{{ .Namespace }}\" }} {{- $c := $c.AddColumn \"ingressProtected\" \"{{ .IngressProtected }}\" }} {{- $c := $c.AddColumn \"egressProtected\"  \"{{ .EgressProtected }}\" }} {{- $c := $c.AddColumn \"envoyEnabled\"     \"{{ .EnvoyEnabled }}\" }} {{- $c.Render .Namespaces }} ",
				},
				{
					Name:     "services.csv",
					Template: "{{ $c := csv }} {{- $c := $c.AddColumn \"service\"          \"{{ .Service }}\" }} {{- $c := $c.AddColumn \"ingressProtected\" \"{{ .IngressProtected }}\" }} {{- $c := $c.AddColumn \"envoyEnabled\"     \"{{ .EnvoyEnabled }}\" }} {{- $c.Render .Services }}",
				},
			},
			IncludeEndpointData: true,
			UISummaryTemplate: v3.ReportTemplate{
				Name:     "ui-temporary.json",
				Template: "'{\"heading\":\"Inscope vs Protected\",\"type\":\"panel\",\"widgets\":[{\"data\":[{\"label\":\"Protected ingress\",\"value\":{{ .EndpointsSummary.NumIngressProtected }}}],\"heading\":\"Endpoints\",\"summary\":{\"label\":\"Total\",\"total\":{{ .EndpointsSummary.NumTotal }}},\"type\":\"radialbarchart\"},{\"data\":[{\"label\":\"Protected ingress\",\"value\":{{ .NamespacesSummary.NumIngressProtected }}}],\"heading\":\"Namespaces\",\"summary\":{\"label\":\"Total\",\"total\":{{ .NamespacesSummary.NumTotal }}},\"type\":\"radialbarchart\"},{\"data\":[{\"label\":\"Protected egress\",\"value\":{{ .EndpointsSummary.NumEgressProtected }}}],\"heading\":\"Endpoints\",\"summary\":{\"label\":\"Total\",\"total\":{{ .EndpointsSummary.NumTotal }}},\"type\":\"radialbarchart\"},{\"data\":[{\"label\":\"Protected egress\",\"value\":{{ .NamespacesSummary.NumEgressProtected }}}],\"heading\":\"Namespaces\",\"summary\":{\"label\":\"Total\",\"total\":{{ .NamespacesSummary.NumTotal }}},\"type\":\"radialbarchart\"}]}'",
			},
		},
	}
}

func complianceGlobalReportNetworkAccess(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalReportType", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "network-access",
			Labels: map[string]string{
				"global-report-type": "network-access",
			},
		},
		Spec: v3.ReportTypeSpec{
			DownloadTemplates: []v3.ReportTemplate{
				{
					Name:     "summary.csv",
					Template: "{{ $c := csv }} {{- $c := $c.AddColumn \"startTime\"                             \"{{ dateRfc3339 .StartTime }}\" }} {{- $c := $c.AddColumn \"endTime\"                               \"{{ dateRfc3339 .EndTime }}\" }} {{- $c := $c.AddColumn \"endpointSelector\"                      \"{{ if .ReportSpec.Endpoints }}{{ .ReportSpec.Endpoints.Selector }}{{ end }}\" }} {{- $c := $c.AddColumn \"namespaceNames\"                        \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ join \";\" .ReportSpec.Endpoints.Namespaces.Names }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"namespaceSelector\"                     \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ .ReportSpec.Endpoints.Namespaces.Selector }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"serviceAccountNames\"                   \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ join \";\" .ReportSpec.Endpoints.ServiceAccounts.Names }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"serviceAccountSelectors\"               \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ .ReportSpec.Endpoints.ServiceAccounts.Selector }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"endpointsNumIngressProtected\"          \"{{ .EndpointsSummary.NumIngressProtected }}\" }} {{- $c := $c.AddColumn \"endpointsNumEgressProtected\"           \"{{ .EndpointsSummary.NumEgressProtected }}\" }} {{- $c := $c.AddColumn \"endpointsNumIngressUnprotected\"        \"{{ sub .EndpointsSummary.NumTotal .EndpointsSummary.NumIngressProtected }}\" }} {{- $c := $c.AddColumn \"endpointsNumEgressUnprotected\"         \"{{ sub .EndpointsSummary.NumTotal .EndpointsSummary.NumEgressProtected  }}\" }} {{- $c := $c.AddColumn \"endpointsNumIngressFromInternet\"       \"{{ .EndpointsSummary.NumIngressFromInternet }}\" }} {{- $c := $c.AddColumn \"endpointsNumEgressToInternet\"          \"{{ .EndpointsSummary.NumEgressToInternet }}\" }} {{- $c := $c.AddColumn \"endpointsNumIngressFromOtherNamespace\" \"{{ .EndpointsSummary.NumIngressFromOtherNamespace }}\" }} {{- $c := $c.AddColumn \"endpointsNumEgressToOtherNamespace\"    \"{{ .EndpointsSummary.NumEgressToOtherNamespace }}\" }} {{- $c := $c.AddColumn \"endpointsNumEnvoyEnabled\"              \"{{ .EndpointsSummary.NumEnvoyEnabled }}\" }}",
				},
				{
					Name:     "endpoints.csv",
					Template: "{{ $c := csv }} {{- $c := $c.AddColumn \"endpoint\"                                  \"{{ .Endpoint }}\" }} {{- $c := $c.AddColumn \"ingressProtected\"                          \"{{ .IngressProtected }}\" }} {{- $c := $c.AddColumn \"egressProtected\"                           \"{{ .EgressProtected }}\" }} {{- $c := $c.AddColumn \"ingressFromInternet\"                       \"{{ .IngressFromInternet }}\" }} {{- $c := $c.AddColumn \"egressToInternet\"                          \"{{ .EgressToInternet }}\" }} {{- $c := $c.AddColumn \"ingressFromOtherNamespace\"                 \"{{ .IngressFromOtherNamespace }}\" }} {{- $c := $c.AddColumn \"egressToOtherNamespace\"                    \"{{ .EgressToOtherNamespace }}\" }} {{- $c := $c.AddColumn \"envoyEnabled\"                              \"{{ .EnvoyEnabled }}\" }} {{- $c := $c.AddColumn \"appliedPolicies\"                           \"{{ join \";\" .AppliedPolicies }}\" }} {{- $c := $c.AddColumn \"trafficAggregationPrefix\"                  \"{{ flowsPrefix . }}\" }} {{- $c := $c.AddColumn \"endpointsGeneratingTrafficToThisEndpoint\"  \"{{ join \";\" (flowsIngress .) }}\" }} {{- $c := $c.AddColumn \"endpointsReceivingTrafficFromThisEndpoint\" \"{{ join \";\" (flowsEgress .) }}\" }} {{- $c.Render .Endpoints }}",
				},
			},
			IncludeEndpointData: true,
			UISummaryTemplate: v3.ReportTemplate{
				Name:     "ui-summary.json",
				Template: "'{\"heading\":\"Inscope vs Protected\",\"type\":\"panel\",\"widgets\":[{\"data\":[{\"label\":\"Protected ingress\",\"value\":{{ .EndpointsSummary.NumIngressProtected }}}],\"heading\":\"Endpoints\",\"summary\":{\"label\":\"Total\",\"total\":{{ .EndpointsSummary.NumTotal }}},\"type\":\"radialbarchart\"},{\"data\":[{\"label\":\"Protected ingress\",\"value\":{{ .NamespacesSummary.NumIngressProtected }}}],\"heading\":\"Namespaces\",\"summary\":{\"label\":\"Total\",\"total\":{{ .NamespacesSummary.NumTotal }}},\"type\":\"radialbarchart\"},{\"data\":[{\"label\":\"Protected egress\",\"value\":{{ .EndpointsSummary.NumEgressProtected }}}],\"heading\":\"Endpoints\",\"summary\":{\"label\":\"Total\",\"total\":{{ .EndpointsSummary.NumTotal }}},\"type\":\"radialbarchart\"},{\"data\":[{\"label\":\"Protected egress\",\"value\":{{ .NamespacesSummary.NumEgressProtected }}}],\"heading\":\"Namespaces\",\"summary\":{\"label\":\"Total\",\"total\":{{ .NamespacesSummary.NumTotal }}},\"type\":\"radialbarchart\"}]}'",
			},
		},
	}
}

func complianceGlobalReportPolicyAudit(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalReportType", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-audit",
			Labels: map[string]string{
				"global-report-type": "policy-audit",
			},
		},
		Spec: v3.ReportTypeSpec{
			DownloadTemplates: []v3.ReportTemplate{
				{
					Name:     "summary.csv",
					Template: "{{ $c := csv }} {{- $c := $c.AddColumn \"startTime\"               \"{{ dateRfc3339 .StartTime }}\" }} {{- $c := $c.AddColumn \"endTime\"                 \"{{ dateRfc3339 .EndTime }}\" }} {{- $c := $c.AddColumn \"endpointSelector\"        \"{{ if .ReportSpec.Endpoints }}{{ .ReportSpec.Endpoints.Selector }}{{ end }}\" }} {{- $c := $c.AddColumn \"namespaceNames\"          \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ join \";\" .ReportSpec.Endpoints.Namespaces.Names }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"namespaceSelector\"       \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.Namespaces }}{{ .ReportSpec.Endpoints.Namespaces.Selector }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"serviceAccountNames\"     \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ join \";\" .ReportSpec.Endpoints.ServiceAccounts.Names }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"serviceAccountSelectors\" \"{{ if .ReportSpec.Endpoints }}{{ if .ReportSpec.Endpoints.ServiceAccounts }}{{ .ReportSpec.Endpoints.ServiceAccounts.Selector }}{{ end }}{{ end }}\" }} {{- $c := $c.AddColumn \"numCreatedPolicies\"      \"{{ .AuditSummary.NumCreate }}\" }} {{- $c := $c.AddColumn \"numModifiedPolicies\"     \"{{ .AuditSummary.NumModify }}\" }} {{- $c := $c.AddColumn \"numDeletedPolicies\"      \"{{ .AuditSummary.NumDelete }}\" }} {{- $c.Render . }}",
				},
				{
					Name:     "events.json",
					Template: "{{ toJson .AuditEvents }}",
				},
				{
					Name:     "events.yaml",
					Template: "{{ toYaml .AuditEvents }}",
				},
			},
			IncludeEndpointData: true,
			UISummaryTemplate: v3.ReportTemplate{
				Name:     "ui-summary.json",
				Template: "'{\"heading\":\"Network Policy Configuration Changes\",\"type\":\"panel\",\"widgets\":[{\"data\":[{\"label\":\"Created\",\"value\":{{ .AuditSummary.NumCreate }}}],\"heading\":\"Network Policies\",\"summary\":{\"label\":\"Total\",\"total\":{{ .AuditSummary.NumTotal }}},\"type\":\"radialbarchart\"},{\"data\":[{\"label\":\"Modified\",\"value\":{{ .AuditSummary.NumModify }}}],\"heading\":\"Network Policies\",\"summary\":{\"label\":\"Total\",\"total\":{{ .AuditSummary.NumTotal }}},\"type\":\"radialbarchart\"},{\"data\":[{\"label\":\"Deleted\",\"value\":{{ .AuditSummary.NumDelete }}}],\"heading\":\"Network Policies\",\"summary\":{\"label\":\"Total\",\"total\":{{ .AuditSummary.NumTotal }}},\"type\":\"radialbarchart\"}]}'",
			},
		},
	}
}

func complianceGlobalReportCISBenchmark(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalReportType", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cis-benchmark",
			Labels: map[string]string{
				"global-report-type": "cis-benchmark",
			},
		},
		Spec: v3.ReportTypeSpec{
			DownloadTemplates: []v3.ReportTemplate{
				{
					Name:     "all-tests.csv",
					Template: "nodeName,testIndex,status,scored {{ range $i, $node := .CISBenchmark -}} {{- range $j, $section := $node.Results -}} {{- range $k, $result := $section.Results -}} {{- $node.NodeName }},{{ $result.TestNumber }},{{ $result.Status }},{{ $result.Scored }} {{ end }} {{- end }} {{- end }}",
				},
				{
					Name:     "failed-tests.csv",
					Template: "nodeName,testIndex,status,scored {{ range $i, $node := .CISBenchmark }} {{- range $j, $section := $node.Results }} {{- range $k, $result := $section.Results }} {{- if eq $result.Status \"FAIL\" }} {{- $node.NodeName }},{{ $result.TestNumber }},{{ $result.Status }},{{ $result.Scored }} {{ end }} {{- end }} {{- end }} {{- end }}",
				},
			},
			IncludeEndpointData: true,
			UISummaryTemplate: v3.ReportTemplate{
				Name:     "ui-summary.json",
				Template: "{{ $n := len .CISBenchmark }}\n{\n\t\"heading\": \"Kubernetes CIS Benchmark\",\n\t\"type\": \"row\",\n\t\"widgets\": [{\n\t\t\"heading\": \"Node Failure Summary\",\n\t\t\"type\": \"cis-benchmark-nodes\",\n\t\t\"summary\": {\n\t\t\t\"label\": \"Total\",\n\t\t\t\"total\": {{ $n }}\n\t\t},\n\t\t\"data\": [{\n\t\t\t\"label\": \"HIGH\",\n\t\t\t\"value\": {{ .CISBenchmarkSummary.HighCount }},\n\t\t\t\"desc\": \"Nodes with {{ if .ReportSpec.CIS }}{{ if .ReportSpec.CIS.HighThreshold }}{{ .ReportSpec.CIS.HighThreshold }}{{ else }}100{{ end }}{{ else }}100{{ end }}% or more tests passing\"\n\t\t}, {\n\t\t\t\"label\": \"MED\",\n\t\t\t\"value\": {{ .CISBenchmarkSummary.MedCount }},\n\t\t\t\"desc\": \"Nodes with {{ if .ReportSpec.CIS }}{{ if .ReportSpec.CIS.MedThreshold }}{{ .ReportSpec.CIS.MedThreshold }}{{ else }}50{{ end }}{{ else }}50{{ end }}% or more tests passing\"\n\t\t}, {\n\t\t\t\"label\": \"LOW\",\n\t\t\t\"value\": {{ .CISBenchmarkSummary.LowCount }},\n\t\t\t\"desc\": \"Nodes with less than {{ if .ReportSpec.CIS }}{{ if .ReportSpec.CIS.MedThreshold }}{{ .ReportSpec.CIS.MedThreshold }}{{ else }}50{{ end }}{{ else }}50{{ end }}% tests passing\"\n\t\t}]\n\t}\n{{ if .CISBenchmark }}\n\t, {\n\t\t\"heading\": \"Top Failed Tests\",\n\t\t\"type\": \"cis-benchmark-tests\",\n\t\t\"topFailedTests\": {\n\t\t\t\"tests\": [\n{{ $tests := cisTopFailedTests . }}\n{{ $nTests := len $tests }}\n{{ range $i, $test := $tests }}\n\t\t\t{\n\t\t\t\t\"index\": \"{{ $test.TestNumber }}\",\n\t\t\t\t\"description\": \"{{ $test.TestDesc }}\",\n\t\t\t\t\"failedCount\": \"{{ $test.Count }}\"\n\t\t\t} {{ $i1 := add1 $i }}{{ if ne $i1 $nTests }}, {{ end }}\n{{ end }}\n\t\t\t]} \n\t}\n{{ end }}\n\t]\n}\n",
			},
		},
	}
}
