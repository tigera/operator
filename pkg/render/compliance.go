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
	v3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
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

			complianceGlobalReportInventory(cr),
			complianceGlobalReportNetworkAccess(cr),
			complianceGlobalReportPolicyAudit(cr),
		},
		deps: []runtime.Object{},
	}
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
							Name:  "compliance-controller",
							Image: cr.Spec.Components.Compliance.ControllerImage,
							Env:   envVars,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "elastic-ca-cert-volume",
									MountPath: "/etc/ssl/elastic/",
								},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/liveness",
										Port: intstr.FromInt(9099),
										Host: "localhost",
									},
								},
							},
						},
					},
					Volumes: []corev1.Volume{
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
					},
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
						Name:  "reporter",
						Image: cr.Spec.Components.Compliance.ReporterImage,
						Env:   envVars,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "elastic-ca-cert-volume",
								MountPath: "/etc/ssl/elastic/",
							},
						},
						LivenessProbe: &corev1.Probe{
							Handler: corev1.Handler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/liveness",
									Port: intstr.FromInt(9099),
									Host: "localhost",
								},
							},
						},
					},
				},
				Volumes: []corev1.Volume{
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
				},
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
				APIGroups: []string{"batch"},
				Resources: []string{"globalreporttypes", "globalreports"},
				Verbs:     []string{"get"},
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
	return &rbacv1.ClusterRoleBinding{}
}

func complianceServerService(cr *operator.Installation) *v1.Service {
	return &v1.Service{}
}

func complianceServerDeployment(cr *operator.Installation) *appsv1.Deployment {
	return &appsv1.Deployment{}
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
	return &rbacv1.ClusterRoleBinding{}
}

func complianceSnapshotterDeployment(cr *operator.Installation) *appsv1.Deployment {
	return &appsv1.Deployment{}
}

// compliance-report-types
func complianceGlobalReportInventory(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{}
}

func complianceGlobalReportNetworkAccess(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{}
}

func complianceGlobalReportPolicyAudit(cr *operator.Installation) *v3.GlobalReportType {
	return &v3.GlobalReportType{}
}
