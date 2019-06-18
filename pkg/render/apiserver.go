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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

const (
	defaultAPIServerImageName   = "tigera/cnx-apiserver"
	defaultQueryServerImageName = "tigera/cnx-queryserver"
	apiServerPort               = 5443
	queryServerPort             = 8080
)

func APIServer(cr *operator.Installation) []runtime.Object {
	if cr.Spec.Variant != operator.TigeraSecureEnterprise {
		return nil
	}
	objs := []runtime.Object{
		apiServer(cr),
		auditPolicyConfigMap(cr),
		apiServerServiceAccount(cr),
		apiService(cr),
		apiServerService(cr),
		apiServiceAccountClusterRole(cr),
		apiServiceAccountClusterRoleBinding(cr),
		tieredPolicyPassthruClusterRole(cr),
		tieredPolicyPassthruClusterRolebinding(cr),
		delegateAuthClusterRoleBinding(cr),
		authReaderRoleBinding(cr),
	}
	return objs
}

// apiService creates an API service that registers Tigera Secure APIs (and API server).
func apiService(cr *operator.Installation) *v1beta1.APIService {
	s := &v1beta1.APIService{
		TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "v3.projectcalico.org",
		},
		Spec: v1beta1.APIServiceSpec{
			Group:                "projectcalico.org",
			VersionPriority:      200,
			GroupPriorityMinimum: 200,
			Service: &v1beta1.ServiceReference{
				Name:      "tigera-api",
				Namespace: "tigera-system",
			},
			Version:               "v3",
			InsecureSkipTLSVerify: true,
		},
	}
	return s
}

// tieredPolicyPassthruClusterRole creates a clusterrole that is used to control the RBAC
// mechanism for Tigera Secure tiered policy.
func tieredPolicyPassthruClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tiered-policy-passthrough",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"networkpolicies", "globalnetworkpolicies"},
				Verbs:     []string{"*"},
			},
		},
	}
}

// tieredPolicyPassthruClusterRolebinding creates a clusterrolebinding that applies tieredPolicyPassthruClusterRole to all users.
func tieredPolicyPassthruClusterRolebinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tiered-policy-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
			{
				Kind:     "Group",
				Name:     "system:unauthenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-tiered-policy-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// delegateAuthClusterRoleBinding creates a clusterrolebinding that allows the API server to delegate
// authn/authz requests to main API server.
func delegateAuthClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-delegate-auth",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-apiserver",
				Namespace: "tigera-system",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "system:auth-delegator",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// authReaderRoleBinding creates a rolebinding that allows the API server to access the
// extension-apiserver-authentication configmap. That configmap contains the client CA file that
// the main API server was configured with.
func authReaderRoleBinding(cr *operator.Installation) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-auth-reader",
			Namespace: "kube-system",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "extension-apiserver-authentication-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-apiserver",
				Namespace: "tigera-system",
			},
		},
	}
}

// apiServerServiceAccount creates the service account used by the API server.
func apiServerServiceAccount(cr *operator.Installation) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-apiserver",
			Namespace: "tigera-system",
		},
	}
}

// apiServiceAccountClusterRole creates a clusterrole that gives permissions to access backing CRDs and
// k8s networkpolicies.
func apiServiceAccountClusterRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-crds",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"extensions",
					"networking.k8s.io",
					"",
				},
				Resources: []string{
					"networkpolicies",
					"nodes",
					"namespaces",
					"pods",
					"serviceaccounts",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"globalnetworkpolicies",
					"networkpolicies",
					"tiers",
					"clusterinformations",
					"hostendpoints",
					"licensekeys",
					"globalnetworksets",
					"globalthreatfeeds",
					"globalreporttypes",
					"globalreports",
				},
				Verbs: []string{"*"},
			},
		},
	}
}

// apiServiceAccountClusterRoleBinding creates a clusterrolebinding that applies apiServiceAccountClusterRole to
// the tigera-apiserver service account.
func apiServiceAccountClusterRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-access-crds",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-apiserver",
				Namespace: "tigera-system",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-crds",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// apiServerService creates a service backed by the API server and query server.
func apiServerService(cr *operator.Installation) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-api",
			Namespace: "tigera-system",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "apiserver",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(apiServerPort),
				},
				{
					Name:       "queryserver",
					Port:       queryServerPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(queryServerPort),
				},
			},
			Selector: map[string]string{
				"apiserver": "true",
			},
		},
	}
}

func auditPolicyConfigMap(cr *operator.Installation) *corev1.ConfigMap {
	const defaultAuditPolicy = `apiVersion: audit.k8s.io/v1beta1
kind: Policy
rules:
- level: RequestResponse
  omitStages:
  - RequestReceived
  verbs:
  - create
  - patch
  - update
  - delete
  resources:
  - group: projectcalico.org
    resources:
    - globalnetworkpolicies
    - networkpolicies
    - globalnetworksets
    - tiers
    - hostendpoints`

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-audit-policy",
			Namespace: "tigera-system",
		},
		Data: map[string]string{
			"config": defaultAuditPolicy,
		},
	}
}

// apiServer creates a deployment containing the API and query servers.
func apiServer(cr *operator.Installation) *appsv1.Deployment {
	var replicas int32 = 1

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-apiserver",
			Namespace: "tigera-system",
			Labels: map[string]string{
				"apiserver": "true",
				"k8s-app":   "tigera-apiserver",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"apiserver": "true"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-apiserver",
					Namespace: "tigera-system",
					Labels: map[string]string{
						"apiserver": "true",
						"k8s-app":   "tigera-apiserver",
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					ServiceAccountName: "tigera-apiserver",
					Tolerations:        tolerations(cr),
					ImagePullSecrets:   cr.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						apiServerContainer(cr),
						queryServerContainer(cr),
					},
					Volumes: apiServerVolumes(cr),
				},
			},
		},
	}
	return d
}

// apiServerContainer creates the API server container.
func apiServerContainer(cr *operator.Installation) corev1.Container {
	apiServerImage := fmt.Sprintf("%s%s:%s", cr.Spec.Registry, defaultAPIServerImageName, cr.Spec.Version)
	if len(cr.Spec.Components.APIServer.ImageOverride) > 0 {
		apiServerImage = cr.Spec.Components.APIServer.ImageOverride
	}

	volumeMounts := []corev1.VolumeMount{
		{Name: "tigera-audit-logs", MountPath: "/var/log/calico/audit"},
		{Name: "tigera-audit-policy", MountPath: "/etc/tigera/audit"},
	}

	volumeMounts = setCustomVolumeMounts(volumeMounts, cr.Spec.Components.APIServer.ExtraVolumeMounts)
	isPrivileged := true

	apiServer := corev1.Container{
		Name:  "tigera-apiserver",
		Image: apiServerImage,
		Args: []string{
			fmt.Sprintf("--secure-port=%d", apiServerPort),
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		},
		Env: []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		},
		// Needed for permissions to write to the audit log
		SecurityContext: &corev1.SecurityContext{Privileged: &isPrivileged},
		VolumeMounts:    volumeMounts,
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt(apiServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
			PeriodSeconds:       10,
		},
	}

	return apiServer
}

// queryServerContainer creates the query server container.
func queryServerContainer(cr *operator.Installation) corev1.Container {
	image := fmt.Sprintf("%s%s:%s", cr.Spec.Registry, defaultQueryServerImageName, cr.Spec.Version)
	if len(cr.Spec.Components.APIServer.ImageOverride) > 0 {
		image = cr.Spec.Components.APIServer.ImageOverride
	}
	c := corev1.Container{
		Name:  "tigera-queryserver",
		Image: image,
		Env: []corev1.EnvVar{
			// Set queryserver logging to "info"
			{Name: "LOGLEVEL", Value: "info"},
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt(queryServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
			PeriodSeconds:       10,
		},
	}
	return c
}

// apiServerVolumes creates the volumes used by the API server deployment.
func apiServerVolumes(cr *operator.Installation) []corev1.Volume {
	hostPathType := corev1.HostPathDirectoryOrCreate
	volumes := []corev1.Volume{
		{
			Name: "tigera-audit-logs",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/audit",
					Type: &hostPathType,
				},
			},
		},
		{
			Name: "tigera-audit-policy",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-audit-policy"},
					Items: []corev1.KeyToPath{
						{
							Key:  "config",
							Path: "policy.conf",
						},
					},
				},
			},
		},
	}
	volumes = setCustomVolumes(volumes, cr.Spec.Components.APIServer.ExtraVolumes)
	return volumes
}

// tolerations creates the tolerations used by the API server deployment.
func tolerations(cr *operator.Installation) []corev1.Toleration {
	tolerations := []corev1.Toleration{
		{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
	}
	tolerations = setCustomTolerations(tolerations, cr.Spec.Components.APIServer.Tolerations)
	return tolerations
}
