package render

import (
	"fmt"
	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

const (
	defaultAPIServerImageName = "tigera/cnx-apiserver"
	defaultQueryServerImageName = "tigera/cnx-queryserver"
)

func APIServer(cr *operatorv1alpha1.Core) []runtime.Object {
	objs := []runtime.Object{
		apiServer(cr),
		auditPolicyConfigMap(cr),
		apiServerServiceAccount(cr),
		apiService(cr),
		apiServerService(cr),
		tieredPolicyPassthruClusterRole(cr),
		tieredPolicyPassthruClusterRolebinding(cr),
		calicoAuthDelegatorClusterRolebinding(cr),
		calicoAuthReaderRoleBinding(cr),
	}
	if len(cr.Spec.Components.APIServer.TLS.Certificate) > 0 && len(cr.Spec.Components.APIServer.TLS.Key) > 0 {
		objs = append(objs, tlsSecret(cr))
	}
	return objs
}

func apiService(cr *operatorv1alpha1.Core) *v1beta1.APIService {
	s := &v1beta1.APIService{
		TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "v3.projectcalico.org",
		},
		Spec: v1beta1.APIServiceSpec{
			Group: "projectcalico.org",
			VersionPriority: 200,
			GroupPriorityMinimum: 200,
			Service: &v1beta1.ServiceReference{
				Name: "cnx-api",
				Namespace: "kube-system",
			},
			Version: "v3",
			InsecureSkipTLSVerify: true,
		},
	}
	// If a CA bundle is provided, enable TLS verification and add the bundle to the API service.
	if len(cr.Spec.Components.APIServer.TLS.CABundle) > 0 {
		s.Spec.InsecureSkipTLSVerify = false
		s.Spec.CABundle = []byte(cr.Spec.Components.APIServer.TLS.CABundle)
	}
	return s
}

// This ClusterRole is used to control the RBAC mechanism for Calico tiered policy.
// -  If the resources are set to ["networkpolicies","globalnetworkpolicies"], then RBAC for Calico policy has per-tier
//    granularity defined using the "tier.networkpolicies" and "tier.globalnetworkpolicies" pseudo-resource types.
//    This is the default as of v2.3.
// -  If the resources are set to ["tier.networkpolicies","tier.globalnetworkpolicies"], this ensures RBAC for Calico
//    policy is the v2.2 (and earlier) format, where Calico policy RBAC is identical across all tiers that the user can
//    access (i.e. has 'get' access for).
//
// Never include both networkpolicies and tier.networkpolicies and/or globalnetworkpolicies and
// tier.globalnetworkpolicies in the resources list for this ClusterRole since that will grant all users full access to
// Calico policy.
func tieredPolicyPassthruClusterRole(cr *operatorv1alpha1.Core) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ee-calico-tiered-policy-passthru",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"networkpolicies","globalnetworkpolicies"},
				Verbs:  []string{"*"},
			},
		},
	}
}

func tieredPolicyPassthruClusterRolebinding(cr *operatorv1alpha1.Core) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ee-calico-tiered-policy-passthru",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "Group",
				Name: "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
			{
				Kind: "Group",
				Name: "system:unauthenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "ee-calico-tiered-policy-passthru",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func calicoAuthDelegatorClusterRolebinding(cr *operatorv1alpha1.Core) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico:system:auth-delegator",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "ServiceAccount",
				Name: "cnx-apiserver",
				Namespace: "kube-system",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "system:auth-delegator",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func calicoAuthReaderRoleBinding(cr *operatorv1alpha1.Core) *rbacv1.RoleBinding{
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-auth-reader",
			Namespace: "kube-system",
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "extension-apiserver-authentication-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "ServiceAccount",
				Name: "cnx-apiserver",
				Namespace: "kube-system",
			},
		},
	}
}

func apiServerServiceAccount(cr *operatorv1alpha1.Core) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnx-apiserver",
			Namespace: "kube-system",
		},
	}
}

func apiServerService(cr *operatorv1alpha1.Core) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnx-api",
			Namespace: "kube-system",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "apiserver",
					Port: 443,
					Protocol: corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(5443),
				},
				{
					Name: "queryserver",
					Port: 8080,
					Protocol: corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(8080),
				},
			},
			Selector: map[string]string{
				"apiserver": "true",
			},
		},
	}
}

func tlsSecret(cr *operatorv1alpha1.Core) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		Type: corev1.SecretTypeOpaque,
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnx-apiserver-certs",
			Namespace: "kube-system",
		},
		Data: map[string][]byte{
			"apiserver.key": []byte(cr.Spec.Components.APIServer.TLS.Key),
			"apiserver.crt": []byte(cr.Spec.Components.APIServer.TLS.Certificate),
		},
	}
}

func auditPolicyConfigMap(cr *operatorv1alpha1.Core) *corev1.ConfigMap {
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
			Name:      "audit-policy-ee",
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"config": defaultAuditPolicy,
		},
	}
}

func apiServer(cr *operatorv1alpha1.Core) *appsv1.Deployment {
	var replicas int32 = 1

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cnx-apiserver",
			Namespace: "kube-system",
			Labels: map[string]string{
				"apiserver": "true",
				"k8s-app":   "cnx-apiserver",
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
					Name:      "cnx-apiserver",
					Namespace: "kube-system",
					Labels: map[string]string{
						"apiserver": "true",
						"k8s-app":   "cnx-apiserver",
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					ServiceAccountName: "cnx-apiserver",
					Tolerations: tolerations(cr),
					ImagePullSecrets: cr.Spec.ImagePullSecretsRef,
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

func apiServerContainer(cr *operatorv1alpha1.Core) corev1.Container {
	apiServerImage := fmt.Sprintf("%s%s:%s", cr.Spec.Registry, defaultAPIServerImageName, cr.Spec.Version)
	if len(cr.Spec.Components.APIServer.ImageOverride) > 0 {
		apiServerImage = cr.Spec.Components.APIServer.ImageOverride
	}

	volumeMounts := []corev1.VolumeMount{
		{Name: "var-log-calico-audit", MountPath: "/var/log/calico/audit"},
		{Name: "audit-policy-ee", MountPath: "/etc/tigera/audit"},
	}

	if len(cr.Spec.Components.APIServer.TLS.Certificate) > 0 && len(cr.Spec.Components.APIServer.TLS.Key) > 0 {
		apiCertVolume := corev1.VolumeMount{
			Name: "apiserver-certs",
			MountPath: "/code/apiserver.local.config/certificates",
		}
		volumeMounts = append(volumeMounts, apiCertVolume)
	}
	volumeMounts = setCustomVolumeMounts(volumeMounts, cr.Spec.Components.APIServer.ExtraVolumeMounts)

	apiServer := corev1.Container{
		Name:  "cnx-apiserver",
		Image: apiServerImage,
		Args: []string{
			"--secure-port=5443",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		},
		Env: []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		},
		VolumeMounts: volumeMounts,
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt(5443),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
			PeriodSeconds:       10,
		},
	}

	return apiServer
}

func queryServerContainer(cr *operatorv1alpha1.Core) corev1.Container {
	image := fmt.Sprintf("%s%s:%s", cr.Spec.Registry, defaultQueryServerImageName, cr.Spec.Version)
	if len(cr.Spec.Components.APIServer.ImageOverride) > 0 {
		image = cr.Spec.Components.APIServer.ImageOverride
	}
	c := corev1.Container{
		Name:  "cnx-queryserver",
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
					Port:   intstr.FromInt(8080),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
			PeriodSeconds:       10,
		},
	}
	return c
}

func apiServerVolumes(cr *operatorv1alpha1.Core) []corev1.Volume {
	hostPathType := corev1.HostPathDirectoryOrCreate
	volumes := []corev1.Volume{
		{
			Name: "var-log-calico-audit",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/audit",
					Type: &hostPathType,
				},
			},
		},
		{
			Name: "audit-policy-ee",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "audit-policy-ee"},
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
	// If we have TLS config specified add the TLS volume using the secret.
	if len(cr.Spec.Components.APIServer.TLS.Certificate) > 0 && len(cr.Spec.Components.APIServer.TLS.Key) > 0 {
		certVolume := corev1.Volume{
			Name: "apiserver-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "cnx-apiserver-certs",
				},
			},
		}
		volumes = append(volumes, certVolume)
	}
	volumes = setCustomVolumes(volumes, cr.Spec.Components.APIServer.ExtraVolumes)
	return volumes
}

func tolerations(cr *operatorv1alpha1.Core) []corev1.Toleration{
	tolerations := []corev1.Toleration{
		{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
	}
	tolerations = setCustomTolerations(tolerations, cr.Spec.Components.APIServer.Tolerations)
	return tolerations
}
