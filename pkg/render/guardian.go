// This renderer is responsible for all resources related to a Guardian Deployment in a
// multicluster setup.
package render

import (
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
	GuardianConfigMapName          = "tigera-guardian-config"
	GuardianVolumeName             = "tigera-guardian-certs"
	GuardianSecretName             = "tigera-managed-cluster-connection"
)

func Guardian(
	url string,
	pullSecrets []*corev1.Secret,
	openshift bool,
	registry string,
	tunnelSecret *corev1.Secret,
) Component {
	return &GuardianComponent{
		url:          url,
		pullSecrets:  pullSecrets,
		openshift:    openshift,
		registry:     registry,
		tunnelSecret: tunnelSecret,
	}
}

type GuardianComponent struct {
	url          string
	pullSecrets  []*v1.Secret
	openshift    bool
	registry     string
	tunnelSecret *corev1.Secret
}

func (c *GuardianComponent) Objects() []runtime.Object {
	return []runtime.Object{
		createNamespace(GuardianNamespace, c.openshift),
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.deployment(),
		c.service(),
		c.configMap(),
		copySecrets(GuardianNamespace, c.tunnelSecret)[0],
	}
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
			Ports: []corev1.ServicePort{{
				Port: 9200,
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: 8080,
				},
				Protocol: corev1.ProtocolTCP,
			}},
		},
	}
}

func (c *GuardianComponent) serviceAccount() runtime.Object {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianServiceAccountName, Namespace: GuardianNamespace},
	}
}

func (c *GuardianComponent) configMap() runtime.Object {
	return &v1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianConfigMapName, Namespace: GuardianNamespace},
		Data: map[string]string{
			// Server port for Guardian
			"tigera-guardian.port": "9443",
			// Logging level
			"tigera-guardian.log-level": "INFO",
			// Proxy targets
			"tigera-guardian.proxy-targets": `[
				{
					"path": "/api/",
					"url": "https://kubernetes.default",
					"tokenPath": "/var/run/secrets/kubernetes.io/serviceaccount/token",
					"caBundlePath": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
				},
				{
					"path": "/apis/",
					"url": "https://kubernetes.default",
					"tokenPath": "/var/run/secrets/kubernetes.io/serviceaccount/token",
					"caBundlePath": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
				},
				{
					"path": "/tigera-elasticsearch/",
					"url": "https://tigera-manager.tigera-manager.svc:9443"
				},
				{
					"path": "/compliance/",
					"url": "https://compliance.tigera-compliance.svc"
				}]`,
			// This tells Guardian how to reach Voltron
			"tigera-guardian.voltron-url": c.url,
		},
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
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
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
			Name:            GuardianDeploymentName,
			Image:           constructImage(GuardianImageName, c.registry),
			Env: []corev1.EnvVar{
				{
					Name:      "GUARDIAN_PORT",
					ValueFrom: envVarSourceFromConfigmap(GuardianConfigMapName, "tigera-guardian.port"),
				},
				{
					Name:      "GUARDIAN_LOGLEVEL",
					ValueFrom: envVarSourceFromConfigmap(GuardianConfigMapName, "tigera-guardian.log-level"),
				},
				{
					Name:      "GUARDIAN_PROXY_TARGETS",
					ValueFrom: envVarSourceFromConfigmap(GuardianConfigMapName, "tigera-guardian.proxy-targets"),
				},
				{
					Name:      "GUARDIAN_VOLTRON_URL",
					ValueFrom: envVarSourceFromConfigmap(GuardianConfigMapName, "tigera-guardian.voltron-url"),
				},
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
