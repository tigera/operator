package render

import (
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	managerPort           = 9443
	managerTargetPort     = 9443
	managerNodePort       = 30003
	tigeraEsConfigMapName = "tigera-es-config"
	tigeraEsSecretName    = "tigera-es-config"
)

func WebApp(cr *operator.Installation) Component {
	return &webAppComponent{cr: cr}
}

type webAppComponent struct {
	cr *operator.Installation
}

func (c *webAppComponent) GetObjects() []runtime.Object {
	return []runtime.Object{
		webAppServiceAccount(),
		webAppClusterRole(),
		webAppClusterRoleBinding(),
		webAppDeployment(c.cr),
		webAppService(c.cr),
		tigeraUserClusterRole(),
		tigeraNetworkAdminClusterRole(),
	}
}

func (c *webAppComponent) GetComponentDeps() []runtime.Object {
	return nil
}

func (c *webAppComponent) Ready(client client.Client) bool {
	return true
}

// webAppDeployment creates a deployment for the WebApp component.
func webAppDeployment(cr *operator.Installation) *appsv1.Deployment {
	var replicas int32 = 1

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cnx-manager",
			Namespace: "calico-monitoring",
			Labels: map[string]string{
				"k8s-app": "cnx-manager",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cnx-manager",
					Namespace: "calico-monitoring",
					Labels: map[string]string{
						"k8s-app": "cnx-manager",
					},
					Annotations: map[string]string{
						// Mark this pod as a critical add-on; when enabled, the critical add-on scheduler
						// reserves resources for critical add-on pods so that they can be rescheduled after
						// a failure.  This annotation works in tandem with the toleration below.
						"scheduler.alpha.kubernetes.io/critical-pod": "",
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					ServiceAccountName: "cnx-manager",
					Tolerations:        webAppTolerations(),
					ImagePullSecrets:   cr.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						webAppManagerContainer(cr),
						webAppEsProxyContainer(cr),
						webAppProxyContainer(cr),
					},
					Volumes: webAppVolumes(),
				},
			},
		},
	}
	return d
}

// webAppVolumes returns the volumes for the WebApp component.
func webAppVolumes() []v1.Volume {
	optional := true
	return []v1.Volume{
		{
			Name: "cnx-manager-tls",
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: "cnx-manager-tls",
				},
			},
		},
		{
			Name: "tigera-es-proxy-tls",
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: "tigera-es-config",
					Optional:   &optional,
					Items: []v1.KeyToPath{
						{Key: "tigera.elasticsearch.ca", Path: "ca.pem"},
					},
				},
			},
		},
	}
}

// webAppManagerProbe returns the probe for the manager container.
func webAppManagerProbe() *v1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

// webAppEsProxyProbe returns the probe for the ES proxy container.
func webAppEsProxyProbe() *v1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/tigera-elasticsearch/version",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

// webAppProxyProbe returns the probe for the proxy container.
func webAppProxyProbe() *v1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

// webAppManagerContainer returns the manager container.
func webAppManagerContainer(cr *operator.Installation) corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		{Name: "tigera-es-proxy-tls", MountPath: "/etc/ssl/elastic/"},
	}
	return corev1.Container{
		Name:  "cnx-manager",
		Image: cr.Spec.Components.WebApp.Manager.Image,
		Env: []corev1.EnvVar{
			{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: string(cr.Spec.Components.WebApp.AuthenticationType)},
			{Name: "CNX_WEB_OIDC_AUTHORITY", Value: cr.Spec.Components.WebApp.OAuth2Authority},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: cr.Spec.Components.WebApp.OAuth2ClientId},
			{Name: "CNX_PROMETHEUS_API_URL", Value: "/api/v1/namespaces/calico-monitoring/services/calico-node-prometheus:9090/proxy/api/v1"},
			{Name: "CNX_COMPLIANCE_REPORTS_API_URL", Value: "/compliance/reports"},
			{Name: "CNX_QUERY_API_URL", Value: "/api/v1/namespaces/kube-system/services/https:tigera-api:8080/proxy"},
			{Name: "CNX_ELASTICSEARCH_API_URL", Value: "/tigera-elasticsearch"},
			{Name: "CNX_ELASTICSEARCH_KIBANA_URL", Value: "http://127.0.0.1:30601"},
			{Name: "CNX_ENABLE_ERROR_TRACKING", Value: "false"},
			{Name: "CNX_ALP_SUPPORT", Value: "false"},
			{Name: "CNX_CLUSTER_NAME", Value: "cluster"},
		},
		VolumeMounts:  volumeMounts,
		LivenessProbe: webAppManagerProbe(),
	}
}

// webAppProxyContainer returns the container for the WebApp proxy container.
func webAppProxyContainer(cr *operator.Installation) corev1.Container {
	return corev1.Container{
		Name:  "cnx-manager-proxy",
		Image: cr.Spec.Components.WebApp.Proxy.Image,
		Env: []corev1.EnvVar{
			{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: string(cr.Spec.Components.WebApp.AuthenticationType)},
			{Name: "CNX_WEB_OIDC_AUTHORITY", Value: cr.Spec.Components.WebApp.OIDCAuthority},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: cr.Spec.Components.WebApp.OIDCClientId},
			{Name: "CNX_WEB_OAUTH_AUTHORITY", Value: cr.Spec.Components.WebApp.OAuth2Authority},
			{Name: "CNX_WEB_OAUTH_CLIENT_ID", Value: cr.Spec.Components.WebApp.OAuth2ClientId},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "cnx-manager-tls", MountPath: "/etc/cnx-manager-web-tls"},
		},
		LivenessProbe: webAppProxyProbe(),
	}
}

// webAppEsProxyEnv returns the env vars for the ES proxy container.
func webAppEsProxyEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{
			Name:      "ELASTIC_HOST",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.host"),
		},
		{
			Name:      "ELASTIC_PORT",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.port"),
		},
		{
			Name:      "ELASTIC_ACCESS_MODE",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.access-mode"),
		},
		{
			Name:      "ELASTIC_SCHEME",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.scheme"),
		},
		// TODO: make this configurable?
		{
			Name: "ELASTIC_INSECURE_SKIP_VERIFY", Value: "false",
		},
		{
			Name:      "ELASTIC_USERNAME",
			ValueFrom: envVarSourceFromSecret(tigeraEsSecretName, "tigera.elasticsearch.username"),
		},
		{
			Name:      "ELASTIC_PASSWORD",
			ValueFrom: envVarSourceFromSecret(tigeraEsSecretName, "tigera.elasticsearch.password"),
		},
		{
			Name:      "ELASTIC_CA",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.ca.path"),
		},
	}
}

// webAppEsProxyContainer returns the ES proxy container
func webAppEsProxyContainer(cr *operator.Installation) corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		{Name: "tigera-es-proxy-tls", MountPath: "/etc/ssl/elastic/"},
	}
	apiServer := corev1.Container{
		Name:          "tigera-es-proxy",
		Image:         cr.Spec.Components.WebApp.EsProxy.Image,
		Env:           webAppEsProxyEnv(),
		VolumeMounts:  volumeMounts,
		LivenessProbe: webAppEsProxyProbe(),
	}

	return apiServer
}

// webAppTolerations returns the tolerations for the WebApp deployment pods.
func webAppTolerations() []v1.Toleration {
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

// webAppService returns the service exposing the Tigera Secure web app.
func webAppService(cr *operator.Installation) *v1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cnx-manager",
			Namespace: "calico-monitoring",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       managerPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(managerTargetPort),
					NodePort:   managerNodePort,
				},
			},
			Selector: map[string]string{
				"k8s-app": "cnx-manager",
			},
		},
	}
}

// webAppServiceAccount creates the serviceaccount used by the Tigera Secure web app.
func webAppServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "cnx-manager", Namespace: "calico-monitoring"},
	}
}

// webAppClusterRole returns a clusterrole that allows authn/authz review requests.
func webAppClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnx-manager-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

// webAppClusterRoleBinding returns a clusterrolebinding that gives the cnx-manager serviceaccount
// the permissions in the cnx-manager-role.
func webAppClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "cnx-manager-binding"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cnx-manager-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "cnx-manager",
				Namespace: "calico-monitoring",
			},
		},
	}
}

// tigeraUserClusterRole returns a cluster role for a default Tigera WebApp user.
func tigeraUserClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-ui-user",
		},
		Rules: []rbacv1.PolicyRule{
			// List requests that the Tigera manager needs.
			{
				APIGroups: []string{
					"projectcalico.org",
					"networking.k8s.io",
					"extensions",
					"",
				},
				// Use both networkpolicies and tier.networkpolicies, and globalnetworkpolicies and tier.globalnetworkpolicies resource
				// types to ensure identical behavior irrespective of the Calico RBAC scheme (see the ClusterRole
				// "ee-calico-tiered-policy-passthru" for more details).
				Resources: []string{
					"tiers",
					"networkpolicies",
					"tier.networkpolicies",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"namespaces",
					"globalnetworksets",
				},
				Verbs: []string{"watch", "list"},
			},
			// Access to statistics.
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			// Access to flow logs, audit logs, and statistics
			{
				APIGroups: []string{"lma.tigera.io"},
				Resources: []string{"index"},
				ResourceNames: []string{
					"flows", "audit*", "events",
				},
				Verbs: []string{"get"},
			},
			// Access to policies in the default tier
			{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"tiers"},
				ResourceNames: []string{"default"},
				Verbs:         []string{"get"},
			},
			// List and download the reports in the WebApp.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreporttypes"},
				Verbs:     []string{"get"},
			},
		},
	}
}

// tigeraNetworkAdminClusterRole returns a cluster role for a Tigera WebApp network admin.
func tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-network-admin",
		},
		Rules: []rbacv1.PolicyRule{
			// Full access to all network policies
			{
				APIGroups: []string{
					"projectcalico.org",
					"networking.k8s.io",
					"extensions",
				},
				// Use both networkpolicies and tier.networkpolicies, and globalnetworkpolicies and tier.globalnetworkpolicies resource
				// types to ensure identical behavior irrespective of the Calico RBAC scheme (see the ClusterRole
				// "ee-calico-tiered-policy-passthru" for more details).
				Resources: []string{
					"tiers",
					"networkpolicies",
					"tier.networkpolicies",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"globalnetworksets",
				},
				Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
			},
			// Additional "list" requests that the Tigera EE WebApp needs
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"watch", "list"},
			},
			// Access to statistics.
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			// Access to flow logs, audit logs, and statistics
			{
				APIGroups: []string{"lma.tigera.io"},
				Resources: []string{"index"},
				ResourceNames: []string{
					"flows", "audit*", "events",
				},
				Verbs: []string{"get"},
			},
			// Manage globalreport configuration, view report generation status, and list reports in the WebApp.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"*"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports/status"},
				Verbs:     []string{"get", "list", "watch"},
			},
			// List and download the reports in the WebApp.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"get"},
			},
		},
	}
}
