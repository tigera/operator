package render

import (
	"fmt"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	ocsv1 "github.com/openshift/api/security/v1"
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
	tigeraEsSecretName    = "tigera-es-config"
	ManagerNamespace      = "tigera-console"
	ManagerTLSSecretName  = "manager-tls"
	ManagerSecretKeyName  = "key"
	ManagerSecretCertName = "cert"
)

func Console(
	cr *operator.Console,
	monitoring *operator.MonitoringConfiguration,
	tlsKeyPair *corev1.Secret,
	pullSecrets []*corev1.Secret,
	openshift bool,
	registry string,
) (Component, error) {
	tlsSecrets := []*corev1.Secret{}
	if tlsKeyPair == nil {
		var err error
		tlsKeyPair, err = createOperatorTLSSecret(nil,
			ManagerTLSSecretName,
			ManagerSecretKeyName,
			ManagerSecretCertName,
			nil,
		)
		if err != nil {
			return nil, err
		}
		tlsSecrets = []*corev1.Secret{tlsKeyPair}
	}
	copy := tlsKeyPair.DeepCopy()
	copy.ObjectMeta.Namespace = ManagerNamespace
	tlsSecrets = append(tlsSecrets, copy)
	return &consoleComponent{
		cr:          cr,
		monitoring:  monitoring,
		tlsSecrets:  tlsSecrets,
		pullSecrets: pullSecrets,
		openshift:   openshift,
		registry:    registry,
	}, nil
}

type consoleComponent struct {
	cr          *operator.Console
	monitoring  *operator.MonitoringConfiguration
	tlsSecrets  []*corev1.Secret
	pullSecrets []*corev1.Secret
	openshift   bool
	registry    string
}

func (c *consoleComponent) Objects() []runtime.Object {
	objs := []runtime.Object{
		createNamespace(ManagerNamespace, c.openshift),
	}
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, ManagerNamespace)...)
	objs = append(objs,
		c.consoleManagerServiceAccount(),
		c.consoleManagerClusterRole(),
		c.consoleManagerClusterRoleBinding(),
	)
	objs = append(objs, c.getTLSObjects()...)
	objs = append(objs,
		c.consoleManagerDeployment(),
		c.consoleManagerService(),
		c.tigeraUserClusterRole(),
		c.tigeraNetworkAdminClusterRole(),
	)

	// If we're running on openshift, we need to add in an SCC.
	if c.openshift {
		objs = append(objs, c.securityContextConstraints())
	}

	return objs
}

func (c *consoleComponent) Ready() bool {
	return true
}

// consoleManagerDeployment creates a deployment for the Tigera Secure console manager component.
func (c *consoleComponent) consoleManagerDeployment() *appsv1.Deployment {
	var replicas int32 = 1
	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cnx-manager",
			Namespace: ManagerNamespace,
			Labels: map[string]string{
				"k8s-app": "cnx-manager",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "cnx-manager",
				},
			},
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cnx-manager",
					Namespace: ManagerNamespace,
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
					Tolerations:        c.consoleTolerations(),
					ImagePullSecrets:   getImagePullSecretReferenceList(c.pullSecrets),
					Containers: []corev1.Container{
						c.consoleManagerContainer(),
						c.consoleEsProxyContainer(),
						c.consoleProxyContainer(),
					},
					Volumes: c.consoleManagerVolumes(),
				},
			},
		},
	}
	return d
}

// consoleManagerVolumes returns the volumes for the Tigera Secure console component.
func (c *consoleComponent) consoleManagerVolumes() []v1.Volume {
	optional := true
	return []v1.Volume{
		{
			Name: ManagerTLSSecretName,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: ManagerTLSSecretName,
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

// consoleManagerProbe returns the probe for the manager container.
func (c *consoleComponent) consoleManagerProbe() *v1.Probe {
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

// consoleEsProxyProbe returns the probe for the ES proxy container.
func (c *consoleComponent) consoleEsProxyProbe() *v1.Probe {
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

// consoleProxyProbe returns the probe for the proxy container.
func (c *consoleComponent) consoleProxyProbe() *v1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/voltron/api/health",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

// consoleManagerEnvVars returns the envvars for the console manager container.
func (c *consoleComponent) consoleManagerEnvVars() []v1.EnvVar {
	envs := []v1.EnvVar{
		{Name: "CNX_PROMETHEUS_API_URL", Value: "/api/v1/namespaces/calico-monitoring/services/calico-node-prometheus:9090/proxy/api/v1"},
		{Name: "CNX_COMPLIANCE_REPORTS_API_URL", Value: "/compliance/reports"},
		{Name: "CNX_QUERY_API_URL", Value: "/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy"},
		{Name: "CNX_ELASTICSEARCH_API_URL", Value: "/tigera-elasticsearch"},
		{Name: "CNX_ELASTICSEARCH_KIBANA_URL", Value: c.monitoring.Spec.Kibana.Endpoint},
		{Name: "CNX_ENABLE_ERROR_TRACKING", Value: "false"},
		{Name: "CNX_ALP_SUPPORT", Value: "false"},
		{Name: "CNX_CLUSTER_NAME", Value: "cluster"},
	}

	envs = append(envs, c.consoleOAuth2EnvVars()...)
	return envs
}

// consoleManagerContainer returns the manager container.
func (c *consoleComponent) consoleManagerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		{Name: "tigera-es-proxy-tls", MountPath: "/etc/ssl/elastic/"},
	}
	return corev1.Container{
		Name:          "cnx-manager",
		Image:         constructImage(ConsoleManagerImageName, c.registry),
		Env:           c.consoleManagerEnvVars(),
		VolumeMounts:  volumeMounts,
		LivenessProbe: c.consoleManagerProbe(),
	}
}

// consoleOAuth2EnvVars returns the OAuth2/OIDC envvars depending on the authentication type.
func (c *consoleComponent) consoleOAuth2EnvVars() []v1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: string(c.cr.Spec.Auth.Type)},
	}

	switch c.cr.Spec.Auth.Type {
	case operator.AuthTypeOIDC:
		oidcEnvs := []corev1.EnvVar{
			{Name: "CNX_WEB_OIDC_AUTHORITY", Value: c.cr.Spec.Auth.Authority},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: c.cr.Spec.Auth.ClientID},
		}
		envs = append(envs, oidcEnvs...)
	case operator.AuthTypeOAuth:
		oauthEnvs := []corev1.EnvVar{
			{Name: "CNX_WEB_OAUTH_AUTHORITY", Value: c.cr.Spec.Auth.Authority},
			{Name: "CNX_WEB_OAUTH_CLIENT_ID", Value: c.cr.Spec.Auth.ClientID},
		}
		envs = append(envs, oauthEnvs...)
	}
	return envs
}

// consoleProxyContainer returns the container for the console proxy container.
func (c *consoleComponent) consoleProxyContainer() corev1.Container {
	return corev1.Container{
		Name:  "tigera-voltron",
		Image: constructImage(ConsoleProxyImageName, c.registry),
		Env: []corev1.EnvVar{
			{Name: "VOLTRON_PORT",
				Value: "9443"},
			{Name: "VOLTRON_COMPLIANCE_ENDPOINT",
				Value: fmt.Sprintf("https://compliance.%s.svc", ComplianceNamespace)},
			{Name: "VOLTRON_LOG_LEVEL",
				Value: "info"},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: ManagerTLSSecretName, MountPath: "/certs/https"},
			{Name: ManagerTLSSecretName, MountPath: "/certs/tunnel"},
		},
		LivenessProbe: c.consoleProxyProbe(),
	}
}

// consoleEsProxyEnv returns the env vars for the ES proxy container.
func (c *consoleComponent) consoleEsProxyEnv() []corev1.EnvVar {
	scheme, host, port, err := ParseEndpoint(c.monitoring.Spec.Elasticsearch.Endpoint)
	if err != nil {
		panic(err)
	}
	return []corev1.EnvVar{
		{Name: "ELASTIC_HOST", Value: host},
		{Name: "ELASTIC_PORT", Value: port},
		{Name: "ELASTIC_ACCESS_MODE", Value: "insecure"}, // TODO: Do we ever set this to something else?
		{Name: "ELASTIC_SCHEME", Value: scheme},
		// TODO: make this configurable?
		{Name: "ELASTIC_INSECURE_SKIP_VERIFY", Value: "false"},
		// {
		// 	Name:      "ELASTIC_USERNAME",
		// 	ValueFrom: envVarSourceFromSecret(tigeraEsSecretName, "tigera.elasticsearch.username", Optional),
		// },
		// {
		// 	Name:      "ELASTIC_PASSWORD",
		// 	ValueFrom: envVarSourceFromSecret(tigeraEsSecretName, "tigera.elasticsearch.password", Optional),
		// },
		// {
		// 	Name:      "ELASTIC_CA",
		// 	ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.ca.path"),
		// },
	}
}

// consoleEsProxyContainer returns the ES proxy container
func (c *consoleComponent) consoleEsProxyContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		{Name: "tigera-es-proxy-tls", MountPath: "/etc/ssl/elastic/"},
	}
	apiServer := corev1.Container{
		Name:          "tigera-es-proxy",
		Image:         constructImage(ConsoleEsProxyImageName, c.registry),
		Env:           c.consoleEsProxyEnv(),
		VolumeMounts:  volumeMounts,
		LivenessProbe: c.consoleEsProxyProbe(),
	}

	return apiServer
}

// consoleTolerations returns the tolerations for the Tigera Secure console deployment pods.
func (c *consoleComponent) consoleTolerations() []v1.Toleration {
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

// consoleManagerService returns the service exposing the Tigera Secure web app.
func (c *consoleComponent) consoleManagerService() *v1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cnx-manager",
			Namespace: ManagerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       managerPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(managerTargetPort),
				},
			},
			Selector: map[string]string{
				"k8s-app": "cnx-manager",
			},
		},
	}
}

// consoleManagerServiceAccount creates the serviceaccount used by the Tigera Secure web app.
func (c *consoleComponent) consoleManagerServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "cnx-manager", Namespace: ManagerNamespace},
	}
}

// consoleManagerClusterRole returns a clusterrole that allows authn/authz review requests.
func (c *consoleComponent) consoleManagerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
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
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch"},
			},

		},
	}
}

// consoleManagerClusterRoleBinding returns a clusterrolebinding that gives the cnx-manager serviceaccount
// the permissions in the cnx-manager-role.
func (c *consoleComponent) consoleManagerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
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
				Namespace: ManagerNamespace,
			},
		},
	}
}

// tigeraUserClusterRole returns a cluster role for a default Tigera Secure user.
func (c *consoleComponent) tigeraUserClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
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
					"managedclusters",
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
			// List and download the reports in the Tigera Secure console.
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

// tigeraNetworkAdminClusterRole returns a cluster role for a Tigera Secure console network admin.
func (c *consoleComponent) tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
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
					"managedclusters",
				},
				Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
			},
			// Additional "list" requests that the Tigera Secure console needs
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
			// Manage globalreport configuration, view report generation status, and list reports in the Tigera Secure console.
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
			// List and download the reports in the Tigera Secure console.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"get"},
			},
		},
	}
}

// TODO: Can we get rid of this and instead just bind to default ones?
func (c *consoleComponent) securityContextConstraints() *ocsv1.SecurityContextConstraints {
	privilegeEscalation := false
	return &ocsv1.SecurityContextConstraints{
		TypeMeta:                 metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
		ObjectMeta:               metav1.ObjectMeta{Name: ManagerNamespace},
		AllowHostDirVolumePlugin: true,
		AllowHostIPC:             false,
		AllowHostNetwork:         false,
		AllowHostPID:             true,
		AllowHostPorts:           false,
		AllowPrivilegeEscalation: &privilegeEscalation,
		AllowPrivilegedContainer: false,
		FSGroup:                  ocsv1.FSGroupStrategyOptions{Type: ocsv1.FSGroupStrategyRunAsAny},
		RunAsUser:                ocsv1.RunAsUserStrategyOptions{Type: ocsv1.RunAsUserStrategyRunAsAny},
		ReadOnlyRootFilesystem:   false,
		SELinuxContext:           ocsv1.SELinuxContextStrategyOptions{Type: ocsv1.SELinuxStrategyMustRunAs},
		SupplementalGroups:       ocsv1.SupplementalGroupsStrategyOptions{Type: ocsv1.SupplementalGroupsStrategyRunAsAny},
		Users:                    []string{fmt.Sprintf("system:serviceaccount:%s:cnx-manager", ManagerNamespace)},
		Groups:                   []string{"system:authenticated"},
		Volumes:                  []ocsv1.FSType{"*"},
	}
}

func (c *consoleComponent) getTLSObjects() []runtime.Object {
	objs := []runtime.Object{}
	for _, s := range c.tlsSecrets {
		objs = append(objs, s)
	}

	return objs
}
