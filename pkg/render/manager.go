package render

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

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
	ManagerNamespace      = "tigera-manager"
	ManagerTLSSecretName  = "manager-tls"
	ManagerSecretKeyName  = "key"
	ManagerSecretCertName = "cert"

	ElasticsearchUserManager = "tigera-ee-manager"
	tlsSecretHashAnnotation  = "hash.operator.tigera.io/tls-secret"
)

const (
	// Use this annotation to enable the Policy Recommendation tech preview feature.
	// "tech-preview.operator.tigera.io/policy-recommendation: Enabled"
	techPreviewFeaturePolicyRecommendationAnnotation = "tech-preview.operator.tigera.io/policy-recommendation"

	// The lower case of the value that we look for to enable a tech preview feature.
	// The feature is disabled for all other values.
	techPreviewEnabledValue = "enabled"
)

// Multicluster configuration constants
const (
	VoltronName                 = "tigera-voltron"
	VoltronTunnelSecretName     = "voltron-tunnel"
	voltronTunnelHashAnnotation = "hash.operator.tigera.io/voltron-tunnel"
	defaultVoltronPort          = 9443
	defaultTunnelVoltronPort    = 9449
	voltronPortName             = "tunnels"
)

func Manager(
	cr *operator.Manager,
	esSecrets []*corev1.Secret,
	kibanaSecrets []*corev1.Secret,
	clusterName string,
	tlsKeyPair *corev1.Secret,
	pullSecrets []*corev1.Secret,
	openshift bool,
	registry string,
	mcmSpec *operator.MulticlusterConfigSpec,
	createVoltronTunnelSecret bool,
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
	// Overwrite the ObjectMeta to ensure we do not keep the resourceVersion or any other information
	// that should not be set on a new object.
	copy.ObjectMeta = metav1.ObjectMeta{Name: ManagerTLSSecretName, Namespace: ManagerNamespace}
	tlsSecrets = append(tlsSecrets, copy)

	// Extract the mcm configuration if a spec was found
	management := false
	voltronAddr := ""
	voltronPort := 0
	if mcmSpec != nil {
		management = mcmSpec.ClusterManagementType == "management"
		voltronAddr = mcmSpec.ManagementClusterAddr
		voltronPort = mcmSpec.ManagementClusterPort
	}

	return &managerComponent{
		cr:                        cr,
		esSecrets:                 esSecrets,
		kibanaSecrets:             kibanaSecrets,
		clusterName:               clusterName,
		tlsSecrets:                tlsSecrets,
		pullSecrets:               pullSecrets,
		openshift:                 openshift,
		registry:                  registry,
		management:                management,
		voltronAddr:               voltronAddr,
		voltronPort:               voltronPort,
		createVoltronTunnelSecret: createVoltronTunnelSecret,
	}, nil
}

type managerComponent struct {
	cr                        *operator.Manager
	esSecrets                 []*corev1.Secret
	kibanaSecrets             []*corev1.Secret
	clusterName               string
	tlsSecrets                []*corev1.Secret
	pullSecrets               []*corev1.Secret
	openshift                 bool
	registry                  string
	management                bool
	voltronAddr               string
	voltronPort               int
	createVoltronTunnelSecret bool
}

func (c *managerComponent) Objects() []runtime.Object {
	objs := []runtime.Object{
		createNamespace(ManagerNamespace, c.openshift),
	}

	var voltronAnnotation string
	if c.management {
		objs = append(objs, c.voltronTunnelService())
		if c.createVoltronTunnelSecret {
			voltronTunnelSecret := c.voltronTunnelSecret()
			voltronAnnotation = AnnotationHash(voltronTunnelSecret.Data)
			objs = append(objs, voltronTunnelSecret)
		}
	}

	objs = append(objs, copyImagePullSecrets(c.pullSecrets, ManagerNamespace)...)
	objs = append(objs,
		c.managerServiceAccount(),
		c.managerClusterRole(),
		c.managerClusterRoleBinding(),
		c.managerPolicyImpactPreviewClusterRole(),
		c.managerPolicyImpactPreviewClusterRoleBinding(),
	)
	objs = append(objs, c.getTLSObjects()...)
	objs = append(objs,
		c.managerDeployment(voltronAnnotation),
		c.managerService(),
		c.tigeraUserClusterRole(),
		c.tigeraNetworkAdminClusterRole(),
	)

	// If we're running on openshift, we need to add in an SCC.
	if c.openshift {
		objs = append(objs, c.securityContextConstraints())
	}
	objs = append(objs, copySecrets(ManagerNamespace, c.esSecrets...)...)
	objs = append(objs, copySecrets(ManagerNamespace, c.kibanaSecrets...)...)

	return objs
}

func (c *managerComponent) Ready() bool {
	return true
}

// managerDeployment creates a deployment for the Tigera Secure manager component.
func (c *managerComponent) managerDeployment(voltronAnnotation string) *appsv1.Deployment {
	var replicas int32 = 1
	annotations := map[string]string{
		// Mark this pod as a critical add-on; when enabled, the critical add-on scheduler
		// reserves resources for critical add-on pods so that they can be rescheduled after
		// a failure.  This annotation works in tandem with the toleration below.
		"scheduler.alpha.kubernetes.io/critical-pod": "",
	}
	if len(c.tlsSecrets) > 0 {
		// Add a hash of the Secret to ensure if it changes the manager will be
		// redeployed.
		annotations[tlsSecretHashAnnotation] = AnnotationHash(c.tlsSecrets[0].Data)
	}
	if c.management && voltronAnnotation != "" {
		annotations[voltronTunnelHashAnnotation] = voltronAnnotation //TODO: figure this out.
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-manager",
			Namespace: ManagerNamespace,
			Labels: map[string]string{
				"k8s-app": "tigera-manager",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "tigera-manager",
				},
			},
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-manager",
					Namespace: ManagerNamespace,
					Labels: map[string]string{
						"k8s-app": "tigera-manager",
					},
					Annotations: annotations,
				},
				Spec: ElasticsearchPodSpecDecorate(corev1.PodSpec{
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					ServiceAccountName: "tigera-manager",
					Tolerations:        c.managerTolerations(),
					ImagePullSecrets:   getImagePullSecretReferenceList(c.pullSecrets),
					Containers: []corev1.Container{
						ElasticsearchContainerDecorate(c.managerContainer(), c.clusterName, ElasticsearchUserManager),
						ElasticsearchContainerDecorate(c.managerEsProxyContainer(), c.clusterName, ElasticsearchUserManager),
						c.managerProxyContainer(),
					},
					Volumes: c.managerVolumes(),
				}),
			},
		},
	}
	return d
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumes() []v1.Volume {
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
			Name: KibanaPublicCertSecret,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: KibanaPublicCertSecret,
				},
			},
		},
		{
			Name: VoltronTunnelSecretName,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: VoltronTunnelSecretName,
					Optional:   &optional,
				},
			},
		},
	}
}

// managerProbe returns the probe for the manager container.
func (c *managerComponent) managerProbe() *v1.Probe {
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

// managerEsProxyProbe returns the probe for the ES proxy container.
func (c *managerComponent) managerEsProxyProbe() *v1.Probe {
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

// managerProxyProbe returns the probe for the proxy container.
func (c *managerComponent) managerProxyProbe() *v1.Probe {
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

// managerEnvVars returns the envvars for the manager container.
func (c *managerComponent) managerEnvVars() []v1.EnvVar {
	envs := []v1.EnvVar{
		{Name: "CNX_PROMETHEUS_API_URL", Value: fmt.Sprintf("/api/v1/namespaces/%s/services/calico-node-prometheus:9090/proxy/api/v1", TigeraPrometheusNamespace)},
		{Name: "CNX_COMPLIANCE_REPORTS_API_URL", Value: "/compliance/reports"},
		{Name: "CNX_QUERY_API_URL", Value: "/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy"},
		{Name: "CNX_ELASTICSEARCH_API_URL", Value: "/tigera-elasticsearch"},
		{Name: "CNX_ELASTICSEARCH_KIBANA_URL", Value: fmt.Sprintf("/%s", KibanaBasePath)},
		{Name: "CNX_ENABLE_ERROR_TRACKING", Value: "false"},
		{Name: "CNX_ALP_SUPPORT", Value: "true"},
		{Name: "CNX_CLUSTER_NAME", Value: "cluster"},
		{Name: "CNX_POLICY_RECOMMENDATION_SUPPORT", Value: c.policyRecommendationSupport()},
		{Name: "ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.management)},
	}

	envs = append(envs, c.managerOAuth2EnvVars()...)
	return envs
}

// managerContainer returns the manager container.
func (c *managerComponent) managerContainer() corev1.Container {
	return corev1.Container{
		Name:            "tigera-manager",
		Image:           constructImage(ManagerImageName, c.registry),
		Env:             c.managerEnvVars(),
		LivenessProbe:   c.managerProbe(),
		SecurityContext: securityContext(),
	}
}

// managerOAuth2EnvVars returns the OAuth2/OIDC envvars depending on the authentication type.
func (c *managerComponent) managerOAuth2EnvVars() []v1.EnvVar {
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

// managerProxyContainer returns the container for the manager proxy container.
func (c *managerComponent) managerProxyContainer() corev1.Container {
	return corev1.Container{
		Name:  VoltronName,
		Image: constructImage(ManagerProxyImageName, c.registry),
		Env: []corev1.EnvVar{
			{Name: "VOLTRON_PORT", Value: strconv.Itoa(defaultVoltronPort)},
			{Name: "VOLTRON_COMPLIANCE_ENDPOINT", Value: fmt.Sprintf("https://compliance.%s.svc", ComplianceNamespace)},
			{Name: "VOLTRON_LOGLEVEL", Value: "info"},
			{Name: "VOLTRON_KIBANA_ENDPOINT", Value: KibanaHTTPSEndpoint},
			{Name: "VOLTRON_KIBANA_BASE_PATH", Value: fmt.Sprintf("/%s/", KibanaBasePath)},
			{Name: "VOLTRON_KIBANA_CA_BUNDLE_PATH", Value: "/certs/kibana/tls.crt"},
			{Name: "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.management)},
			{Name: "VOLTRON_PUBLIC_IP", Value: fmt.Sprintf("%s:%d", c.voltronAddr, c.voltronPort)},
			{Name: "VOLTRON_TUNNEL_PORT", Value: fmt.Sprintf("%d", defaultTunnelVoltronPort)},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: ManagerTLSSecretName, MountPath: "/certs/https"},
			{Name: KibanaPublicCertSecret, MountPath: "/certs/kibana"},
			{Name: VoltronTunnelSecretName, MountPath: "/certs/tunnel/"},
		},
		LivenessProbe:   c.managerProxyProbe(),
		SecurityContext: securityContext(),
	}
}

// managerEsProxyContainer returns the ES proxy container
func (c *managerComponent) managerEsProxyContainer() corev1.Container {
	apiServer := corev1.Container{
		Name:            "tigera-es-proxy",
		Image:           constructImage(ManagerEsProxyImageName, c.registry),
		LivenessProbe:   c.managerEsProxyProbe(),
		SecurityContext: securityContext(),
	}

	return apiServer
}

// managerTolerations returns the tolerations for the Tigera Secure manager deployment pods.
func (c *managerComponent) managerTolerations() []v1.Toleration {
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

// managerService returns the service exposing the Tigera Secure web app.
func (c *managerComponent) managerService() *v1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-manager",
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
				"k8s-app": "tigera-manager",
			},
		},
	}
}

// managerService returns the service exposing the Tigera Secure web app.
func (c *managerComponent) voltronTunnelSecret() *v1.Secret {

	//TODO: Placeholder secret. SAAS-471
	cert, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQrVENDQXVHZ0F3SUJBZ0lVQmFXenB2ZzlVckVzaUF4SExEMllmWVFGcFFVd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2dZc3hDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwRFlXeHBabTl5Ym1saE1SWXdGQVlEVlFRSApEQTFUWVc0Z1JuSmhibU5wYzJOdk1SUXdFZ1lEVlFRS0RBdFVhV2RsY21Fc0lFbHVZekVYTUJVR0ExVUVBd3dPCmRHbG5aWEpoTFhadmJIUnliMjR4SURBZUJna3Foa2lHOXcwQkNRRVdFV052Ym5SaFkzUkFkR2xuWlhKaExtbHYKTUI0WERURTVNVEV4TXpBeU1URXlNRm9YRFRJd01URXhNakF5TVRFeU1Gb3dnWXN4Q3pBSkJnTlZCQVlUQWxWVApNUk13RVFZRFZRUUlEQXBEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIREExVFlXNGdSbkpoYm1OcGMyTnZNUlF3CkVnWURWUVFLREF0VWFXZGxjbUVzSUVsdVl6RVhNQlVHQTFVRUF3d09kR2xuWlhKaExYWnZiSFJ5YjI0eElEQWUKQmdrcWhraUc5dzBCQ1FFV0VXTnZiblJoWTNSQWRHbG5aWEpoTG1sdk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRgpBQU9DQVE4QU1JSUJDZ0tDQVFFQXNWNm1IdWdZeDBaQkN5U1VNQU1XWThESUxBbjlseGhBa0tyNStIa0ttQU1mCkRrMTkwVjNwdXNFUEg5TlovYnlBT08rUG9qakpnSTFuMzdJY09OQlRvVjdXVWR6Qk16eGpGZWwzSkJMdHo4bVYKb2YxVHMwVEFRZGI3R2xBYjNORTRHdmtCWno3Vkk2YWE1bnc4SGlWVlp1UjJNNHlOejJKek1OTUFzRnpDNk5tNQpRVU1UcnY0b3lkSTZ5cXQ0R0h3anlISVhBVWt0K3RzKy9RRjgxK1NXTkNGRWM2VTZlcjdsS013MFpwN21PWUpvCm4zWEpJWmJIMjJUcnFnNUtzTXZwVW1NSVd1d2VJZ053RGlJUDhZZ2NOZUc1YlA2eU5hc21PZ0hSbHN5a0M5MGYKaTFzenpSbTIyTlBiYjhENi9Vc1E5MHpoaUg4djRKVkFuT3BHdStrZnNRSURBUUFCbzFNd1VUQVNCZ05WSFJFRQpDekFKZ2dkMmIyeDBjbTl1TUIwR0ExVWREZ1FXQkJRdWhqRTVoUmo3dEEvak9FMmh3YlpucWJrL2RqQVBCZ05WCkhSTUJBZjhFQlRBREFRSC9NQXNHQTFVZER3UUVBd0lDNURBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQWdiVUEKWWlCRFhMUllkRXlVQ3c5RDl3b1hEVEdXcU8rZWQzRUFvNU1wLzRKSmgwSEY2eHhrV0ZaaUtMNGQrSkNOSWVMRgo0MTlhalFZWnFuWTN1cHV6TmY2YVhKaHc2SG52bEV4Z1l1aERJSm1wOWI5N2tDdzZaMFFDaTJiak9qTUlyVGgzClJEa1VuajZjMVZyNGJYZXNIc1JUbmNtdWdZRFRYdU44bUhRbDQ0RjE3NTkzTUJxMXlrSGQrUHJDMnVOa1pNOTgKTlJDZCtVWWcwSHM3MENLTHJXbHIvaStxWEJEYzhWOUxYaGl5OWkrNSs4RXZLVlVCSVVkb0g5UVE0NGh1VWQ5MQpIMzNvZVZYMWlRM09lZFRPOUlGMW5BVUp0NW1SVzRxU09xTys3UXhZUTJTdjRUdXRvc3FYNzQzRzZvWEhmV2hTCk1YeXZ5N1JTR2hUeWVJMFpCQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K")
	key, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBc1Y2bUh1Z1l4MFpCQ3lTVU1BTVdZOERJTEFuOWx4aEFrS3I1K0hrS21BTWZEazE5CjBWM3B1c0VQSDlOWi9ieUFPTytQb2pqSmdJMW4zN0ljT05CVG9WN1dVZHpCTXp4akZlbDNKQkx0ejhtVm9mMVQKczBUQVFkYjdHbEFiM05FNEd2a0JaejdWSTZhYTVudzhIaVZWWnVSMk00eU56Mkp6TU5NQXNGekM2Tm01UVVNVApydjRveWRJNnlxdDRHSHdqeUhJWEFVa3QrdHMrL1FGODErU1dOQ0ZFYzZVNmVyN2xLTXcwWnA3bU9ZSm9uM1hKCklaYkgyMlRycWc1S3NNdnBVbU1JV3V3ZUlnTndEaUlQOFlnY05lRzViUDZ5TmFzbU9nSFJsc3lrQzkwZmkxc3oKelJtMjJOUGJiOEQ2L1VzUTkwemhpSDh2NEpWQW5PcEd1K2tmc1FJREFRQUJBb0lCQUFFd0tCNjI0VXVjYmQwYwpQcDNmdDJ1dG8rbWZtNEpDbUZRZndSTG9CS2ttQkRROVVxVnZZcHhzcEtSSzd5UmkrZHpueGVlSlI5aERtam1HCllPZ0VoVHJrZnIwSHBJZXFWT09WcjhXZkZ0YTRlL2NjMGsyMkhTK1R1QlRpQ24yOUxRb0pOdmd4Rkk1cmxFZ00KOXY0Z3MrUy9qUWNsWHVIUHdBUEl0ZzE0WVpuYnNLSTB4SWtCS0x0MVRqL0NMWjY1LytHMkdjbUVtVjJtWUVBQQpjcjFUSXRQQk9IWlhMTWpXbEQ4UXNMSmNNYytCdkNtUVNyZU1BODNKMHRmSTRvUnlBWmgxQndVNDhRK3NUQ0grCm9GczFRQkNJMityejBPZzZRRUI3YjFSdTdRRVZIK08rcDAwNFB2aEZZUk13bzJHdDZnZmg4R2c4b2szY1AwcEwKWU9IOVFiMENnWUVBN0hVMTJjL29vY1ZKL2o3ZmltTmZLZCs0RklSK1VxbXl3UzhMb0dZdjFESXlmSmNBY1diRQpWa3ArUXFVb2tYT1JTVVRua0IvWHJvbnRHREkvT3RjQmhqRVhIekNsVnh2a0wzNFczS2p3aDBNcUVyRG5ZQ0E1CjFOVmUzY2c5VU1Rd0pwS0YrYkVXWElianBXQUVGVExrZER0cng2UzRNTHpLSjVNNjFkTjVXWmNDZ1lFQXdBZE0KV3o1UWxCSHNIKzlEMWRxbi9pamg5TGJocXNWYXN6dkVjZHgrYjlrVnVZb01neGZaUlFRKzYrVVk3YnNnak0rQQpwWkRGNUYzdWExQlFWL2ZQQjA1ckgwQjFRM1ZMR2VlbjNIM2pPMFQ4TXN5VEIycDlTTTB6cm4xYWxsWXQzUTZzCjlvbm9hdTRFYTJEMlM2ZlNxYTU4REYvMmY3bnNQOHJtSnplcHFmY0NnWUJuVzhqQlArODVIMHI3dHJIeUJRUHAKQXVDdEgwazBpdmNYR0tCbGFhV0loTFNxM3pxVFYwK0ZSS1N5THcxdm51dW44bFdpR3prbEV5Y3ZSMjk2SWRlSgp0OVdhamFJSVZLbkcxTC9iam9FdEx2K3FFZWZoamRTWm92Y0h6T3A0Ym5sNXN0eWJTM3d4ejhpY1ZqOFNvUjlaCmEwdnVoYUw1c3R4T3RqMm1qL3pnV3dLQmdGc2NXMTlEZnNueWd2MVg4ZkNxMFdCbkYyYWJ5eERTbU1sSHgxcGEKeXViWXNsVVpLZnlkT1NwazdGSFNublJWZ0FrdmZ4T1BVRVdkUjcxRkd3blIrem0xUEdCVW5nN0d2VDVxU3B2MApZdmRCTVFRTlNvbVBQaWhuckdqUzgwTTNXb1Z6TEIvQnFUUHJBTS9ON3E1UXowUlJGR3h1cjY5RWtOSm51N0hKCjJFZGJBb0dCQUpIR3BEa1Rwc1c1ZmJidEh2Y1hxcmVjdlFLM2RaNFBNNmRhWHFJeWZCVmxQNmVDeWJLZnBlMysKV1dacUNiZnlHYmhKakpNbm9CSk1mWUJxSGFwMTAzWkR5dk1XRzZodkFUdSswb3hVdkJuWTRKcGpqeGE4QVcySQpDd093WndBZjJwa3Nzd2psOE1tSmVQSmFOK0lTandvM2ZOUTIvbUtPZS9PcjJLUUlYVDZKCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==")

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      VoltronTunnelSecretName,
			Namespace: ManagerNamespace,
		},
		Data: map[string][]byte{
			"cert": []byte(cert),
			"key":  []byte(key),
		},
	}
}

// managerService returns the service exposing the Tigera Secure web app.
func (c *managerComponent) voltronTunnelService() *v1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      VoltronName,
			Namespace: ManagerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Port:     defaultTunnelVoltronPort,
					NodePort: int32(c.voltronPort),
					Protocol: corev1.ProtocolTCP,
					Name:     voltronPortName,
				},
			},
			Selector: map[string]string{
				"k8s-app": "tigera-manager",
			},
		},
	}
}

// managerServiceAccount creates the serviceaccount used by the Tigera Secure web app.
func (c *managerComponent) managerServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: ManagerNamespace},
	}
}

// managerClusterRole returns a clusterrole that allows authn/authz review requests.
func (c *managerComponent) managerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-manager-role",
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

// managerClusterRoleBinding returns a clusterrolebinding that gives the tigera-manager serviceaccount
// the permissions in the tigera-manager-role.
func (c *managerComponent) managerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-binding"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-manager-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-manager",
				Namespace: ManagerNamespace,
			},
		},
	}
}

// managerClusterRole returns a clusterrole that allows authn/authz review requests.
func (c *managerComponent) managerPolicyImpactPreviewClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-manager-pip",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"networksets",
					"globalnetworksets",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"networkpolicies",
					"tier.networkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get", "list"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces"},
				Verbs:     []string{"list"},
			},
		},
	}
}

func (c *managerComponent) managerPolicyImpactPreviewClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-pip"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-manager-pip",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-manager",
				Namespace: ManagerNamespace,
			},
		},
	}
}

// tigeraUserClusterRole returns a cluster role for a default Tigera Secure user.
func (c *managerComponent) tigeraUserClusterRole() *rbacv1.ClusterRole {
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
				// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
				// irrespective of the Calico RBAC scheme (see the ClusterRole "ee-calico-tiered-policy-passthru" for
				// more details).  Similar for all tiered policy resource types.
				Resources: []string{
					"tiers",
					"networkpolicies",
					"tier.networkpolicies",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"namespaces",
					"globalnetworksets",
					"networksets",
					"managedclusters",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
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
					"flows", "audit*", "events", "dns",
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
			// List and download the reports in the Tigera Secure manager.
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
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
}

// tigeraNetworkAdminClusterRole returns a cluster role for a Tigera Secure manager network admin.
func (c *managerComponent) tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
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
				// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
				// irrespective of the Calico RBAC scheme (see the ClusterRole "ee-calico-tiered-policy-passthru" for
				// more details).  Similar for all tiered policy resource types.
				Resources: []string{
					"tiers",
					"networkpolicies",
					"tier.networkpolicies",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"stagedglobalnetworkpolicies",
					"tier.stagedglobalnetworkpolicies",
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
					"stagedkubernetesnetworkpolicies",
					"globalnetworksets",
					"networksets",
					"managedclusters",
				},
				Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
			},
			// Additional "list" requests that the Tigera Secure manager needs
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
					"flows", "audit*", "events", "dns",
				},
				Verbs: []string{"get"},
			},
			// Manage globalreport configuration, view report generation status, and list reports in the Tigera Secure manager.
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
			// List and download the reports in the Tigera Secure manager.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"get"},
			},
			// Access to cluster information containing Calico and EE versions from the UI.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
}

// TODO: Can we get rid of this and instead just bind to default ones?
func (c *managerComponent) securityContextConstraints() *ocsv1.SecurityContextConstraints {
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
		Users:                    []string{fmt.Sprintf("system:serviceaccount:%s:tigera-manager", ManagerNamespace)},
		Groups:                   []string{"system:authenticated"},
		Volumes:                  []ocsv1.FSType{"*"},
	}
}

func (c *managerComponent) getTLSObjects() []runtime.Object {
	objs := []runtime.Object{}
	for _, s := range c.tlsSecrets {
		objs = append(objs, s)
	}

	return objs
}

func (c *managerComponent) policyRecommendationSupport() string {
	supported := "false"
	a := c.cr.GetObjectMeta().GetAnnotations()
	if val, ok := a[techPreviewFeaturePolicyRecommendationAnnotation]; ok && strings.ToLower(val) == techPreviewEnabledValue {
		supported = "true"
	}
	return supported
}
