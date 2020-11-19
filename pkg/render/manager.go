// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"strconv"
	"time"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"

	ocsv1 "github.com/openshift/api/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	managerPort                      = 9443
	managerTargetPort                = 9443
	ManagerNamespace                 = "tigera-manager"
	ManagerServiceDNS                = "tigera-manager.tigera-manager.svc"
	ManagerServiceIP                 = "localhost"
	ManagerServiceAccount            = "tigera-manager"
	ManagerClusterRole               = "tigera-manager-role"
	ManagerClusterRoleBinding        = "tigera-manager-binding"
	ManagerTLSSecretName             = "manager-tls"
	ManagerSecretKeyName             = "key"
	ManagerSecretCertName            = "cert"
	ManagerInternalTLSSecretName     = "internal-manager-tls"
	ManagerInternalTLSSecretCertName = "internal-manager-tls-cert"
	ManagerInternalSecretKeyName     = "key"
	ManagerInternalSecretCertName    = "cert"
	ManagerOIDCConfig                = "tigera-manager-oidc-config"

	ElasticsearchManagerUserSecret   = "tigera-ee-manager-elasticsearch-access"
	tlsSecretHashAnnotation          = "hash.operator.tigera.io/tls-secret"
	ManagerInternalTLSHashAnnotation = "hash.operator.tigera.io/internal-tls-secret"
)

// ManagementClusterConnection configuration constants
const (
	VoltronName                 = "tigera-voltron"
	VoltronTunnelSecretName     = "tigera-management-cluster-connection"
	VoltronTunnelSecretCertName = "cert"
	VoltronTunnelSecretKeyName  = "key"
	voltronTunnelHashAnnotation = "hash.operator.tigera.io/voltron-tunnel"
	defaultVoltronPort          = "9443"
	defaultTunnelVoltronPort    = "9449"
)

func Manager(
	dexCfg DexKeyValidatorConfig,
	esSecrets []*corev1.Secret,
	kibanaSecrets []*corev1.Secret,
	complianceServerCertSecret *corev1.Secret,
	esClusterConfig *ElasticsearchClusterConfig,
	tlsKeyPair *corev1.Secret,
	pullSecrets []*corev1.Secret,
	openshift bool,
	installation *operator.InstallationSpec,
	managementCluster *operator.ManagementCluster,
	tunnelSecret *corev1.Secret,
	internalTrafficSecret *corev1.Secret,
) (Component, error) {
	tlsSecrets := []*corev1.Secret{}

	if tlsKeyPair == nil {
		var err error
		tlsKeyPair, err = CreateOperatorTLSSecret(nil,
			ManagerTLSSecretName,
			ManagerSecretKeyName,
			ManagerSecretCertName,
			825*24*time.Hour, // 825days*24hours: Create cert with a max expiration that macOS 10.15 will accept
			nil,
		)
		if err != nil {
			return nil, err
		}
		tlsSecrets = []*corev1.Secret{tlsKeyPair}
	}

	tlsSecrets = append(tlsSecrets, CopySecrets(ManagerNamespace, tlsKeyPair)...)
	tlsAnnotations := make(map[string]string)

	if dexCfg != nil {
		tlsSecrets = append(tlsSecrets, dexCfg.RequiredSecrets(ManagerNamespace)...)
		tlsAnnotations = dexCfg.RequiredAnnotations()
	}
	tlsAnnotations[tlsSecretHashAnnotation] = AnnotationHash(tlsKeyPair.Data)

	if managementCluster != nil {
		// Copy tunnelSecret and internalTrafficSecret to TLS secrets
		// tunnelSecret contains the ca cert to generate guardian certificates
		// internalTrafficCert containts the cert used to communicated within the management K8S cluster
		tlsSecrets = append(tlsSecrets, CopySecrets(ManagerNamespace, tunnelSecret)...)
		tlsSecrets = append(tlsSecrets, CopySecrets(ManagerNamespace, internalTrafficSecret)...)
		tlsAnnotations[voltronTunnelHashAnnotation] = AnnotationHash(tunnelSecret.Data)
		tlsAnnotations[ManagerInternalTLSHashAnnotation] = AnnotationHash(internalTrafficSecret.Data)
	}
	return &managerComponent{
		dexCfg:                     dexCfg,
		esSecrets:                  esSecrets,
		kibanaSecrets:              kibanaSecrets,
		complianceServerCertSecret: complianceServerCertSecret,
		esClusterConfig:            esClusterConfig,
		tlsSecrets:                 tlsSecrets,
		tlsAnnotations:             tlsAnnotations,
		pullSecrets:                pullSecrets,
		openshift:                  openshift,
		installation:               installation,
		managementCluster:          managementCluster,
	}, nil
}

type managerComponent struct {
	dexCfg                     DexKeyValidatorConfig
	esSecrets                  []*corev1.Secret
	kibanaSecrets              []*corev1.Secret
	complianceServerCertSecret *corev1.Secret
	esClusterConfig            *ElasticsearchClusterConfig
	tlsSecrets                 []*corev1.Secret
	tlsAnnotations             map[string]string
	pullSecrets                []*corev1.Secret
	openshift                  bool
	installation               *operator.InstallationSpec
	managementCluster          *operator.ManagementCluster
}

func (c *managerComponent) SupportedOSType() OSType {
	return OSTypeLinux
}

func (c *managerComponent) Objects() ([]runtime.Object, []runtime.Object) {
	objs := []runtime.Object{
		createNamespace(ManagerNamespace, c.openshift),
	}
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, ManagerNamespace)...)

	// TODO: move copying of imagePullSecrets for prometheus into a dedicated prometheus controller
	// once one is introduced.
	// note that the TigeraPrometheusNamespace is not created by the operator but rather a dependency
	// (as is all prometheus resources).
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, common.TigeraPrometheusNamespace)...)

	objs = append(objs,
		managerServiceAccount(),
		managerClusterRole(c.managementCluster != nil, false, c.openshift),
		managerClusterRoleBinding(),
	)
	objs = append(objs, c.getTLSObjects()...)
	objs = append(objs,
		c.managerService(),
	)

	// If we're running on openshift, we need to add in an SCC.
	if c.openshift {
		objs = append(objs, c.securityContextConstraints())
	} else {
		// If we're not running openshift, we need to add pod security policies.
		objs = append(objs, c.managerPodSecurityPolicy())
	}
	objs = append(objs, secretsToRuntimeObjects(CopySecrets(ManagerNamespace, c.esSecrets...)...)...)
	objs = append(objs, secretsToRuntimeObjects(CopySecrets(ManagerNamespace, c.kibanaSecrets...)...)...)
	objs = append(objs, secretsToRuntimeObjects(CopySecrets(ManagerNamespace, c.complianceServerCertSecret)...)...)
	objs = append(objs, c.managerDeployment())

	return objs, nil
}

func (c *managerComponent) Ready() bool {
	return true
}

// managerDeployment creates a deployment for the Tigera Secure manager component.
func (c *managerComponent) managerDeployment() *appsv1.Deployment {
	var replicas int32 = 1
	annotations := map[string]string{
		// Mark this pod as a critical add-on; when enabled, the critical add-on scheduler
		// reserves resources for critical add-on pods so that they can be rescheduled after
		// a failure.  This annotation works in tandem with the toleration below.
		"scheduler.alpha.kubernetes.io/critical-pod": "",
		complianceServerTLSHashAnnotation:            AnnotationHash(c.complianceServerCertSecret.Data),
	}

	// Add a hash of the Secret to ensure if it changes the manager will be
	// redeployed.	The following secrets are annotated:
	// manager-tls : cert used for tigera UI
	// internal-manager-tls : cert used for internal communication within K8S cluster
	// tigera-management-cluster-connection : cert used to generate guardian certificates
	for k, v := range c.tlsAnnotations {
		annotations[k] = v
	}

	podTemplate := ElasticsearchDecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-manager",
			Namespace: ManagerNamespace,
			Labels: map[string]string{
				"k8s-app": "tigera-manager",
			},
			Annotations: annotations,
		},
		Spec: ElasticsearchPodSpecDecorate(corev1.PodSpec{
			ServiceAccountName: ManagerServiceAccount,
			Tolerations:        c.managerTolerations(),
			ImagePullSecrets:   getImagePullSecretReferenceList(c.pullSecrets),
			Containers: []corev1.Container{
				ElasticsearchContainerDecorate(c.managerContainer(), c.esClusterConfig.ClusterName(), ElasticsearchManagerUserSecret),
				ElasticsearchContainerDecorate(c.managerEsProxyContainer(), c.esClusterConfig.ClusterName(), ElasticsearchManagerUserSecret),
				c.managerProxyContainer(),
			},
			Volumes: c.managerVolumes(),
		}),
	}, c.esClusterConfig, c.esSecrets).(*corev1.PodTemplateSpec)

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
			Template: *podTemplate,
		},
	}
	return d
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumes() []v1.Volume {
	v := []v1.Volume{
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
			Name: ComplianceServerCertSecret,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					Items: []v1.KeyToPath{{
						Key:  "tls.crt",
						Path: "tls.crt",
					}},
					SecretName: ComplianceServerCertSecret,
				},
			},
		},
	}

	if c.managementCluster != nil {
		v = append(v,
			v1.Volume{
				// We only want to mount the cert, not the private key to es-proxy to establish a connection with voltron.
				Name: ManagerInternalTLSSecretCertName,
				VolumeSource: v1.VolumeSource{
					Secret: &v1.SecretVolumeSource{
						SecretName: ManagerInternalTLSSecretName,
						Items: []v1.KeyToPath{
							{
								Key:  "cert",
								Path: "cert",
							},
						},
					},
				},
			},
			v1.Volume{
				// We mount the full secret to be shared with Voltron.
				Name: ManagerInternalTLSSecretName,
				VolumeSource: v1.VolumeSource{
					Secret: &v1.SecretVolumeSource{
						SecretName: ManagerInternalTLSSecretName,
					},
				},
			},
			v1.Volume{
				// Append volume for tunnel certificate
				Name: VoltronTunnelSecretName,
				VolumeSource: v1.VolumeSource{
					Secret: &v1.SecretVolumeSource{
						SecretName: VoltronTunnelSecretName,
					},
				},
			},
		)
	}
	if c.dexCfg != nil {
		v = append(v, c.dexCfg.RequiredVolumes()...)
	}

	return v
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
		{Name: "CNX_PROMETHEUS_API_URL", Value: fmt.Sprintf("/api/v1/namespaces/%s/services/calico-node-prometheus:9090/proxy/api/v1", common.TigeraPrometheusNamespace)},
		{Name: "CNX_COMPLIANCE_REPORTS_API_URL", Value: "/compliance/reports"},
		{Name: "CNX_QUERY_API_URL", Value: "/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy"},
		{Name: "CNX_ELASTICSEARCH_API_URL", Value: "/tigera-elasticsearch"},
		{Name: "CNX_ELASTICSEARCH_KIBANA_URL", Value: fmt.Sprintf("/%s", KibanaBasePath)},
		{Name: "CNX_ENABLE_ERROR_TRACKING", Value: "false"},
		{Name: "CNX_ALP_SUPPORT", Value: "true"},
		{Name: "CNX_CLUSTER_NAME", Value: "cluster"},
		{Name: "CNX_POLICY_RECOMMENDATION_SUPPORT", Value: "true"},
		{Name: "ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.managementCluster != nil)},
	}

	envs = append(envs, c.managerOAuth2EnvVars()...)
	return envs
}

// managerContainer returns the manager container.
func (c *managerComponent) managerContainer() corev1.Container {
	tm := corev1.Container{
		Name:            "tigera-manager",
		Image:           components.GetReference(components.ComponentManager, c.installation.Registry, c.installation.ImagePath),
		Env:             c.managerEnvVars(),
		LivenessProbe:   c.managerProbe(),
		SecurityContext: securityContext(),
	}

	return tm
}

// managerOAuth2EnvVars returns the OAuth2/OIDC envvars depending on the authentication type.
func (c *managerComponent) managerOAuth2EnvVars() []v1.EnvVar {
	var envs []corev1.EnvVar

	if c.dexCfg == nil {
		envs = []corev1.EnvVar{{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "Token"}}
	} else {
		envs = []corev1.EnvVar{
			{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "OIDC"},
			{Name: "CNX_WEB_OIDC_AUTHORITY", Value: fmt.Sprintf("%s/dex", c.dexCfg.ManagerURI())},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: DexClientId}}
	}
	return envs
}

// managerProxyContainer returns the container for the manager proxy container.
func (c *managerComponent) managerProxyContainer() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "VOLTRON_PORT", Value: defaultVoltronPort},
		{Name: "VOLTRON_COMPLIANCE_ENDPOINT", Value: fmt.Sprintf("https://compliance.%s.svc", ComplianceNamespace)},
		{Name: "VOLTRON_LOGLEVEL", Value: "info"},
		{Name: "VOLTRON_KIBANA_ENDPOINT", Value: KibanaHTTPSEndpoint},
		{Name: "VOLTRON_KIBANA_BASE_PATH", Value: fmt.Sprintf("/%s/", KibanaBasePath)},
		{Name: "VOLTRON_KIBANA_CA_BUNDLE_PATH", Value: "/certs/kibana/tls.crt"},
		{Name: "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.managementCluster != nil)},
		{Name: "VOLTRON_TUNNEL_PORT", Value: defaultTunnelVoltronPort},
	}

	if c.dexCfg != nil {
		env = append(env, c.dexCfg.RequiredEnv("VOLTRON_")...)
	}

	return corev1.Container{
		Name:            VoltronName,
		Image:           components.GetReference(components.ComponentManagerProxy, c.installation.Registry, c.installation.ImagePath),
		Env:             env,
		VolumeMounts:    c.volumeMountsForProxyManager(),
		LivenessProbe:   c.managerProxyProbe(),
		SecurityContext: securityContext(),
	}
}

func (c *managerComponent) volumeMountsForProxyManager() []v1.VolumeMount {
	var mounts = []corev1.VolumeMount{
		{Name: ManagerTLSSecretName, MountPath: "/certs/https", ReadOnly: true},
		{Name: KibanaPublicCertSecret, MountPath: "/certs/kibana", ReadOnly: true},
		{Name: ComplianceServerCertSecret, MountPath: "/certs/compliance", ReadOnly: true},
	}

	if c.managementCluster != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: ManagerInternalTLSSecretName, MountPath: "/certs/internal", ReadOnly: true})
		mounts = append(mounts, corev1.VolumeMount{Name: VoltronTunnelSecretName, MountPath: "/certs/tunnel", ReadOnly: true})
	}

	if c.dexCfg != nil {
		mounts = append(mounts, c.dexCfg.RequiredVolumeMounts()...)
	}

	return mounts
}

// managerEsProxyContainer returns the ES proxy container
func (c *managerComponent) managerEsProxyContainer() corev1.Container {
	var volumeMounts []corev1.VolumeMount
	if c.managementCluster != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{Name: ManagerInternalTLSSecretCertName, MountPath: "/manager-tls", ReadOnly: true})
	}

	var env []v1.EnvVar
	if c.dexCfg != nil {
		env = append(env, c.dexCfg.RequiredEnv("")...)
		volumeMounts = append(volumeMounts, c.dexCfg.RequiredVolumeMounts()...)
	}

	return corev1.Container{
		Name:            "tigera-es-proxy",
		Image:           components.GetReference(components.ComponentEsProxy, c.installation.Registry, c.installation.ImagePath),
		LivenessProbe:   c.managerEsProxyProbe(),
		SecurityContext: securityContext(),
		Env:             env,
		VolumeMounts:    volumeMounts,
	}
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

// managerServiceAccount creates the serviceaccount used by the Tigera Secure web app.
func managerServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ManagerServiceAccount, Namespace: ManagerNamespace},
	}
}

// managerClusterRole returns a clusterrole that allows authn/authz review requests.
func managerClusterRole(managementCluster, managedCluster, openshift bool) *rbacv1.ClusterRole {
	cr := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerClusterRole,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
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
			// When a request is made in the manager UI, they are proxied through the Voltron backend server. If the
			// request is targeting a k8s api or when it is targeting a managed cluster, Voltron will authenticate the
			// user based on the auth header and then impersonate the user.
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}

	if !managedCluster {
		cr.Rules = append(cr.Rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch", "update"},
			},
		)
	}

	if managementCluster {
		// For cross-cluster requests an authentication review will be done for authenticating the tigera-manager.
		// Requests on behalf of the tigera-manager will be sent to Voltron, where an authentication review will
		// take place with its bearer token.
		cr.Rules = append(cr.Rules, rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authenticationreviews"},
			Verbs:     []string{"create"},
		})
	}

	if !openshift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		cr.Rules = append(cr.Rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"tigera-manager"},
			},
		)
	}

	return cr
}

// managerClusterRoleBinding returns a clusterrolebinding that gives the tigera-manager serviceaccount
// the permissions in the tigera-manager-role.
func managerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ManagerClusterRoleBinding},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ManagerClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ManagerServiceAccount,
				Namespace: ManagerNamespace,
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

func (c *managerComponent) managerPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := basePodSecurityPolicy()
	psp.GetObjectMeta().SetName("tigera-manager")
	return psp
}
