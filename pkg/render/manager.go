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

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
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
	managerPort             = 9443
	managerTargetPort       = 9443
	ManagerNamespace        = "tigera-manager"
	ManagerTLSSecretName    = "manager-tls"
	ManagerSecretKeyName    = "key"
	ManagerSecretCertName   = "cert"
	ManagerOIDCConfig       = "tigera-manager-oidc-config"
	ManagerOIDCWellknownURI = "/usr/share/nginx/html/.well-known"
	ManagerOIDCJwksURI      = "/usr/share/nginx/html/discovery"

	ElasticsearchManagerUserSecret = "tigera-ee-manager-elasticsearch-access"
	tlsSecretHashAnnotation        = "hash.operator.tigera.io/tls-secret"
	oidcConfigHashAnnotation       = "hash.operator.tigera.io/oidc-config"
)

// ManagementClusterConnection configuration constants
const (
	VoltronName                 = "tigera-voltron"
	VoltronTunnelSecretName     = "tigera-management-cluster-connection"
	voltronTunnelHashAnnotation = "hash.operator.tigera.io/voltron-tunnel"
	defaultVoltronPort          = "9443"
	defaultTunnelVoltronPort    = "9449"
)

func Manager(
	cr *operator.Manager,
	esSecrets []*corev1.Secret,
	kibanaSecrets []*corev1.Secret,
	complianceServerCertSecret *corev1.Secret,
	esClusterConfig *ElasticsearchClusterConfig,
	tlsKeyPair *corev1.Secret,
	pullSecrets []*corev1.Secret,
	openshift bool,
	installation *operator.Installation,
	oidcConfig *corev1.ConfigMap,
	management bool,
	tunnelSecret *corev1.Secret,
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
	copy := tlsKeyPair.DeepCopy()
	// Overwrite the ObjectMeta to ensure we do not keep the resourceVersion or any other information
	// that should not be set on a new object.
	copy.ObjectMeta = metav1.ObjectMeta{Name: ManagerTLSSecretName, Namespace: ManagerNamespace}
	tlsSecrets = append(tlsSecrets, copy)

	var tunnelSecrets []*corev1.Secret
	if management {
		// If there is no secret create one and add it to the operator namespace.
		if tunnelSecret == nil {
			tunnelSecret = voltronTunnelSecret()
			tunnelSecrets = append(tunnelSecrets, tunnelSecret)
		}

		tunnelSecrets = append(tunnelSecrets, CopySecrets(ManagerNamespace, tunnelSecret)...)
	}
	return &managerComponent{
		cr:                         cr,
		esSecrets:                  esSecrets,
		kibanaSecrets:              kibanaSecrets,
		complianceServerCertSecret: complianceServerCertSecret,
		esClusterConfig:            esClusterConfig,
		tlsSecrets:                 tlsSecrets,
		pullSecrets:                pullSecrets,
		openshift:                  openshift,
		installation:               installation,
		oidcConfig:                 oidcConfig,
		management:                 management,
		tunnelSecrets:              tunnelSecrets,
	}, nil
}

type managerComponent struct {
	cr                         *operator.Manager
	esSecrets                  []*corev1.Secret
	kibanaSecrets              []*corev1.Secret
	complianceServerCertSecret *corev1.Secret
	esClusterConfig            *ElasticsearchClusterConfig
	tlsSecrets                 []*corev1.Secret
	pullSecrets                []*corev1.Secret
	openshift                  bool
	installation               *operator.Installation
	oidcConfig                 *corev1.ConfigMap
	// If true, this is a management cluster.
	management bool
	// The tunnel secret if present in the operator namespace
	tunnelSecrets []*corev1.Secret
}

func (c *managerComponent) Objects() ([]runtime.Object, []runtime.Object) {
	objs := []runtime.Object{
		createNamespace(ManagerNamespace, c.openshift),
	}
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, ManagerNamespace)...)
	objs = append(objs, copyImagePullSecrets(c.pullSecrets, common.TigeraPrometheusNamespace)...)

	objs = append(objs,
		c.managerServiceAccount(),
		c.managerClusterRole(),
		c.managerClusterRoleBinding(),
		c.managerPolicyImpactPreviewClusterRole(),
		c.managerPolicyImpactPreviewClusterRoleBinding(),
	)
	objs = append(objs, c.getTLSObjects()...)
	objs = append(objs,
		c.managerService(),
	)

	// If we're running on openshift, we need to add in an SCC.
	if c.openshift {
		objs = append(objs, c.securityContextConstraints())
	}
	objs = append(objs, secretsToRuntimeObjects(CopySecrets(ManagerNamespace, c.esSecrets...)...)...)
	objs = append(objs, secretsToRuntimeObjects(CopySecrets(ManagerNamespace, c.kibanaSecrets...)...)...)
	objs = append(objs, secretsToRuntimeObjects(CopySecrets(ManagerNamespace, c.complianceServerCertSecret)...)...)
	objs = append(objs, secretsToRuntimeObjects(c.tunnelSecrets...)...)
	if c.oidcConfig != nil {
		objs = append(objs, copyConfigMaps(ManagerNamespace, c.oidcConfig)...)
	}
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
	if c.management {
		annotations[voltronTunnelHashAnnotation] = AnnotationHash(c.tunnelSecrets[0].Data)
	}
	if len(c.tlsSecrets) > 0 {
		// Add a hash of the Secret to ensure if it changes the manager will be
		// redeployed.
		annotations[tlsSecretHashAnnotation] = AnnotationHash(c.tlsSecrets[0].Data)
	}
	if c.oidcConfig != nil {
		annotations[oidcConfigHashAnnotation] = AnnotationHash(c.oidcConfig.Data)
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
			NodeSelector: map[string]string{
				"beta.kubernetes.io/os": "linux",
			},
			ServiceAccountName: "tigera-manager",
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
	optional := true
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
			Name: VoltronTunnelSecretName,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: VoltronTunnelSecretName,
					Optional:   &optional,
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

	if c.oidcConfig != nil {
		defaultMode := int32(420)
		v = append(v,
			v1.Volume{
				Name: ManagerOIDCConfig,
				VolumeSource: v1.VolumeSource{
					ConfigMap: &v1.ConfigMapVolumeSource{
						LocalObjectReference: v1.LocalObjectReference{
							Name: ManagerOIDCConfig,
						},
						DefaultMode: &defaultMode,
					},
				},
			})
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
		{Name: "ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.management)},
	}

	envs = append(envs, c.managerOAuth2EnvVars()...)
	return envs
}

// managerContainer returns the manager container.
func (c *managerComponent) managerContainer() corev1.Container {
	tm := corev1.Container{
		Name:            "tigera-manager",
		Image:           components.GetReference(components.ComponentManager, c.installation.Spec.Registry, c.installation.Spec.ImagePath),
		Env:             c.managerEnvVars(),
		LivenessProbe:   c.managerProbe(),
		SecurityContext: securityContext(),
	}

	if c.oidcConfig != nil {
		// If OIDC configuration is defined, use manager to avail well-known and JWKS configuration.
		tm.VolumeMounts = []corev1.VolumeMount{
			{Name: ManagerOIDCConfig, MountPath: ManagerOIDCWellknownURI},
			{Name: ManagerOIDCConfig, MountPath: ManagerOIDCJwksURI},
		}
	}

	return tm
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
		Image: components.GetReference(components.ComponentManagerProxy, c.installation.Spec.Registry, c.installation.Spec.ImagePath),
		Env: []corev1.EnvVar{
			{Name: "VOLTRON_PORT", Value: defaultVoltronPort},
			{Name: "VOLTRON_COMPLIANCE_ENDPOINT", Value: fmt.Sprintf("https://compliance.%s.svc", ComplianceNamespace)},
			{Name: "VOLTRON_LOGLEVEL", Value: "info"},
			{Name: "VOLTRON_KIBANA_ENDPOINT", Value: KibanaHTTPSEndpoint},
			{Name: "VOLTRON_KIBANA_BASE_PATH", Value: fmt.Sprintf("/%s/", KibanaBasePath)},
			{Name: "VOLTRON_KIBANA_CA_BUNDLE_PATH", Value: "/certs/kibana/tls.crt"},
			{Name: "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.management)},
			{Name: "VOLTRON_TUNNEL_PORT", Value: defaultTunnelVoltronPort},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: ManagerTLSSecretName, MountPath: "/certs/https"},
			{Name: KibanaPublicCertSecret, MountPath: "/certs/kibana"},
			{Name: ComplianceServerCertSecret, MountPath: "/certs/compliance"},
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
		Image:           components.GetReference(components.ComponentEsProxy, c.installation.Spec.Registry, c.installation.Spec.ImagePath),
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
func voltronTunnelSecret() *v1.Secret {
	key, cert := ceateSelfSignedVoltronSecret()
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      VoltronTunnelSecretName,
			Namespace: OperatorNamespace(),
		},
		Data: map[string][]byte{
			"cert": []byte(cert),
			"key":  []byte(key),
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
				Verbs:     []string{"list", "get", "watch", "update"},
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


