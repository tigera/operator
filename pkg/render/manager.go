// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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
	"strings"

	ocsv1 "github.com/openshift/api/security/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render/common/authentication"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	"github.com/tigera/operator/pkg/render/common/configmap"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rkibana "github.com/tigera/operator/pkg/render/common/kibana"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/podsecuritycontext"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	managerPort                  = 9443
	managerTargetPort            = 9443
	ManagerServiceName           = "tigera-manager"
	ManagerNamespace             = "tigera-manager"
	ManagerServiceIP             = "localhost"
	ManagerServiceAccount        = "tigera-manager"
	ManagerClusterRole           = "tigera-manager-role"
	ManagerClusterRoleBinding    = "tigera-manager-binding"
	ManagerTLSSecretName         = "manager-tls"
	ManagerInternalTLSSecretName = "internal-manager-tls"

	ManagerUserSettings = "user-settings"

	ElasticsearchManagerUserSecret  = "tigera-ee-manager-elasticsearch-access"
	TlsSecretHashAnnotation         = "hash.operator.tigera.io/tls-secret"
	KibanaTLSHashAnnotation         = "hash.operator.tigera.io/kibana-secrets"
	ElasticsearchUserHashAnnotation = "hash.operator.tigera.io/elasticsearch-user"

	PrometheusTLSSecretName = "calico-node-prometheus-tls"
)

// ManagementClusterConnection configuration constants
const (
	VoltronName              = "tigera-voltron"
	VoltronTunnelSecretName  = "tigera-management-cluster-connection"
	defaultVoltronPort       = "9443"
	defaultTunnelVoltronPort = "9449"
)

func Manager(cfg *ManagerConfiguration) (Component, error) {
	var tlsSecrets []*corev1.Secret
	tlsAnnotations := cfg.TrustedCertBundle.HashAnnotations()
	tlsAnnotations[KibanaTLSHashAnnotation] = rmeta.SecretsAnnotationHash(cfg.KibanaSecrets...)
	tlsAnnotations[cfg.TLSKeyPair.HashAnnotationKey()] = cfg.TLSKeyPair.HashAnnotationValue()

	if cfg.KeyValidatorConfig != nil {
		tlsSecrets = append(tlsSecrets, cfg.KeyValidatorConfig.RequiredSecrets(ManagerNamespace)...)
		for key, value := range cfg.KeyValidatorConfig.RequiredAnnotations() {
			tlsAnnotations[key] = value
		}
	}

	if cfg.ManagementCluster != nil {
		tlsAnnotations[cfg.InternalTrafficSecret.HashAnnotationKey()] = cfg.InternalTrafficSecret.HashAnnotationValue()
		tlsAnnotations[cfg.TunnelSecret.HashAnnotationKey()] = cfg.InternalTrafficSecret.HashAnnotationValue()
	}
	return &managerComponent{
		cfg:            cfg,
		tlsSecrets:     tlsSecrets,
		tlsAnnotations: tlsAnnotations,
	}, nil
}

// ManagerConfiguration contains all the config information needed to render the component.
type ManagerConfiguration struct {
	KeyValidatorConfig      authentication.KeyValidatorConfig
	ESSecrets               []*corev1.Secret
	KibanaSecrets           []*corev1.Secret
	TrustedCertBundle       certificatemanagement.TrustedBundle
	ESClusterConfig         *relasticsearch.ClusterConfig
	TLSKeyPair              certificatemanagement.KeyPairInterface
	PullSecrets             []*corev1.Secret
	Openshift               bool
	Installation            *operatorv1.InstallationSpec
	ManagementCluster       *operatorv1.ManagementCluster
	TunnelSecret            certificatemanagement.KeyPairInterface
	InternalTrafficSecret   certificatemanagement.KeyPairInterface
	ClusterDomain           string
	ESLicenseType           ElasticsearchLicenseType
	Replicas                *int32
	ComplianceFeatureActive bool
}

type managerComponent struct {
	cfg            *ManagerConfiguration
	tlsSecrets     []*corev1.Secret
	tlsAnnotations map[string]string
	managerImage   string
	proxyImage     string
	esProxyImage   string
}

func (c *managerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.managerImage, err = components.GetReference(components.ComponentManager, reg, path, prefix, is)
	errMsgs := []string{}
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.proxyImage, err = components.GetReference(components.ComponentManagerProxy, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.esProxyImage, err = components.GetReference(components.ComponentEsProxy, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *managerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *managerComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		CreateNamespace(ManagerNamespace, c.cfg.Installation.KubernetesProvider),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, c.cfg.PullSecrets...)...)...)

	objs = append(objs,
		managerServiceAccount(),
		managerClusterRole(c.cfg.ManagementCluster != nil, false, c.cfg.Openshift),
		managerClusterRoleBinding(),
		managerUserSpecificSettingsGroup(),
	)
	objs = append(objs, c.getTLSObjects()...)
	objs = append(objs,
		c.managerService(),
	)

	// If we're running on openshift, we need to add in an SCC.
	if c.cfg.Openshift {
		objs = append(objs, c.securityContextConstraints())
	} else {
		// If we're not running openshift, we need to add pod security policies.
		objs = append(objs, c.managerPodSecurityPolicy())
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, c.cfg.ESSecrets...)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, c.cfg.KibanaSecrets...)...)...)
	objs = append(objs, c.managerDeployment())
	if c.cfg.KeyValidatorConfig != nil {
		objs = append(objs, configmap.ToRuntimeObjects(c.cfg.KeyValidatorConfig.RequiredConfigMaps(ManagerNamespace)...)...)
	}

	return objs, nil
}

func (c *managerComponent) Ready() bool {
	return true
}

// managerDeployment creates a deployment for the Tigera Secure manager component.
func (c *managerComponent) managerDeployment() *appsv1.Deployment {
	var initContainers []corev1.Container
	if c.cfg.TLSKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TLSKeyPair.InitContainer(ManagerNamespace))
	}

	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-manager",
			Namespace: ManagerNamespace,
			Labels: map[string]string{
				"k8s-app": "tigera-manager",
			},
			Annotations: c.tlsAnnotations,
		},
		Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: ManagerServiceAccount,
			Tolerations:        c.managerTolerations(),
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				relasticsearch.ContainerDecorate(c.managerContainer(), c.cfg.ESClusterConfig.ClusterName(), ElasticsearchManagerUserSecret, c.cfg.ClusterDomain, c.SupportedOSType()),
				relasticsearch.ContainerDecorate(c.managerEsProxyContainer(), c.cfg.ESClusterConfig.ClusterName(), ElasticsearchManagerUserSecret, c.cfg.ClusterDomain, c.SupportedOSType()),
				c.managerProxyContainer(),
			},
			Volumes: c.managerVolumes(),
		}),
	}, c.cfg.ESClusterConfig, c.cfg.ESSecrets).(*corev1.PodTemplateSpec)

	if c.cfg.Replicas != nil && *c.cfg.Replicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity("tigera-manager", ManagerNamespace)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
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
			Replicas: c.cfg.Replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
		},
	}
	return d
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumeMounts() []corev1.VolumeMount {
	if c.cfg.KeyValidatorConfig != nil {
		return c.cfg.KeyValidatorConfig.RequiredVolumeMounts()
	}
	return []corev1.VolumeMount{}
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumes() []corev1.Volume {
	v := []corev1.Volume{
		c.cfg.TLSKeyPair.Volume(),
		c.cfg.TrustedCertBundle.Volume(),
		{
			Name: KibanaPublicCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: KibanaPublicCertSecret,
				},
			},
		},
	}
	if c.cfg.ManagementCluster != nil {
		v = append(v,
			c.cfg.InternalTrafficSecret.Volume(),
			c.cfg.TunnelSecret.Volume(),
		)
	}
	if c.cfg.KeyValidatorConfig != nil {
		v = append(v, c.cfg.KeyValidatorConfig.RequiredVolumes()...)
	}

	return v
}

// managerProbe returns the probe for the manager container.
func (c *managerComponent) managerProbe() *corev1.Probe {
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
func (c *managerComponent) managerEsProxyProbe() *corev1.Probe {
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
func (c *managerComponent) managerProxyProbe() *corev1.Probe {
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
func (c *managerComponent) managerEnvVars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "CNX_PROMETHEUS_API_URL", Value: fmt.Sprintf("/api/v1/namespaces/%s/services/calico-node-prometheus:9090/proxy/api/v1", common.TigeraPrometheusNamespace)},
		{Name: "CNX_COMPLIANCE_REPORTS_API_URL", Value: "/compliance/reports"},
		{Name: "CNX_QUERY_API_URL", Value: "/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy"},
		{Name: "CNX_ELASTICSEARCH_API_URL", Value: "/tigera-elasticsearch"},
		{Name: "CNX_ELASTICSEARCH_KIBANA_URL", Value: fmt.Sprintf("/%s", KibanaBasePath)},
		{Name: "CNX_ENABLE_ERROR_TRACKING", Value: "false"},
		{Name: "CNX_ALP_SUPPORT", Value: "true"},
		{Name: "CNX_CLUSTER_NAME", Value: "cluster"},
		{Name: "CNX_POLICY_RECOMMENDATION_SUPPORT", Value: "true"},
		{Name: "ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.cfg.ManagementCluster != nil)},
	}

	envs = append(envs, c.managerOAuth2EnvVars()...)
	return envs
}

// managerContainer returns the manager container.
func (c *managerComponent) managerContainer() corev1.Container {
	tm := corev1.Container{
		Name:            "tigera-manager",
		Image:           c.managerImage,
		Env:             c.managerEnvVars(),
		LivenessProbe:   c.managerProbe(),
		SecurityContext: podsecuritycontext.NewBaseContext(),
		VolumeMounts:    c.managerVolumeMounts(),
	}

	return tm
}

// managerOAuth2EnvVars returns the OAuth2/OIDC envvars depending on the authentication type.
func (c *managerComponent) managerOAuth2EnvVars() []corev1.EnvVar {
	var envs []corev1.EnvVar

	if c.cfg.KeyValidatorConfig == nil {
		envs = []corev1.EnvVar{{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "Token"}}
	} else {
		envs = []corev1.EnvVar{
			{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "OIDC"},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: c.cfg.KeyValidatorConfig.ClientID()}}

		switch c.cfg.KeyValidatorConfig.(type) {
		case *DexKeyValidatorConfig:
			envs = append(envs, corev1.EnvVar{Name: "CNX_WEB_OIDC_AUTHORITY", Value: c.cfg.KeyValidatorConfig.Issuer()})
		case *tigerakvc.KeyValidatorConfig:
			envs = append(envs, corev1.EnvVar{Name: "CNX_WEB_OIDC_AUTHORITY", Value: ""})
		}
	}
	return envs
}

// managerProxyContainer returns the container for the manager proxy container.
func (c *managerComponent) managerProxyContainer() corev1.Container {
	var keyPath, certPath, intKeyPath, intCertPath, tunnelKeyPath, tunnelCertPath string
	if c.cfg.TLSKeyPair != nil {
		keyPath, certPath = c.cfg.TLSKeyPair.VolumeMountKeyFilePath(), c.cfg.TLSKeyPair.VolumeMountCertificateFilePath()
	}
	if c.cfg.InternalTrafficSecret != nil {
		intKeyPath, intCertPath = c.cfg.InternalTrafficSecret.VolumeMountKeyFilePath(), c.cfg.InternalTrafficSecret.VolumeMountCertificateFilePath()
	}
	if c.cfg.TunnelSecret != nil {
		tunnelKeyPath, tunnelCertPath = c.cfg.TunnelSecret.VolumeMountKeyFilePath(), c.cfg.TunnelSecret.VolumeMountCertificateFilePath()
	}
	env := []corev1.EnvVar{
		{Name: "VOLTRON_PORT", Value: defaultVoltronPort},
		{Name: "VOLTRON_COMPLIANCE_ENDPOINT", Value: fmt.Sprintf("https://compliance.%s.svc.%s", ComplianceNamespace, c.cfg.ClusterDomain)},
		{Name: "VOLTRON_LOGLEVEL", Value: "Info"},
		{Name: "VOLTRON_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain)},
		{Name: "VOLTRON_KIBANA_BASE_PATH", Value: fmt.Sprintf("/%s/", KibanaBasePath)},
		{Name: "VOLTRON_KIBANA_CA_BUNDLE_PATH", Value: "/certs/kibana/tls.crt"},
		{Name: "VOLTRON_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_PROMETHEUS_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_COMPLIANCE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_HTTPS_KEY", Value: keyPath},
		{Name: "VOLTRON_HTTPS_CERT", Value: certPath},
		{Name: "VOLTRON_TUNNEL_KEY", Value: tunnelKeyPath},
		{Name: "VOLTRON_TUNNEL_CERT", Value: tunnelCertPath},
		{Name: "VOLTRON_INTERNAL_HTTPS_KEY", Value: intKeyPath},
		{Name: "VOLTRON_INTERNAL_HTTPS_CERT", Value: intCertPath},
		{Name: "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.cfg.ManagementCluster != nil)},
		{Name: "VOLTRON_TUNNEL_PORT", Value: defaultTunnelVoltronPort},
		{Name: "VOLTRON_DEFAULT_FORWARD_SERVER", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc:9200"},
		{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: fmt.Sprintf("%v", c.cfg.ComplianceFeatureActive)},
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("VOLTRON_")...)
	}

	return corev1.Container{
		Name:            VoltronName,
		Image:           c.proxyImage,
		Env:             env,
		VolumeMounts:    c.volumeMountsForProxyManager(),
		LivenessProbe:   c.managerProxyProbe(),
		SecurityContext: podsecuritycontext.NewBaseContext(),
	}
}

func (c *managerComponent) volumeMountsForProxyManager() []corev1.VolumeMount {
	var mounts = []corev1.VolumeMount{
		{Name: ManagerTLSSecretName, MountPath: "/manager-tls", ReadOnly: true},
		{Name: KibanaPublicCertSecret, MountPath: "/certs/kibana", ReadOnly: true},
		c.cfg.TrustedCertBundle.VolumeMount(),
	}

	if c.cfg.ManagementCluster != nil {
		mounts = append(mounts, c.cfg.InternalTrafficSecret.VolumeMount())
		mounts = append(mounts, c.cfg.TunnelSecret.VolumeMount())
	}

	if c.cfg.KeyValidatorConfig != nil {
		mounts = append(mounts, c.cfg.KeyValidatorConfig.RequiredVolumeMounts()...)
	}

	return mounts
}

// managerEsProxyContainer returns the ES proxy container
func (c *managerComponent) managerEsProxyContainer() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "ELASTIC_LICENSE_TYPE", Value: string(c.cfg.ESLicenseType)},
		{Name: "ELASTIC_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain)},
	}

	var volumeMounts []corev1.VolumeMount
	if c.cfg.ManagementCluster != nil {
		volumeMounts = append(volumeMounts, c.cfg.TrustedCertBundle.VolumeMount())
		env = append(env, corev1.EnvVar{Name: "VOLTRON_CA_PATH", Value: certificatemanagement.TrustedCertBundleMountPath})
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("")...)
		volumeMounts = append(volumeMounts, c.cfg.KeyValidatorConfig.RequiredVolumeMounts()...)
	}

	return corev1.Container{
		Name:            "tigera-es-proxy",
		Image:           c.esProxyImage,
		LivenessProbe:   c.managerEsProxyProbe(),
		SecurityContext: podsecuritycontext.NewBaseContext(),
		Env:             env,
		VolumeMounts:    volumeMounts,
	}
}

// managerTolerations returns the tolerations for the Tigera Secure manager deployment pods.
func (c *managerComponent) managerTolerations() []corev1.Toleration {
	return append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly)
}

// managerService returns the service exposing the Tigera Secure web app.
func (c *managerComponent) managerService() *corev1.Service {
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
func managerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
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
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
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
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"hostendpoints",
				},
				Verbs: []string{"list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"felixconfigurations",
				},
				ResourceNames: []string{
					"default",
				},
				Verbs: []string{"get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"alertexceptions",
				},
				Verbs: []string{"get", "list", "update"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces", "nodes", "events", "services", "pods"},
				Verbs:     []string{"list"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets", "statefulsets", "daemonsets"},
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
		Volumes:                  []ocsv1.FSType{"*"},
	}
}

func (c *managerComponent) getTLSObjects() []client.Object {
	objs := []client.Object{}
	for _, s := range c.tlsSecrets {
		objs = append(objs, s)
	}

	return objs
}

func (c *managerComponent) managerPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName("tigera-manager")
	return psp
}

// managerUserSpecificSettingsGroup returns a UISettingsGroup with the description "user settings"
//
// Calico Enterprise only
func managerUserSpecificSettingsGroup() *v3.UISettingsGroup {
	return &v3.UISettingsGroup{
		TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerUserSettings,
		},
		Spec: v3.UISettingsGroupSpec{
			Description: "User Settings",
			FilterType:  v3.FilterTypeUser,
		},
	}
}
