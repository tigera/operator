// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"

	ocsv1 "github.com/openshift/api/security/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render/common/authentication"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/configmap"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rkibana "github.com/tigera/operator/pkg/render/common/kibana"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/manager"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

const (
	managerPort                  = 9443
	managerTargetPort            = 9443
	ManagerServiceName           = "tigera-manager"
	ManagerDeploymentName        = "tigera-manager"
	ManagerNamespace             = "tigera-manager"
	ManagerServiceAccount        = "tigera-manager"
	ManagerClusterRole           = "tigera-manager-role"
	ManagerClusterRoleBinding    = "tigera-manager-binding"
	ManagerTLSSecretName         = "manager-tls"
	ManagerInternalTLSSecretName = "internal-manager-tls"
	ManagerPolicyName            = networkpolicy.TigeraComponentPolicyPrefix + "manager-access"

	// The name of the TLS certificate used by Voltron to authenticate connections from managed
	// cluster clients talking to Linseed.
	VoltronLinseedTLS        = "tigera-voltron-linseed-tls"
	VoltronLinseedPublicCert = "tigera-voltron-linseed-certs-public"

	ManagerClusterSettings            = "cluster-settings"
	ManagerUserSettings               = "user-settings"
	ManagerClusterSettingsLayerTigera = "cluster-settings.layer.tigera-infrastructure"
	ManagerClusterSettingsViewDefault = "cluster-settings.view.default"

	ElasticsearchManagerUserSecret  = "tigera-ee-manager-elasticsearch-access"
	TlsSecretHashAnnotation         = "hash.operator.tigera.io/tls-secret"
	KibanaTLSHashAnnotation         = "hash.operator.tigera.io/kibana-secrets"
	ElasticsearchUserHashAnnotation = "hash.operator.tigera.io/elasticsearch-user"
)

// ManagementClusterConnection configuration constants
const (
	VoltronName              = "tigera-voltron"
	VoltronTunnelSecretName  = "tigera-management-cluster-connection"
	defaultVoltronPort       = "9443"
	defaultTunnelVoltronPort = "9449"
)

// Manager returns a component for rendering namespaced manager resources.
func init() {
	certkeyusage.SetCertKeyUsage(ManagerTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	certkeyusage.SetCertKeyUsage(ManagerInternalTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

// Manager returns a component for rendering namespaced manager resources.
func Manager(cfg *ManagerConfiguration) (Component, error) {
	var tlsSecrets []*corev1.Secret
	tlsAnnotations := cfg.TrustedCertBundle.HashAnnotations()
	tlsAnnotations[cfg.TLSKeyPair.HashAnnotationKey()] = cfg.TLSKeyPair.HashAnnotationValue()

	if cfg.VoltronLinseedKeyPair != nil {
		tlsAnnotations[cfg.VoltronLinseedKeyPair.HashAnnotationKey()] = cfg.VoltronLinseedKeyPair.HashAnnotationValue()
	}

	if cfg.KeyValidatorConfig != nil {
		tlsSecrets = append(tlsSecrets, cfg.KeyValidatorConfig.RequiredSecrets(cfg.Namespace)...)
		for key, value := range cfg.KeyValidatorConfig.RequiredAnnotations() {
			tlsAnnotations[key] = value
		}
	}

	tlsAnnotations[cfg.InternalTLSKeyPair.HashAnnotationKey()] = cfg.InternalTLSKeyPair.HashAnnotationValue()
	if cfg.ManagementCluster != nil {
		tlsAnnotations[cfg.TunnelServerCert.HashAnnotationKey()] = cfg.TunnelServerCert.HashAnnotationValue()
	}

	return &managerComponent{
		cfg:            cfg,
		tlsSecrets:     tlsSecrets,
		tlsAnnotations: tlsAnnotations,
	}, nil
}

// ManagerConfiguration contains all the config information needed to render the component.
type ManagerConfiguration struct {
	VoltronRouteConfig *manager.VoltronRouteConfig

	KeyValidatorConfig authentication.KeyValidatorConfig
	ESSecrets          []*corev1.Secret
	ClusterConfig      *relasticsearch.ClusterConfig
	PullSecrets        []*corev1.Secret
	Openshift          bool
	Installation       *operatorv1.InstallationSpec
	ManagementCluster  *operatorv1.ManagementCluster

	// If provided, the KeyPair to used for external connections terminated by Voltron,
	// and connections from the manager pod to Linseed.
	TLSKeyPair certificatemanagement.KeyPairInterface

	// The key pair to use for TLS between Linseed clients in managed clusters and Voltron
	// in the management cluster.
	VoltronLinseedKeyPair certificatemanagement.KeyPairInterface

	// KeyPair used by Voltron as the server certificate when establishing an mTLS tunnel with Guardian.
	TunnelServerCert certificatemanagement.KeyPairInterface

	// TLS KeyPair used by both Voltron and es-proxy, presented by each as part of the mTLS handshake with
	// other services within the cluster. This is used in both management and standalone clusters.
	InternalTLSKeyPair certificatemanagement.KeyPairInterface

	// Certificate bundle used by the manager pod to verify certificates presented
	// by clients as part of mTLS authentication.
	TrustedCertBundle certificatemanagement.TrustedBundleRO

	ClusterDomain           string
	ESLicenseType           ElasticsearchLicenseType
	Replicas                *int32
	Compliance              *operatorv1.Compliance
	ComplianceLicenseActive bool
	ComplianceNamespace     string

	// Whether the cluster supports pod security policies.
	UsePSP            bool
	Namespace         string
	TruthNamespace    string
	BindingNamespaces []string

	// Whether to run the rendered components in multi-tenant, single-tenant, or zero-tenant mode
	Tenant          *operatorv1.Tenant
	ExternalElastic bool

	Manager *operatorv1.Manager
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
	objs := []client.Object{}

	if !c.cfg.Tenant.MultiTenant() {
		// In multi-tenant environments, the namespace is pre-created. So, only create it if we're not in a multi-tenant environment.
		objs = append(objs, CreateNamespace(c.cfg.Namespace, c.cfg.Installation.KubernetesProvider, PSSRestricted))

		// For multi-tenant environments, the management cluster itself isn't shown in the UI so we only need to create these
		// when there is no tenant.
		objs = append(objs,
			managerClusterWideSettingsGroup(),
			managerUserSpecificSettingsGroup(),
			managerClusterWideTigeraLayer(),
			managerClusterWideDefaultView(),
		)
	}

	objs = append(objs,
		managerClusterRoleBinding(c.cfg.BindingNamespaces),
		managerClusterRole(c.cfg.ManagementCluster != nil, false, c.cfg.UsePSP, c.cfg.Installation.KubernetesProvider),
	)

	if c.cfg.UsePSP {
		objs = append(objs, managerPodSecurityPolicy())
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(c.cfg.Namespace, c.cfg.PullSecrets...)...)...)
	objs = append(objs,
		c.managerAllowTigeraNetworkPolicy(),
		networkpolicy.AllowTigeraDefaultDeny(c.cfg.Namespace),
		managerServiceAccount(c.cfg.Namespace),
	)
	objs = append(objs, c.getTLSObjects()...)
	objs = append(objs, c.managerService())

	if c.cfg.VoltronRouteConfig != nil {
		objs = append(objs, c.cfg.VoltronRouteConfig.RoutesConfigMap(c.cfg.Namespace))
	}

	// If we're running on openshift, we need to add in an SCC.
	if c.cfg.Openshift {
		objs = append(objs, c.securityContextConstraints())
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(c.cfg.Namespace, c.cfg.ESSecrets...)...)...)
	objs = append(objs, c.managerDeployment())
	if c.cfg.KeyValidatorConfig != nil {
		objs = append(objs, configmap.ToRuntimeObjects(c.cfg.KeyValidatorConfig.RequiredConfigMaps(c.cfg.Namespace)...)...)
	}

	// The following secret is read by kube controllers and sent to managed clusters so that linseed clients in the managed cluster
	// can authenticate the certificate presented by Voltron.
	if c.cfg.VoltronLinseedKeyPair != nil {
		if c.cfg.VoltronLinseedKeyPair.UseCertificateManagement() {
			objs = append(objs, CreateCertificateSecret(c.cfg.Installation.CertificateManagement.CACert, VoltronLinseedPublicCert, c.cfg.TruthNamespace))
		} else {
			objs = append(objs, CreateCertificateSecret(c.cfg.VoltronLinseedKeyPair.GetCertificatePEM(), VoltronLinseedPublicCert, c.cfg.TruthNamespace))
		}
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
		initContainers = append(initContainers, c.cfg.TLSKeyPair.InitContainer(c.cfg.Namespace))
	}

	// Containers for the manager pod.
	if c.cfg.InternalTLSKeyPair != nil && c.cfg.InternalTLSKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.InternalTLSKeyPair.InitContainer(ManagerNamespace))
	}
	if c.cfg.VoltronLinseedKeyPair != nil && c.cfg.VoltronLinseedKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.VoltronLinseedKeyPair.InitContainer(ManagerNamespace))
	}

	managerPodContainers := []corev1.Container{c.managerEsProxyContainer(), c.voltronContainer()}
	if c.cfg.Tenant == nil {
		managerPodContainers = append(managerPodContainers, c.managerContainer())
	}
	annotations := c.tlsAnnotations
	if c.cfg.VoltronRouteConfig != nil {
		for key, value := range c.cfg.VoltronRouteConfig.Annotations() {
			annotations[key] = value
		}
	}

	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ManagerDeploymentName,
			Namespace:   c.cfg.Namespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: ManagerServiceAccount,
			Tolerations:        c.managerTolerations(),
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			InitContainers:     initContainers,
			Containers:         managerPodContainers,
			Volumes:            c.managerVolumes(),
		},
	}, c.cfg.ESSecrets).(*corev1.PodTemplateSpec)

	if c.cfg.Replicas != nil && *c.cfg.Replicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity("tigera-manager", c.cfg.Namespace)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ManagerDeploymentName,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.Manager != nil {
		if overrides := c.cfg.Manager.Spec.ManagerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumeMounts() []corev1.VolumeMount {
	if c.cfg.KeyValidatorConfig != nil {
		return c.cfg.KeyValidatorConfig.RequiredVolumeMounts()
	}
	return nil
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumes() []corev1.Volume {
	v := []corev1.Volume{
		c.cfg.TLSKeyPair.Volume(),
		c.cfg.TrustedCertBundle.Volume(),
		c.cfg.InternalTLSKeyPair.Volume(),
	}
	if c.cfg.ManagementCluster != nil {
		v = append(v,
			c.cfg.TunnelServerCert.Volume(),
			c.cfg.VoltronLinseedKeyPair.Volume(),
		)
	}
	if c.cfg.KeyValidatorConfig != nil {
		v = append(v, c.cfg.KeyValidatorConfig.RequiredVolumes()...)
	}

	if c.cfg.VoltronRouteConfig != nil {
		v = append(v, c.cfg.VoltronRouteConfig.Volumes()...)
	}

	return v
}

// managerProbe returns the probe for the manager container.
func (c *managerComponent) managerProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
	}
}

// managerEsProxyProbe returns the probe for the ES proxy container.
func (c *managerComponent) managerEsProxyProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/tigera-elasticsearch/version",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
	}
}

// managerProxyProbe returns the probe for the proxy container.
func (c *managerComponent) managerProxyProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/voltron/api/health",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
	}
}

func KibanaEnabled(tenant *operatorv1.Tenant, installation *operatorv1.InstallationSpec) bool {
	enableKibana := !operatorv1.IsFIPSModeEnabled(installation.FIPSMode)
	if tenant.MultiTenant() {
		enableKibana = false
	}
	return enableKibana
}

// managerEnvVars returns the envvars for the manager container.
func (c *managerComponent) managerEnvVars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		// TODO: Prometheus URL will need to change.
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
		{Name: "ENABLE_KIBANA", Value: strconv.FormatBool(KibanaEnabled(c.cfg.Tenant, c.cfg.Installation))},
		// The manager supports two states of a product feature being unavailable: the product feature being feature-flagged off,
		// and the current license not enabling the feature. The compliance flag that we set on the manager container is a feature
		// flag, which we should set purely based on whether the compliance CR is present, ignoring the license status.
		{Name: "ENABLE_COMPLIANCE_REPORTS", Value: strconv.FormatBool(c.cfg.Compliance != nil)},
	}

	envs = append(envs, c.managerOAuth2EnvVars()...)
	return envs
}

// managerContainer returns the manager container.
func (c *managerComponent) managerContainer() corev1.Container {
	return corev1.Container{
		Name:            "tigera-manager",
		Image:           c.managerImage,
		ImagePullPolicy: ImagePullPolicy(),
		Env:             c.managerEnvVars(),
		LivenessProbe:   c.managerProbe(),
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    c.managerVolumeMounts(),
	}
}

// managerOAuth2EnvVars returns the OAuth2/OIDC envvars depending on the authentication type.
func (c *managerComponent) managerOAuth2EnvVars() []corev1.EnvVar {
	var envs []corev1.EnvVar

	if c.cfg.KeyValidatorConfig == nil {
		envs = []corev1.EnvVar{{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "Token"}}
	} else {
		envs = []corev1.EnvVar{
			{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "OIDC"},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: c.cfg.KeyValidatorConfig.ClientID()},
		}

		switch c.cfg.KeyValidatorConfig.(type) {
		case *DexKeyValidatorConfig:
			envs = append(envs, corev1.EnvVar{Name: "CNX_WEB_OIDC_AUTHORITY", Value: c.cfg.KeyValidatorConfig.Issuer()})
		case *tigerakvc.KeyValidatorConfig:
			envs = append(envs, corev1.EnvVar{Name: "CNX_WEB_OIDC_AUTHORITY", Value: ""})
		}
	}
	return envs
}

// voltronContainer returns the container for the manager proxy container - voltron.
func (c *managerComponent) voltronContainer() corev1.Container {
	var keyPath, certPath, intKeyPath, intCertPath, tunnelKeyPath, tunnelCertPath string
	var linseedKeyPath, linseedCertPath string
	if c.cfg.TLSKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.TLSKeyPair.VolumeMountKeyFilePath(), c.cfg.TLSKeyPair.VolumeMountCertificateFilePath()
	}
	if c.cfg.InternalTLSKeyPair != nil {
		intKeyPath, intCertPath = c.cfg.InternalTLSKeyPair.VolumeMountKeyFilePath(), c.cfg.InternalTLSKeyPair.VolumeMountCertificateFilePath()
	}
	if c.cfg.TunnelServerCert != nil {
		tunnelKeyPath, tunnelCertPath = c.cfg.TunnelServerCert.VolumeMountKeyFilePath(), c.cfg.TunnelServerCert.VolumeMountCertificateFilePath()
	}
	if c.cfg.VoltronLinseedKeyPair != nil {
		linseedKeyPath, linseedCertPath = c.cfg.VoltronLinseedKeyPair.VolumeMountKeyFilePath(), c.cfg.VoltronLinseedKeyPair.VolumeMountCertificateFilePath()
	}
	defaultForwardServer := "tigera-secure-es-gateway-http.tigera-elasticsearch.svc:9200"
	if c.cfg.Tenant.MultiTenant() {
		// Use the local namespace instead of tigera-elasticsearch.
		defaultForwardServer = fmt.Sprintf("tigera-secure-es-gateway-http.%s.svc:9200", c.cfg.Namespace)
	}

	env := []corev1.EnvVar{
		{Name: "VOLTRON_PORT", Value: defaultVoltronPort},
		{Name: "VOLTRON_COMPLIANCE_ENDPOINT", Value: fmt.Sprintf("https://compliance.%s.svc.%s", c.cfg.ComplianceNamespace, c.cfg.ClusterDomain)},
		{Name: "VOLTRON_LOGLEVEL", Value: "Info"},
		{Name: "VOLTRON_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain)},
		{Name: "VOLTRON_KIBANA_BASE_PATH", Value: fmt.Sprintf("/%s/", KibanaBasePath)},
		{Name: "VOLTRON_KIBANA_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_PROMETHEUS_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_COMPLIANCE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_DEX_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_QUERYSERVER_ENDPOINT", Value: fmt.Sprintf("https://%s.%s.svc:%d", QueryserverServiceName, QueryserverNamespace, QueryServerPort)},
		{Name: "VOLTRON_QUERYSERVER_BASE_PATH", Value: fmt.Sprintf("/api/v1/namespaces/%s/services/https:%s:%d/proxy/", QueryserverNamespace, QueryserverServiceName, QueryServerPort)},
		{Name: "VOLTRON_QUERYSERVER_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_HTTPS_KEY", Value: keyPath},
		{Name: "VOLTRON_HTTPS_CERT", Value: certPath},
		{Name: "VOLTRON_TUNNEL_KEY", Value: tunnelKeyPath},
		{Name: "VOLTRON_TUNNEL_CERT", Value: tunnelCertPath},
		{Name: "VOLTRON_INTERNAL_HTTPS_KEY", Value: intKeyPath},
		{Name: "VOLTRON_INTERNAL_HTTPS_CERT", Value: intCertPath},
		{Name: "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.cfg.ManagementCluster != nil)},
		{Name: "VOLTRON_TUNNEL_PORT", Value: defaultTunnelVoltronPort},
		{Name: "VOLTRON_DEFAULT_FORWARD_SERVER", Value: defaultForwardServer},
		{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: strconv.FormatBool(c.cfg.Compliance != nil && c.cfg.ComplianceLicenseActive)},
		{Name: "VOLTRON_FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode)},
	}

	if c.cfg.VoltronRouteConfig != nil {
		env = append(env, c.cfg.VoltronRouteConfig.EnvVars()...)
	}

	if c.cfg.ManagementCluster != nil {
		env = append(env, corev1.EnvVar{Name: "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", Value: strconv.FormatBool(c.cfg.ManagementCluster.Spec.TLS != nil && c.cfg.ManagementCluster.Spec.TLS.SecretName == ManagerTLSSecretName)})
		env = append(env, corev1.EnvVar{Name: "VOLTRON_LINSEED_SERVER_KEY", Value: linseedKeyPath})
		env = append(env, corev1.EnvVar{Name: "VOLTRON_LINSEED_SERVER_CERT", Value: linseedCertPath})
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("VOLTRON_")...)
	}

	// Determine the volume mounts to use. This varies based on the type of cluster.
	mounts := c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())
	mounts = append(mounts, corev1.VolumeMount{Name: ManagerTLSSecretName, MountPath: "/manager-tls", ReadOnly: true})
	if c.cfg.ManagementCluster != nil {
		mounts = append(mounts, c.cfg.InternalTLSKeyPair.VolumeMount(c.SupportedOSType()))
		mounts = append(mounts, c.cfg.TunnelServerCert.VolumeMount(c.SupportedOSType()))
		mounts = append(mounts, c.cfg.VoltronLinseedKeyPair.VolumeMount(c.SupportedOSType()))
	}

	linseedEndpointEnv := corev1.EnvVar{Name: "VOLTRON_LINSEED_ENDPOINT", Value: fmt.Sprintf("https://tigera-linseed.%s.svc.%s", ElasticsearchNamespace, c.cfg.ClusterDomain)}
	if c.cfg.Tenant != nil {
		// Configure the tenant id in order to read /write linseed data using the correct tenant ID
		// Multi-tenant and single tenant with external elastic needs this variable set
		if c.cfg.ExternalElastic {
			env = append(env, corev1.EnvVar{Name: "VOLTRON_TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}

		// Always configure the Tenant Claim for all multi-tenancy setups (single tenant and multi tenant)
		// This will check the tenant claim when a Bearer token is presented to Voltron
		// The actual value of the token is extracted from the tenant claim
		env = append(env, corev1.EnvVar{Name: "VOLTRON_REQUIRE_TENANT_CLAIM", Value: "true"})
		env = append(env, corev1.EnvVar{Name: "VOLTRON_TENANT_CLAIM", Value: c.cfg.Tenant.Spec.ID})

		if c.cfg.Tenant.MultiTenant() {
			env = append(env, corev1.EnvVar{Name: "VOLTRON_TENANT_NAMESPACE", Value: c.cfg.Tenant.Namespace})
			linseedEndpointEnv = corev1.EnvVar{Name: "VOLTRON_LINSEED_ENDPOINT", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", c.cfg.Tenant.Namespace)}
		}
	}
	env = append(env, linseedEndpointEnv)

	if c.cfg.VoltronRouteConfig != nil {
		mounts = append(mounts, c.cfg.VoltronRouteConfig.VolumeMounts()...)
	}

	return corev1.Container{
		Name:            VoltronName,
		Image:           c.proxyImage,
		ImagePullPolicy: ImagePullPolicy(),
		Env:             env,
		VolumeMounts:    mounts,
		LivenessProbe:   c.managerProxyProbe(),
		SecurityContext: securitycontext.NewNonRootContext(),
	}
}

// managerEsProxyContainer returns the ES proxy container
func (c *managerComponent) managerEsProxyContainer() corev1.Container {
	var keyPath, certPath string
	if c.cfg.InternalTLSKeyPair != nil {
		// This should never be nil, but we check it anyway just to be safe.
		keyPath, certPath = c.cfg.InternalTLSKeyPair.VolumeMountKeyFilePath(), c.cfg.InternalTLSKeyPair.VolumeMountCertificateFilePath()
	}

	env := []corev1.EnvVar{
		{Name: "ELASTIC_LICENSE_TYPE", Value: string(c.cfg.ESLicenseType)},
		{Name: "ELASTIC_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain)},
		{Name: "FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode)},
		{Name: "LINSEED_CLIENT_CERT", Value: certPath},
		{Name: "LINSEED_CLIENT_KEY", Value: keyPath},
		{Name: "ELASTIC_KIBANA_DISABLED", Value: strconv.FormatBool(!KibanaEnabled(c.cfg.Tenant, c.cfg.Installation))},
		{Name: "VOLTRON_URL", Value: fmt.Sprintf("https://tigera-manager.%s.svc:9443", c.cfg.Namespace)},
	}

	// Determine the Linseed location. Use code default unless in multi-tenant mode,
	// in which case use the Linseed in the current namespace.
	if c.cfg.Tenant != nil {

		if c.cfg.ExternalElastic {
			// A tenant was specified, ensure we set the tenant ID.
			env = append(env, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}

		if c.cfg.Tenant.MultiTenant() {
			// This cluster supports multiple tenants. Point the manager at the correct Linseed instance for this tenant.
			env = append(env, corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", c.cfg.Namespace)})
			env = append(env, corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: c.cfg.Namespace})
		}
	}

	volumeMounts := append(
		c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.InternalTLSKeyPair.VolumeMount(c.SupportedOSType()),
	)
	if c.cfg.ManagementCluster != nil {
		env = append(env, corev1.EnvVar{Name: "VOLTRON_CA_PATH", Value: certificatemanagement.TrustedCertBundleMountPath})
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("")...)
	}

	return corev1.Container{
		Name:            "tigera-es-proxy",
		Image:           c.esProxyImage,
		ImagePullPolicy: ImagePullPolicy(),
		LivenessProbe:   c.managerEsProxyProbe(),
		SecurityContext: securitycontext.NewNonRootContext(),
		Env:             env,
		VolumeMounts:    volumeMounts,
	}
}

// managerTolerations returns the tolerations for the Tigera Secure manager deployment pods.
func (c *managerComponent) managerTolerations() []corev1.Toleration {
	return append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
}

// managerService returns the service exposing the Tigera Secure web app.
func (c *managerComponent) managerService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ManagerServiceName,
			Namespace: c.cfg.Namespace,
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
				"k8s-app": ManagerDeploymentName,
			},
		},
	}
}

// managerServiceAccount creates the serviceaccount used by the Tigera Secure web app.
func managerServiceAccount(ns string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ManagerServiceAccount, Namespace: ns},
	}
}

func managerClusterRoleBinding(namespaces []string) client.Object {
	return rcomponents.ClusterRoleBinding(ManagerClusterRoleBinding, ManagerClusterRole, ManagerServiceAccount, namespaces)
}

func managerPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy("tigera-manager")
}

// managerClusterRole returns a clusterrole that allows authn/authz review requests.
func managerClusterRole(managementCluster, managedCluster, usePSP bool, kubernetesProvider operatorv1.Provider) *rbacv1.ClusterRole {
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
					"stagednetworkpolicies",
					"tier.stagednetworkpolicies",
				},
				Verbs: []string{"patch"},
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
			// Allow query server talk to Prometheus via the manager user.
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			{
				// Add access to Linseed APIs.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"flows",
					"flowlogs",
					"bgplogs",
					"auditlogs",
					"dnsflows",
					"dnslogs",
					"l7flows",
					"l7logs",
					"events",
					"processes",
				},
				Verbs: []string{"get"},
			},
			{
				// Dismiss events.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
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

	if usePSP {
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

	if kubernetesProvider == operatorv1.ProviderOpenShift {
		cr.Rules = append(cr.Rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{PSSPrivileged},
			},
		)
	}

	return cr
}

// TODO: Can we get rid of this and instead just bind to default ones?
func (c *managerComponent) securityContextConstraints() *ocsv1.SecurityContextConstraints {
	privilegeEscalation := false
	return &ocsv1.SecurityContextConstraints{
		TypeMeta:                 metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
		ObjectMeta:               metav1.ObjectMeta{Name: c.cfg.Namespace},
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
		Users:                    []string{fmt.Sprintf("system:serviceaccount:%s:tigera-manager", c.cfg.Namespace)},
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

// Allow users to access Calico Enterprise Manager.
func (c *managerComponent) managerAllowTigeraNetworkPolicy() *v3.NetworkPolicy {
	networkpolicyHelper := networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace)
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ManagerEntityRule(),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: TigeraAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      v3.EntityRule{},
			Destination: networkpolicyHelper.ESGatewayEntityRule(),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      v3.EntityRule{},
			Destination: networkpolicyHelper.LinseedEntityRule(),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ComplianceServerEntityRule(),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: DexEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: PacketCaptureEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.PrometheusEntityRule,
	})

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				// This policy allows access to Calico Enterprise Manager from anywhere
				Nets: []string{"0.0.0.0/0"},
			},
			Destination: v3.EntityRule{
				// By default, Calico Enterprise Manager is accessed over https
				Ports: networkpolicy.Ports(managerTargetPort),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				// This policy allows access to Calico Enterprise Manager from anywhere
				Nets: []string{"::/0"},
			},
			Destination: v3.EntityRule{
				// By default, Calico Enterprise Manager is accessed over https
				Ports: networkpolicy.Ports(managerTargetPort),
			},
		},
	}

	voltronTunnelPort, err := strconv.ParseUint(defaultTunnelVoltronPort, 10, 16)
	if err == nil {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				// This policy is used for multi-cluster management to establish a tunnel from another cluster.
				Ports: networkpolicy.Ports(uint16(voltronTunnelPort)),
			},
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ManagerPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(ManagerDeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}

// managerClusterWideSettingsGroup returns a UISettingsGroup with the description "cluster-wide settings"
//
// Calico Enterprise only
func managerClusterWideSettingsGroup() *v3.UISettingsGroup {
	return &v3.UISettingsGroup{
		TypeMeta: metav1.TypeMeta{Kind: "UISettingsGroup", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerClusterSettings,
		},
		Spec: v3.UISettingsGroupSpec{
			Description: "Cluster Settings",
		},
	}
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

// managerClusterWideTigeraLayer returns a UISettings layer belonging to the cluster-wide settings group that contains
// all of the tigera namespaces.
//
// Calico Enterprise only
func managerClusterWideTigeraLayer() *v3.UISettings {
	namespaces := []string{
		"tigera-compliance",
		"tigera-dex",
		"tigera-dpi",
		"tigera-eck-operator",
		"tigera-elasticsearch",
		"tigera-fluentd",
		"tigera-guardian",
		"tigera-intrusion-detection",
		"tigera-kibana",
		"tigera-manager",
		"tigera-operator",
		"tigera-packetcapture",
		"tigera-policy-recommendation",
		"tigera-prometheus",
		"tigera-system",
		"calico-system",
		"tigera-firewall-controller",
		"calico-cloud",
		"tigera-image-assurance",
		"tigera-runtime-security",
		"tigera-skraper",
	}
	nodes := make([]v3.UIGraphNode, len(namespaces))
	for i := range namespaces {
		ns := namespaces[i]
		nodes[i] = v3.UIGraphNode{
			ID:   "namespace/" + ns,
			Type: "namespace",
			Name: ns,
		}
	}

	return &v3.UISettings{
		TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerClusterSettingsLayerTigera,
		},
		Spec: v3.UISettingsSpec{
			Group:       "cluster-settings",
			Description: "Tigera Infrastructure",
			Layer: &v3.UIGraphLayer{
				Nodes: nodes,
			},
		},
	}
}

// managerClusterWideDefaultView returns a UISettings view belonging to the cluster-wide settings group that shows
// everything and uses the tigera-infrastructure layer.
//
// Calico Enterprise only
func managerClusterWideDefaultView() *v3.UISettings {
	return &v3.UISettings{
		TypeMeta: metav1.TypeMeta{Kind: "UISettings", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ManagerClusterSettingsViewDefault,
		},
		Spec: v3.UISettingsSpec{
			Group:       "cluster-settings",
			Description: "Default",
			View: &v3.UIGraphView{
				Nodes: []v3.UIGraphNodeView{{
					UIGraphNode: v3.UIGraphNode{
						ID:   "layer/cluster-settings.layer.tigera-infrastructure",
						Type: "layer",
						Name: "cluster-settings.layer.tigera-infrastructure",
					},
				}},
			},
		},
	}
}
