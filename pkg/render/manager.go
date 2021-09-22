// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	"github.com/tigera/operator/pkg/render/common/podaffinity"

	ocsv1 "github.com/openshift/api/security/v1"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/dns"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rkibana "github.com/tigera/operator/pkg/render/common/kibana"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritycontext"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	managerPort                      = 9443
	managerTargetPort                = 9443
	ManagerServiceName               = "tigera-manager"
	ManagerNamespace                 = "tigera-manager"
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

	ElasticsearchManagerUserSecret   = "tigera-ee-manager-elasticsearch-access"
	TlsSecretHashAnnotation          = "hash.operator.tigera.io/tls-secret"
	ManagerInternalTLSHashAnnotation = "hash.operator.tigera.io/internal-tls-secret"

	KibanaTLSHashAnnotation         = "hash.operator.tigera.io/kibana-secrets"
	ElasticsearchUserHashAnnotation = "hash.operator.tigera.io/elasticsearch-user"
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
	keyValidatorConfig authentication.KeyValidatorConfig,
	esSecrets []*corev1.Secret,
	kibanaSecrets []*corev1.Secret,
	complianceServerCertSecret *corev1.Secret,
	packetCaptureServerCertSecret *corev1.Secret,
	esClusterConfig *relasticsearch.ClusterConfig,
	tlsKeyPair *corev1.Secret,
	pullSecrets []*corev1.Secret,
	openshift bool,
	installation *operatorv1.InstallationSpec,
	managementCluster *operatorv1.ManagementCluster,
	tunnelSecret *corev1.Secret,
	internalTrafficSecret *corev1.Secret,
	clusterDomain string,
	esLicenseType ElasticsearchLicenseType,
	replicas *int32,
) (Component, error) {
	var tlsSecrets []*corev1.Secret
	tlsAnnotations := map[string]string{
		KibanaTLSHashAnnotation: rmeta.SecretsAnnotationHash(kibanaSecrets...),
	}
	var tlsAnnotation string
	if installation.CertificateManagement == nil {
		tlsSecrets = append(tlsSecrets, tlsKeyPair)
		tlsSecrets = append(tlsSecrets, secret.CopyToNamespace(ManagerNamespace, tlsKeyPair)...)
		tlsAnnotation = rmeta.AnnotationHash(tlsKeyPair.Data)
	}
	tlsAnnotations[TlsSecretHashAnnotation] = tlsAnnotation

	if keyValidatorConfig != nil {
		tlsSecrets = append(tlsSecrets, keyValidatorConfig.RequiredSecrets(ManagerNamespace)...)
		for key, value := range keyValidatorConfig.RequiredAnnotations() {
			tlsAnnotations[key] = value
		}
	}

	if managementCluster != nil {
		// Copy tunnelSecret and internalTrafficSecret to TLS secrets
		// tunnelSecret contains the ca cert to generate guardian certificates
		// internalTrafficCert containts the cert used to communicated within the management K8S cluster
		tlsSecrets = append(tlsSecrets, secret.CopyToNamespace(ManagerNamespace, tunnelSecret)...)
		tlsSecrets = append(tlsSecrets, secret.CopyToNamespace(ManagerNamespace, internalTrafficSecret)...)
		tlsAnnotations[voltronTunnelHashAnnotation] = rmeta.AnnotationHash(tunnelSecret.Data)
		tlsAnnotations[ManagerInternalTLSHashAnnotation] = rmeta.AnnotationHash(internalTrafficSecret.Data)
	}
	return &managerComponent{
		keyValidatorConfig:            keyValidatorConfig,
		esSecrets:                     esSecrets,
		kibanaSecrets:                 kibanaSecrets,
		complianceServerCertSecret:    complianceServerCertSecret,
		packetCaptureServerCertSecret: packetCaptureServerCertSecret,
		esClusterConfig:               esClusterConfig,
		tlsSecrets:                    tlsSecrets,
		tlsAnnotations:                tlsAnnotations,
		pullSecrets:                   pullSecrets,
		openshift:                     openshift,
		clusterDomain:                 clusterDomain,
		installation:                  installation,
		managementCluster:             managementCluster,
		esLicenseType:                 esLicenseType,
		replicas:                      replicas,
	}, nil
}

type managerComponent struct {
	keyValidatorConfig            authentication.KeyValidatorConfig
	esSecrets                     []*corev1.Secret
	kibanaSecrets                 []*corev1.Secret
	complianceServerCertSecret    *corev1.Secret
	packetCaptureServerCertSecret *corev1.Secret
	esClusterConfig               *relasticsearch.ClusterConfig
	tlsSecrets                    []*corev1.Secret
	tlsAnnotations                map[string]string
	pullSecrets                   []*corev1.Secret
	openshift                     bool
	clusterDomain                 string
	installation                  *operatorv1.InstallationSpec
	managementCluster             *operatorv1.ManagementCluster
	esLicenseType                 ElasticsearchLicenseType
	managerImage                  string
	proxyImage                    string
	esProxyImage                  string
	csrInitImage                  string
	replicas                      *int32
}

func (c *managerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.installation.Registry
	path := c.installation.ImagePath
	prefix := c.installation.ImagePrefix
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

	if c.installation.CertificateManagement != nil {
		c.csrInitImage, err = ResolveCSRInitImage(c.installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
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
		CreateNamespace(ManagerNamespace, c.installation.KubernetesProvider),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, c.pullSecrets...)...)...)

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
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, c.esSecrets...)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, c.kibanaSecrets...)...)...)
	if c.complianceServerCertSecret != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, c.complianceServerCertSecret)...)...)
	}
	if c.packetCaptureServerCertSecret != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, c.packetCaptureServerCertSecret)...)...)
	}
	objs = append(objs, c.managerDeployment())
	if c.keyValidatorConfig != nil {
		objs = append(objs, configmap.ToRuntimeObjects(c.keyValidatorConfig.RequiredConfigMaps(ManagerNamespace)...)...)
	}

	var toDelete []client.Object
	if c.installation.CertificateManagement != nil {
		objs = append(objs, CSRClusterRoleBinding(ManagerServiceName, ManagerNamespace))
		// If we want to use certificate management, we should clean up any existing secrets that have been created by the operator.
		secretToDelete := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ManagerTLSSecretName,
				Namespace: common.OperatorNamespace(),
			},
		}
		toDelete = append(toDelete, secretToDelete)
		toDelete = append(toDelete, secret.ToRuntimeObjects(secret.CopyToNamespace(ManagerNamespace, secretToDelete)...)...)
	}

	return objs, toDelete
}

func (c *managerComponent) Ready() bool {
	return true
}

// managerDeployment creates a deployment for the Tigera Secure manager component.
func (c *managerComponent) managerDeployment() *appsv1.Deployment {
	annotations := make(map[string]string)

	if c.complianceServerCertSecret != nil {
		annotations[complianceServerTLSHashAnnotation] = rmeta.AnnotationHash(c.complianceServerCertSecret.Data)
	}

	if c.packetCaptureServerCertSecret != nil {
		annotations[PacketCaptureTLSHashAnnotation] = rmeta.AnnotationHash(c.packetCaptureServerCertSecret.Data)
	}

	// Add a hash of the Secret to ensure if it changes the manager will be
	// redeployed.	The following secrets are annotated:
	// manager-tls : cert used for tigera UI
	// internal-manager-tls : cert used for internal communication within K8S cluster
	// tigera-management-cluster-connection : cert used to generate guardian certificates
	for k, v := range c.tlsAnnotations {
		annotations[k] = v
	}

	var initContainers []corev1.Container
	if c.installation.CertificateManagement != nil {
		initContainers = append(initContainers, CreateCSRInitContainer(
			c.installation.CertificateManagement,
			c.csrInitImage,
			ManagerTLSSecretName,
			ManagerServiceName,
			ManagerSecretKeyName,
			ManagerSecretCertName,
			dns.GetServiceDNSNames(ManagerServiceName, ManagerNamespace, c.clusterDomain),
			ManagerNamespace))
	}

	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-manager",
			Namespace: ManagerNamespace,
			Labels: map[string]string{
				"k8s-app": "tigera-manager",
			},
			Annotations: annotations,
		},
		Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
			NodeSelector:       c.installation.ControlPlaneNodeSelector,
			ServiceAccountName: ManagerServiceAccount,
			Tolerations:        c.managerTolerations(),
			ImagePullSecrets:   secret.GetReferenceList(c.pullSecrets),
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				relasticsearch.ContainerDecorate(c.managerContainer(), c.esClusterConfig.ClusterName(), ElasticsearchManagerUserSecret, c.clusterDomain, c.SupportedOSType()),
				relasticsearch.ContainerDecorate(c.managerEsProxyContainer(), c.esClusterConfig.ClusterName(), ElasticsearchManagerUserSecret, c.clusterDomain, c.SupportedOSType()),
				c.managerProxyContainer(),
			},
			Volumes: c.managerVolumes(),
		}),
	}, c.esClusterConfig, c.esSecrets).(*corev1.PodTemplateSpec)

	if c.replicas != nil && *c.replicas > 1 {
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
			Replicas: c.replicas,
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
	if c.keyValidatorConfig != nil {
		return c.keyValidatorConfig.RequiredVolumeMounts()
	}
	return []corev1.VolumeMount{}
}

// managerVolumes returns the volumes for the Tigera Secure manager component.
func (c *managerComponent) managerVolumes() []corev1.Volume {
	var certificateManagement *operatorv1.CertificateManagement
	if c.installation.CertificateManagement != nil {
		certificateManagement = c.installation.CertificateManagement
	}
	tlsVolumeSource := certificateVolumeSource(certificateManagement, ManagerTLSSecretName)
	v := []corev1.Volume{
		{
			Name:         ManagerTLSSecretName,
			VolumeSource: tlsVolumeSource,
		},
		{
			Name: KibanaPublicCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: KibanaPublicCertSecret,
				},
			},
		},
	}

	if c.complianceServerCertSecret != nil {
		v = append(v, corev1.Volume{
			Name: ComplianceServerCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					Items: []corev1.KeyToPath{{
						Key:  "tls.crt",
						Path: "tls.crt",
					}},
					SecretName: ComplianceServerCertSecret,
				},
			},
		})
	}

	if c.packetCaptureServerCertSecret != nil {
		v = append(v, corev1.Volume{
			Name: PacketCaptureCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					Items: []corev1.KeyToPath{{
						Key:  "tls.crt",
						Path: "tls.crt",
					}},
					SecretName: PacketCaptureCertSecret,
				},
			},
		})
	}

	if c.managementCluster != nil {
		v = append(v,
			corev1.Volume{
				// We only want to mount the cert, not the private key to es-proxy to establish a connection with voltron.
				Name: ManagerInternalTLSSecretCertName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: ManagerInternalTLSSecretName,
						Items: []corev1.KeyToPath{
							{
								Key:  "cert",
								Path: "cert",
							},
						},
					},
				},
			},
			corev1.Volume{
				// We mount the full secret to be shared with Voltron.
				Name: ManagerInternalTLSSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: ManagerInternalTLSSecretName,
					},
				},
			},
			corev1.Volume{
				// Append volume for tunnel certificate
				Name: VoltronTunnelSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: VoltronTunnelSecretName,
					},
				},
			},
		)
	}
	if c.keyValidatorConfig != nil {
		v = append(v, c.keyValidatorConfig.RequiredVolumes()...)
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
		{Name: "ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.managementCluster != nil)},
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

	if c.keyValidatorConfig == nil {
		envs = []corev1.EnvVar{{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "Token"}}
	} else {
		envs = []corev1.EnvVar{
			{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: "OIDC"},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: c.keyValidatorConfig.ClientID()}}

		switch c.keyValidatorConfig.(type) {
		case *DexKeyValidatorConfig:
			envs = append(envs, corev1.EnvVar{Name: "CNX_WEB_OIDC_AUTHORITY", Value: c.keyValidatorConfig.Issuer()})
		case *tigerakvc.KeyValidatorConfig:
			envs = append(envs, corev1.EnvVar{Name: "CNX_WEB_OIDC_AUTHORITY", Value: ""})
		}
	}
	return envs
}

// managerProxyContainer returns the container for the manager proxy container.
func (c *managerComponent) managerProxyContainer() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "VOLTRON_PORT", Value: defaultVoltronPort},
		{Name: "VOLTRON_COMPLIANCE_ENDPOINT", Value: fmt.Sprintf("https://compliance.%s.svc.%s", ComplianceNamespace, c.clusterDomain)},
		{Name: "VOLTRON_LOGLEVEL", Value: "Info"},
		{Name: "VOLTRON_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.clusterDomain)},
		{Name: "VOLTRON_KIBANA_BASE_PATH", Value: fmt.Sprintf("/%s/", KibanaBasePath)},
		{Name: "VOLTRON_KIBANA_CA_BUNDLE_PATH", Value: "/certs/kibana/tls.crt"},
		{Name: "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: strconv.FormatBool(c.managementCluster != nil)},
		{Name: "VOLTRON_TUNNEL_PORT", Value: defaultTunnelVoltronPort},
		{Name: "VOLTRON_DEFAULT_FORWARD_SERVER", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc:9200"},
	}

	if c.keyValidatorConfig != nil {
		env = append(env, c.keyValidatorConfig.RequiredEnv("VOLTRON_")...)
	}

	if c.complianceServerCertSecret == nil {
		env = append(env, corev1.EnvVar{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: "false"})
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
		{Name: ManagerTLSSecretName, MountPath: "/certs/https", ReadOnly: true},
		{Name: KibanaPublicCertSecret, MountPath: "/certs/kibana", ReadOnly: true},
	}

	if c.complianceServerCertSecret != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: ComplianceServerCertSecret, MountPath: "/certs/compliance", ReadOnly: true})
	}

	if c.packetCaptureServerCertSecret != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: PacketCaptureCertSecret, MountPath: "/certs/packetcapture", ReadOnly: true})
	}

	if c.managementCluster != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: ManagerInternalTLSSecretName, MountPath: "/certs/internal", ReadOnly: true})
		mounts = append(mounts, corev1.VolumeMount{Name: VoltronTunnelSecretName, MountPath: "/certs/tunnel", ReadOnly: true})
	}

	if c.keyValidatorConfig != nil {
		mounts = append(mounts, c.keyValidatorConfig.RequiredVolumeMounts()...)
	}

	return mounts
}

// managerEsProxyContainer returns the ES proxy container
func (c *managerComponent) managerEsProxyContainer() corev1.Container {
	var volumeMounts []corev1.VolumeMount
	if c.managementCluster != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{Name: ManagerInternalTLSSecretCertName, MountPath: "/manager-tls", ReadOnly: true})
	}

	env := []corev1.EnvVar{
		{Name: "ELASTIC_LICENSE_TYPE", Value: string(c.esLicenseType)},
		{Name: "ELASTIC_VERSION", Value: components.ComponentEckElasticsearch.Version},
		{Name: "ELASTIC_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.clusterDomain)},
	}

	if c.keyValidatorConfig != nil {
		env = append(env, c.keyValidatorConfig.RequiredEnv("")...)
		volumeMounts = append(volumeMounts, c.keyValidatorConfig.RequiredVolumeMounts()...)
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
	return append(c.installation.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly)
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
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts", "namespaces", "nodes", "events"},
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
