// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package kibana

import (
	"fmt"
	"net/url"
	"strings"

	cmnv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/common/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (

	// TigeraKibanaCertSecret is the TLS key pair that is mounted by the Kibana pods.
	TigeraKibanaCertSecret = "tigera-secure-kibana-cert"

	CRName       = "tigera-secure"
	ObjectName   = "tigera-kibana"
	Namespace    = ObjectName
	BasePath     = ObjectName
	ServiceName  = "tigera-secure-kb-http"
	DefaultRoute = "/app/kibana#/dashboards?%s&title=%s"
	PolicyName   = networkpolicy.TigeraComponentPolicyPrefix + "kibana-access"
	Port         = 5601

	// TODO: ALINA Check annotations
	TLSAnnotationHash = "hash.operator.tigera.io/kb-secrets"

	TimeFilter                       = "_g=(time:(from:now-24h,to:now))"
	FlowsDashboardName               = "Calico Enterprise Flow Logs"
	MultiTenantCredentialsSecretName = "tigera-kibana-elasticsearch-credentials"
)

var (
	EntityRule = networkpolicy.CreateEntityRule(Namespace, CRName, Port)
)

// Kibana renders the components necessary for kibana and elasticsearch
func Kibana(cfg *Configuration) render.Component {
	if cfg.Enabled && operatorv1.IsFIPSModeEnabled(cfg.Installation.FIPSMode) {
		// This branch should only be hit if there is a coding bug in the controller, as Enabled
		// should already take into account FIPS.
		panic("BUG: Kibana is not supported in FIPS mode")
	}
	return &kibana{
		cfg: cfg,
	}
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	LogStorage      *operatorv1.LogStorage
	Installation    *operatorv1.InstallationSpec
	Kibana          *kbv1.Kibana
	KibanaKeyPair   certificatemanagement.KeyPairInterface
	PullSecrets     []*corev1.Secret
	Provider        operatorv1.Provider
	KbService       *corev1.Service
	ClusterDomain   string
	BaseURL         string // BaseUrl is where the manager is reachable, for setting Kibana publicBaseUrl
	TrustedBundle   certificatemanagement.TrustedBundleRO
	UnusedTLSSecret *corev1.Secret
	Enabled         bool
	Tenant          *operatorv1.Tenant
	Namespace       string

	// Secret containing client certificate and key for connecting to the Elastic cluster. If configured,
	// mTLS is used between Challenger and the external Elastic cluster.
	ChallengerClientCertificate *corev1.Secret
	ExternalElasticURL          *url.URL
	KibanaUsername              string

	// Whether the cluster supports pod security policies.
	UsePSP bool
}

type kibana struct {
	cfg             *Configuration
	kibanaSecrets   []*corev1.Secret
	kibanaImage     string
	challengerImage string
	csrImage        string
}

func (k *kibana) ResolveImages(is *operatorv1.ImageSet) error {
	reg := k.cfg.Installation.Registry
	path := k.cfg.Installation.ImagePath
	prefix := k.cfg.Installation.ImagePrefix

	var err error
	errMsgs := make([]string, 0)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	k.kibanaImage, err = components.GetReference(components.ComponentKibana, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if k.cfg.Tenant.MultiTenant() {
		k.challengerImage, err = components.GetReference(components.ComponentESGateway, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if k.cfg.Installation.CertificateManagement != nil {
		k.csrImage, err = certificatemanagement.ResolveCSRInitImage(k.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (k *kibana) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (k *kibana) Objects() ([]client.Object, []client.Object) {
	var toCreate, toDelete []client.Object

	// Delete a previous Kibana CR if LogStorage is in the process of being deleted
	if k.cfg.LogStorage != nil && k.cfg.LogStorage.DeletionTimestamp != nil {
		if k.cfg.Kibana != nil {
			if k.cfg.Kibana.DeletionTimestamp == nil {
				toDelete = append(toDelete, k.cfg.Kibana)
			}
		}
		return toCreate, toDelete
	}

	if k.cfg.UsePSP {
		if k.cfg.Enabled {
			toCreate = append(toCreate,
				k.clusterRoleBinding(),
				k.clusterRole(),
				k.kibanaPodSecurityPolicy(),
			)
		}
	}

	if k.cfg.Enabled {
		// Kibana CRs
		// In order to use restricted, we need to change elastic-internal-init-config:
		// - securityContext.allowPrivilegeEscalation=false
		// - securityContext.capabilities.drop=["ALL"]
		// - securityContext.runAsNonRoot=true
		// - securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost"
		// We only create the certain objects in a zero tenant or single tenant installation
		// For example, tigera-kibana namespace, pull secrets and default deny
		// For multi-tenancy, these are already created by other renderers
		if !k.cfg.Tenant.MultiTenant() {
			toCreate = append(toCreate, render.CreateNamespace(Namespace, k.cfg.Installation.KubernetesProvider, render.PSSBaseline))
			if len(k.cfg.PullSecrets) > 0 {
				toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(Namespace, k.cfg.PullSecrets...)...)...)
			}
			toCreate = append(toCreate, networkpolicy.AllowTigeraDefaultDeny(Namespace))
		}
		toCreate = append(toCreate, k.allowTigeraPolicy())
		toCreate = append(toCreate, k.serviceAccount())
		if len(k.kibanaSecrets) > 0 {
			toCreate = append(toCreate, secret.ToRuntimeObjects(k.kibanaSecrets...)...)
		}
		toCreate = append(toCreate, k.kibanaCR())
		// TODO: ALINA: I think we do the same in Linseed
		if k.cfg.ChallengerClientCertificate != nil {
			// If using External ES, we need to copy the client certificates into the tenant namespace to be mounted.
			toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(k.cfg.Namespace, k.cfg.ChallengerClientCertificate)...)...)
		}
	} else {
		toDelete = append(toDelete, k.kibanaCR())
	}

	if k.cfg.KbService != nil && k.cfg.KbService.Spec.Type == corev1.ServiceTypeExternalName {
		toDelete = append(toDelete, k.cfg.KbService)
	}

	if k.cfg.Installation.CertificateManagement != nil {
		if k.cfg.KibanaKeyPair != nil && k.cfg.KibanaKeyPair.UseCertificateManagement() {
			// We need to render a secret. It won't ever be used by Kibana for TLS, but is needed to pass ECK's checks.
			// If the secret changes / gets reconciled, it will not trigger a re-render of Kibana.
			unusedSecret := k.cfg.KibanaKeyPair.Secret(k.cfg.Namespace)
			unusedSecret.Data = k.cfg.UnusedTLSSecret.Data
			toCreate = append(toCreate, unusedSecret)
		}
	} else if k.cfg.UnusedTLSSecret != nil {
		toDelete = append(toDelete, k.cfg.UnusedTLSSecret)
	}

	return toCreate, toDelete
}

func (k *kibana) Ready() bool {
	return true
}

func (k *kibana) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ObjectName,
			Namespace: k.cfg.Namespace,
		},
	}
}

func (k *kibana) kibanaCR() *kbv1.Kibana {
	server := map[string]interface{}{
		"basePath":        fmt.Sprintf("/%s", BasePath),
		"rewriteBasePath": true,
		"defaultRoute":    fmt.Sprintf(DefaultRoute, TimeFilter, url.PathEscape(FlowsDashboardName)),
	}

	if k.cfg.BaseURL != "" {
		server["publicBaseUrl"] = fmt.Sprintf("%s/%s", k.cfg.BaseURL, BasePath)
	}

	config := map[string]interface{}{
		"server":                             server,
		"xpack.security.session.lifespan":    "8h",
		"xpack.security.session.idleTimeout": "30m",
		"tigera": map[string]interface{}{
			"enabled":        true,
			"licenseEdition": "enterpriseEdition",
		},
		// Telemetry is unwanted for the majority of our customers and if enabled can cause blocked flows. This flag
		// can still be overwritten in the Kibana Settings if the user desires it.
		"telemetry.optIn": false,
	}

	if k.cfg.Tenant.MultiTenant() {
		config["elasticsearch.hosts"] = "http://localhost:8080"
		config["elasticsearch.ssl.verificationMode"] = "none"
		config["elasticsearch.username"] = k.cfg.KibanaUsername
	} else {
		config["elasticsearch.ssl.certificateAuthorities"] = []string{"/usr/share/kibana/config/elasticsearch-certs/tls.crt"}
	}

	var initContainers []corev1.Container
	var volumes []corev1.Volume
	var automountToken bool
	var volumeMounts []corev1.VolumeMount
	if k.cfg.Installation.CertificateManagement != nil {
		config["elasticsearch.ssl.certificateAuthorities"] = []string{"/mnt/elastic-internal/http-certs/ca.crt"}
		automountToken = true
		csrInitContainer := certificatemanagement.CreateCSRInitContainer(
			k.cfg.Installation.CertificateManagement,
			render.CSRVolumeNameHTTP,
			k.csrImage,
			render.CSRVolumeNameHTTP,
			render.ElasticsearchServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			dns.GetServiceDNSNames(ServiceName, k.cfg.Namespace, k.cfg.ClusterDomain),
			k.cfg.Namespace)

		initContainers = append(initContainers, csrInitContainer)
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      render.CSRVolumeNameHTTP,
			MountPath: "/mnt/elastic-internal/http-certs/",
		})
		volumes = append(volumes,
			corev1.Volume{
				Name: render.CSRVolumeNameHTTP,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
			// Volume where we place the ca cert.
			corev1.Volume{
				Name: render.CAVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		)
	}

	count := int32(1)
	if k.cfg.Installation.ControlPlaneReplicas != nil {
		count = *k.cfg.Installation.ControlPlaneReplicas
	}

	containers := []corev1.Container{
		{
			Name: "kibana",
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: fmt.Sprintf("/%s/login", BasePath),
						Port: intstr.IntOrString{
							IntVal: Port,
						},
						Scheme: corev1.URISchemeHTTPS,
					},
				},
			},
			SecurityContext: securitycontext.NewNonRootContext(),
			VolumeMounts:    volumeMounts,
		},
	}

	if k.cfg.Tenant.MultiTenant() {
		volumes = append(volumes, k.cfg.TrustedBundle.Volume())
		volumeMounts = append(volumeMounts, k.cfg.TrustedBundle.VolumeMounts(k.SupportedOSType())...)
		if k.cfg.ChallengerClientCertificate != nil {
			// Add a volume for the required client certificate and key.
			volumes = append(volumes, corev1.Volume{
				Name: logstorage.ExternalCertsVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: logstorage.ExternalCertsSecret,
					},
				},
			})
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      logstorage.ExternalCertsVolumeName,
				MountPath: "/certs/elasticsearch",
				ReadOnly:  true,
			})
		}

		containers = append(containers, corev1.Container{
			Name: "challenger",
			Env: []corev1.EnvVar{
				{
					Name:  "ES_GATEWAY_LOG_LEVEL",
					Value: "INFO",
				},
				{
					Name:  "ES_GATEWAY_KIBANA_CATCH_ALL_ROUTE",
					Value: "/",
				},
				{
					Name:  "ES_GATEWAY_ELASTIC_ENDPOINT",
					Value: k.cfg.ExternalElasticURL.String(),
				},
				{
					Name:  "ES_GATEWAY_ELASTIC_CA_BUNDLE_PATH",
					Value: k.cfg.TrustedBundle.MountPath(),
				},
				{
					Name:  "ES_GATEWAY_ELASTIC_CLIENT_KEY_PATH",
					Value: "/certs/elasticsearch/client.key",
				},
				{
					Name:  "ES_GATEWAY_ELASTIC_CLIENT_CERT_PATH",
					Value: "/certs/elasticsearch/client.crt",
				},
				{
					Name:  "ES_GATEWAY_ENABLE_ELASTIC_MUTUAL_TLS",
					Value: "true",
				},
				{
					Name:  "TENANT_ID",
					Value: k.cfg.Tenant.Spec.ID,
				},
			},
			Command: []string{
				"/usr/bin/es-gateway", "-run-as-challenger",
			},
			Image:           k.challengerImage,
			SecurityContext: securitycontext.NewNonRootContext(),
			VolumeMounts:    volumeMounts,
		})
	}

	kibana := &kbv1.Kibana{
		TypeMeta: metav1.TypeMeta{Kind: "Kibana", APIVersion: "kibana.k8s.elastic.co/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CRName,
			Namespace: k.cfg.Namespace,
			Labels: map[string]string{
				"k8s-app": CRName,
			},
		},
		Spec: kbv1.KibanaSpec{
			Version: components.ComponentEckKibana.Version,
			Image:   k.kibanaImage,
			Config: &cmnv1.Config{
				Data: config,
			},
			Count: count,
			HTTP: cmnv1.HTTPConfig{
				TLS: cmnv1.TLSOptions{
					Certificate: cmnv1.SecretRef{
						SecretName: TigeraKibanaCertSecret,
					},
				},
			},
			PodTemplate: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: k.cfg.Namespace,
					Annotations: map[string]string{
						TLSAnnotationHash: rmeta.SecretsAnnotationHash(k.kibanaSecrets...),
					},
					Labels: map[string]string{
						"name":    CRName,
						"k8s-app": CRName,
					},
				},
				Spec: corev1.PodSpec{
					ImagePullSecrets:             secret.GetReferenceList(k.cfg.PullSecrets),
					ServiceAccountName:           ObjectName,
					NodeSelector:                 k.cfg.Installation.ControlPlaneNodeSelector,
					Tolerations:                  k.cfg.Installation.ControlPlaneTolerations,
					InitContainers:               initContainers,
					AutomountServiceAccountToken: &automountToken,
					Containers:                   containers,
					Volumes:                      volumes,
				},
			},
		},
	}

	if !k.cfg.Tenant.MultiTenant() {
		kibana.Spec.ElasticsearchRef = cmnv1.ObjectSelector{
			Name:      render.ElasticsearchName,
			Namespace: render.ElasticsearchNamespace,
		}
	}

	if k.cfg.Tenant.MultiTenant() {
		kibana.Spec.SecureSettings = []cmnv1.SecretSource{
			{
				SecretName: MultiTenantCredentialsSecretName,
			},
		}
	}

	if k.cfg.Installation.ControlPlaneReplicas != nil && *k.cfg.Installation.ControlPlaneReplicas > 1 {
		kibana.Spec.PodTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(CRName, Namespace)
	}

	if k.cfg.LogStorage != nil {
		if overrides := k.cfg.LogStorage.Spec.Kibana; overrides != nil {
			rcomponents.ApplyKibanaOverrides(kibana, overrides)
		}
	}

	return kibana
}

func (k *kibana) clusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: ObjectName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{ObjectName},
			},
		},
	}
}

func (k *kibana) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: ObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ObjectName,
				Namespace: k.cfg.Namespace,
			},
		},
	}
}

func (k *kibana) kibanaPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy(ObjectName)
}

// Allow access to Kibana
func (k *kibana) allowTigeraPolicy() *v3.NetworkPolicy {
	networkPolicyHelper := networkpolicy.Helper(k.cfg.Tenant.MultiTenant(), k.cfg.Namespace)
	var egressRules []v3.Rule
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, k.cfg.Provider == operatorv1.ProviderOpenShift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
	}...)

	if k.cfg.Tenant.MultiTenant() {
		// Allow egress traffic to the external Elasticsearch.
		egressRules = append(egressRules,
			v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Ports:   []numorstring.Port{{MinPort: 443, MaxPort: 443}},
					Domains: []string{k.cfg.ExternalElasticURL.Hostname()},
				},
			},
		)
	} else {
		// Allow egress traffic to ES Gateway and Elastic
		egressRules = append(egressRules,
			v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      v3.EntityRule{},
				Destination: render.ElasticsearchEntityRule,
			},
			v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Destination: networkpolicy.DefaultHelper().ESGatewayEntityRule(),
			})
	}

	kibanaPortIngressDestination := v3.EntityRule{
		Ports: networkpolicy.Ports(Port),
	}

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				// This policy allows access to Kibana from anywhere.
				Nets: []string{"0.0.0.0/0"},
			},
			Destination: kibanaPortIngressDestination,
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				// This policy allows access to Kibana from anywhere.
				Nets: []string{"::/0"},
			},
			Destination: kibanaPortIngressDestination,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkPolicyHelper.DashboardInstallerSourceEntityRule(),
			Destination: kibanaPortIngressDestination,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.ECKOperatorSourceEntityRule,
			Destination: kibanaPortIngressDestination,
		},
	}

	if k.cfg.Tenant.MultiTenant() {
		ingressRules = append(ingressRules,
			v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      networkPolicyHelper.ManagerSourceEntityRule(),
				Destination: kibanaPortIngressDestination,
			})
	} else {
		// Zero and single tenant with internal elastic will have all Kibana
		// traffic proxied via ES Gateway
		ingressRules = append(ingressRules,
			v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      networkpolicy.DefaultHelper().ESGatewaySourceEntityRule(),
				Destination: kibanaPortIngressDestination,
			},
		)
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyName,
			Namespace: k.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(CRName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}