// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

package esgateway

import (
	"fmt"
	"strings"

	"github.com/tigera/operator/pkg/render/common/elasticsearch"

	"github.com/tigera/operator/pkg/ptr"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	DeploymentName        = "tigera-secure-es-gateway"
	ServiceAccountName    = "tigera-secure-es-gateway"
	RoleName              = "tigera-secure-es-gateway"
	PodSecurityPolicyName = "tigera-esgateway"
	ServiceName           = "tigera-secure-es-gateway-http"
	PolicyName            = networkpolicy.TigeraComponentPolicyPrefix + "es-gateway-access"
	ElasticsearchPortName = "es-gateway-elasticsearch-port"
	KibanaPortName        = "es-gateway-kibana-port"
	Port                  = 5554

	ElasticsearchHTTPSEndpoint = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"

	KibanaHTTPSEndpoint = "https://tigera-secure-kb-http.tigera-kibana.svc:5601"
)

func EsGateway(c *Config) render.Component {
	return &esGateway{
		cfg: c,
	}
}

type esGateway struct {
	csrImage       string
	esGatewayImage string
	cfg            *Config
}

// Config contains all the config information needed to render the EsGateway component.
type Config struct {
	Installation               *operatorv1.InstallationSpec
	PullSecrets                []*corev1.Secret
	KubeControllersUserSecrets []*corev1.Secret
	ESGatewayKeyPair           certificatemanagement.KeyPairInterface
	TrustedBundle              certificatemanagement.TrustedBundleRO
	ClusterDomain              string
	EsAdminUserName            string
	Namespace                  string
	TruthNamespace             string

	// Whether the cluster supports pod security policies.
	UsePSP bool
}

func (e *esGateway) ResolveImages(is *operatorv1.ImageSet) error {
	reg := e.cfg.Installation.Registry
	path := e.cfg.Installation.ImagePath
	prefix := e.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	e.esGatewayImage, err = components.GetReference(components.ComponentESGateway, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	if e.cfg.Installation.CertificateManagement != nil {
		e.csrImage, err = certificatemanagement.ResolveCSRInitImage(e.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}
	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (e *esGateway) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, e.esGatewayAllowTigeraPolicy())
	toCreate = append(toCreate, secret.ToRuntimeObjects(e.cfg.KubeControllersUserSecrets...)...)
	toCreate = append(toCreate, e.esGatewayService())
	toCreate = append(toCreate, e.esGatewayRole())
	toCreate = append(toCreate, e.esGatewayRoleBinding())
	toCreate = append(toCreate, e.esGatewayServiceAccount())
	toCreate = append(toCreate, e.esGatewayDeployment())

	// The following secret is used by kube controllers and sent to managed clusters. It is also used by manifests in our docs.
	if e.cfg.ESGatewayKeyPair.UseCertificateManagement() {
		toCreate = append(toCreate, render.CreateCertificateSecret(e.cfg.Installation.CertificateManagement.CACert, elasticsearch.PublicCertSecret, e.cfg.TruthNamespace))
	} else {
		toCreate = append(toCreate, render.CreateCertificateSecret(e.cfg.ESGatewayKeyPair.GetCertificatePEM(), elasticsearch.PublicCertSecret, e.cfg.TruthNamespace))
	}
	if e.cfg.UsePSP {
		toCreate = append(toCreate, e.esGatewayPodSecurityPolicy())
	}
	return toCreate, toDelete
}

func (e *esGateway) Ready() bool {
	return true
}

func (e *esGateway) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e *esGateway) esGatewayRole() *rbacv1.Role {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{},
			Verbs:         []string{"get", "list", "watch"},
		},
	}

	if e.cfg.UsePSP {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{PodSecurityPolicyName},
		})
	}

	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RoleName,
			Namespace: e.cfg.Namespace,
		},
		Rules: rules,
	}
}

func (e *esGateway) esGatewayRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RoleName,
			Namespace: e.cfg.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     RoleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ServiceAccountName,
				Namespace: e.cfg.Namespace,
			},
		},
	}
}

func (e *esGateway) esGatewayPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy(PodSecurityPolicyName)
}

func (e *esGateway) esGatewayDeployment() *appsv1.Deployment {
	envVars := []corev1.EnvVar{
		{Name: "NAMESPACE", Value: e.cfg.Namespace},
		{Name: "ES_GATEWAY_LOG_LEVEL", Value: "INFO"},
		{Name: "ES_GATEWAY_ELASTIC_ENDPOINT", Value: ElasticsearchHTTPSEndpoint},
		{Name: "ES_GATEWAY_KIBANA_ENDPOINT", Value: KibanaHTTPSEndpoint},
		{Name: "ES_GATEWAY_HTTPS_CERT", Value: e.cfg.ESGatewayKeyPair.VolumeMountCertificateFilePath()},
		{Name: "ES_GATEWAY_HTTPS_KEY", Value: e.cfg.ESGatewayKeyPair.VolumeMountKeyFilePath()},
		{Name: "ES_GATEWAY_KIBANA_CLIENT_CERT_PATH", Value: e.cfg.TrustedBundle.MountPath()},
		{Name: "ES_GATEWAY_ELASTIC_CLIENT_CERT_PATH", Value: e.cfg.TrustedBundle.MountPath()},
		{Name: "ES_GATEWAY_ELASTIC_CA_BUNDLE_PATH", Value: e.cfg.TrustedBundle.MountPath()},
		{Name: "ES_GATEWAY_KIBANA_CA_BUNDLE_PATH", Value: e.cfg.TrustedBundle.MountPath()},
		{Name: "ES_GATEWAY_ELASTIC_USERNAME", Value: e.cfg.EsAdminUserName},
		{Name: "ES_GATEWAY_ELASTIC_PASSWORD", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: render.ElasticsearchAdminUserSecret,
				},
				Key: e.cfg.EsAdminUserName,
			},
		}},
		{Name: "ES_GATEWAY_FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(e.cfg.Installation.FIPSMode)},
	}

	var initContainers []corev1.Container
	if e.cfg.ESGatewayKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, e.cfg.ESGatewayKeyPair.InitContainer(e.cfg.Namespace))
	}

	volumes := []corev1.Volume{
		e.cfg.ESGatewayKeyPair.Volume(),
		e.cfg.TrustedBundle.Volume(),
	}

	volumeMounts := append(
		e.cfg.TrustedBundle.VolumeMounts(e.SupportedOSType()),
		e.cfg.ESGatewayKeyPair.VolumeMount(e.SupportedOSType()),
	)

	annotations := e.cfg.TrustedBundle.HashAnnotations()
	annotations[e.cfg.ESGatewayKeyPair.HashAnnotationKey()] = e.cfg.ESGatewayKeyPair.HashAnnotationValue()
	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        DeploymentName,
			Namespace:   e.cfg.Namespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Tolerations:        e.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:       e.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: ServiceAccountName,
			ImagePullSecrets:   secret.GetReferenceList(e.cfg.PullSecrets),
			Volumes:            volumes,
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:            DeploymentName,
					Image:           e.esGatewayImage,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					VolumeMounts:    volumeMounts,
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/health",
								Port:   intstr.FromInt(Port),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						InitialDelaySeconds: 10,
					},
					SecurityContext: securitycontext.NewNonRootContext(),
				},
			},
		},
	}

	if e.cfg.Installation.ControlPlaneReplicas != nil && *e.cfg.Installation.ControlPlaneReplicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(DeploymentName, e.cfg.Namespace)
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName,
			Namespace: e.cfg.Namespace,
			Labels: map[string]string{
				"k8s-app": DeploymentName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: ptr.IntOrStrPtr("0"),
					MaxSurge:       ptr.IntOrStrPtr("100%"),
				},
			},
			Template: *podTemplate,
			Replicas: e.cfg.Installation.ControlPlaneReplicas,
		},
	}
}

func (e *esGateway) esGatewayServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceAccountName,
			Namespace: e.cfg.Namespace,
		},
	}
}

func (e *esGateway) esGatewayService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName,
			Namespace: e.cfg.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": DeploymentName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       ElasticsearchPortName,
					Port:       int32(render.ElasticsearchDefaultPort),
					TargetPort: intstr.FromInt(Port),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       KibanaPortName,
					Port:       int32(render.KibanaPort),
					TargetPort: intstr.FromInt(Port),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// Allow access to ES Gateway from components that need to talk to Elasticsearch or Kibana.
func (e *esGateway) esGatewayAllowTigeraPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, e.cfg.Installation.KubernetesProvider == operatorv1.ProviderOpenShift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.DexEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.ElasticsearchEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.KibanaEntityRule,
		},
	}...)

	esgatewayIngressDestinationEntityRule := v3.EntityRule{
		Ports: networkpolicy.Ports(Port),
	}
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyName,
			Namespace: e.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(DeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.FluentdSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.EKSLogForwarderEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.IntrusionDetectionInstallerSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().ManagerSourceEntityRule(),
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.IntrusionDetectionSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ECKOperatorSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      esmetrics.ESMetricsSourceEntityRule,
					Destination: esgatewayIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Destination: esgatewayIngressDestinationEntityRule,
					// The operator needs access to Elasticsearch and Kibana (through ES Gateway), however, since the
					// operator is on the hostnetwork it's hard to create specific network policies for it.
					// Allow all sources, as node CIDRs are not known. This also applies to DPI, which is host networked
				},
			},
			Egress: egressRules,
		},
	}
}
