// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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

package linseed

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tigera/operator/pkg/ptr"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

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
	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	DeploymentName        = "tigera-linseed"
	ServiceAccountName    = "tigera-linseed"
	RoleName              = "tigera-linseed"
	ServiceName           = "tigera-linseed"
	PodSecurityPolicyName = "tigera-linseed"
	PolicyName            = networkpolicy.TigeraComponentPolicyPrefix + "linseed-access"
	PortName              = "tigera-linseed"
	TargetPort            = 8444
	Port                  = 443
	ClusterRoleName       = "tigera-linseed"
)

func Linseed(c *Config) render.Component {
	return &linseed{
		cfg:       c,
		namespace: render.ElasticsearchNamespace,
	}
}

type linseed struct {
	linseedImage string
	csrImage     string
	cfg          *Config

	// Namespace in which to provision namespaced resources.
	namespace string
}

// Config contains all the information needed to render the Linseed component.
type Config struct {
	// CustomResources provided by the user.
	Installation *operatorv1.InstallationSpec

	// Pull secrets provided by the user.
	PullSecrets []*corev1.Secret

	// Keypair to use for asserting Linseed's identity.
	KeyPair certificatemanagement.KeyPairInterface

	// Keypair to use for signing tokens.
	TokenKeyPair certificatemanagement.KeyPairInterface

	// Trusted bundle to use when validating client certificates.
	TrustedBundle certificatemanagement.TrustedBundle

	// ClusterDomain to use when building service URLs.
	ClusterDomain string

	// ESAdminUserName is the admin user used to connect to Elastic
	ESAdminUserName string

	// Whether this is a management cluster
	ManagementCluster bool

	// Whether the cluster supports pod security policies.
	UsePSP bool

	// Elastic cluster configuration
	ESClusterConfig *relasticsearch.ClusterConfig
}

func (l *linseed) ResolveImages(is *operatorv1.ImageSet) error {
	reg := l.cfg.Installation.Registry
	path := l.cfg.Installation.ImagePath
	prefix := l.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	// Calculate the image(s) to use for Linseed, given user registry configuration.
	l.linseedImage, err = components.GetReference(components.ComponentLinseed, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if l.cfg.Installation.CertificateManagement != nil {
		l.csrImage, err = certificatemanagement.ResolveCSRInitImage(l.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}
	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (l *linseed) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, l.linseedAllowTigeraPolicy())
	toCreate = append(toCreate, l.linseedService())
	toCreate = append(toCreate, l.linseedClusterRole())
	toCreate = append(toCreate, l.linseedRoleBinding())
	toCreate = append(toCreate, l.linseedServiceAccount())
	toCreate = append(toCreate, l.linseedDeployment())
	if l.cfg.UsePSP {
		toCreate = append(toCreate, l.linseedPodSecurityPolicy())
	}
	return toCreate, toDelete
}

func (l *linseed) Ready() bool {
	return true
}

func (l *linseed) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

// All linseeds in the cluster must be able to do this.
func (l *linseed) linseedClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Linseed uses subject access review to perform authorization of clients.
			APIGroups:     []string{"authorization.k8s.io"},
			Resources:     []string{"subjectaccessreviews"},
			ResourceNames: []string{},
			Verbs:         []string{"create"},
		},
		{
			// Used to validate tokens from standalone and mangement cluster clients.
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		{
			// Need to be able to list managed clusters
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"managedclusters"},
			Verbs:     []string{"list", "watch"},
		},
	}

	if l.cfg.UsePSP {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{PodSecurityPolicyName},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ClusterRoleName,
		},
		Rules: rules,
	}
}

func (l *linseed) linseedRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ClusterRoleName,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     ClusterRoleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ServiceAccountName,
				Namespace: l.namespace,
			},
		},
	}
}

func (l *linseed) linseedPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy(PodSecurityPolicyName)
}

func (l *linseed) linseedDeployment() *appsv1.Deployment {
	envVars := []corev1.EnvVar{
		{Name: "LINSEED_LOG_LEVEL", Value: "INFO"},
		{Name: "LINSEED_FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(l.cfg.Installation.FIPSMode)},

		// Configure Linseed server certificate.
		{Name: "LINSEED_HTTPS_CERT", Value: l.cfg.KeyPair.VolumeMountCertificateFilePath()},
		{Name: "LINSEED_HTTPS_KEY", Value: l.cfg.KeyPair.VolumeMountKeyFilePath()},

		// Configure the CA certificate used for verifying client certs.
		{Name: "LINSEED_CA_CERT", Value: l.cfg.TrustedBundle.MountPath()},

		// Configure default shards and replicas for indices
		{Name: "ELASTIC_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},

		// Configure shards and replicas for special indices
		{Name: "ELASTIC_FLOWS_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_DNS_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_AUDIT_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_BGP_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_WAF_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_L7_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},
		{Name: "ELASTIC_RUNTIME_INDEX_REPLICAS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Replicas())},

		{Name: "ELASTIC_FLOWS_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.FlowShards())},
		{Name: "ELASTIC_DNS_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_AUDIT_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_BGP_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_WAF_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_L7_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},
		{Name: "ELASTIC_RUNTIME_INDEX_SHARDS", Value: strconv.Itoa(l.cfg.ESClusterConfig.Shards())},

		{Name: "ELASTIC_SCHEME", Value: "https"},
		{Name: "ELASTIC_HOST", Value: "tigera-secure-es-http.tigera-elasticsearch.svc"},
		{Name: "ELASTIC_PORT", Value: "9200"},
		{Name: "ELASTIC_USERNAME", Value: l.cfg.ESAdminUserName},
		{
			Name:      "ELASTIC_PASSWORD",
			ValueFrom: secret.GetEnvVarSource(render.ElasticsearchAdminUserSecret, l.cfg.ESAdminUserName, false),
		},
		{Name: "ELASTIC_CA", Value: l.cfg.TrustedBundle.MountPath()},
	}

	volumes := []corev1.Volume{
		l.cfg.KeyPair.Volume(),
		l.cfg.TrustedBundle.Volume(),
	}

	volumeMounts := append(
		l.cfg.TrustedBundle.VolumeMounts(l.SupportedOSType()),
		l.cfg.KeyPair.VolumeMount(l.SupportedOSType()),
	)

	if l.cfg.ManagementCluster {
		envVars = append(envVars,
			corev1.EnvVar{Name: "TOKEN_CONTROLLER_ENABLED", Value: "true"},
			corev1.EnvVar{Name: "LINSEED_TOKEN_KEY", Value: l.cfg.TokenKeyPair.VolumeMountKeyFilePath()},
		)
		volumes = append(volumes, l.cfg.TokenKeyPair.Volume())
		volumeMounts = append(volumeMounts, l.cfg.TokenKeyPair.VolumeMount(l.SupportedOSType()))
	}

	var initContainers []corev1.Container
	if l.cfg.KeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, l.cfg.KeyPair.InitContainer(l.namespace))
	}

	annotations := l.cfg.TrustedBundle.HashAnnotations()
	annotations[l.cfg.KeyPair.HashAnnotationKey()] = l.cfg.KeyPair.HashAnnotationValue()
	if l.cfg.TokenKeyPair != nil {
		annotations[l.cfg.TokenKeyPair.HashAnnotationKey()] = l.cfg.TokenKeyPair.HashAnnotationValue()
	}
	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        DeploymentName,
			Namespace:   l.namespace,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Tolerations:        l.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:       l.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: ServiceAccountName,
			ImagePullSecrets:   secret.GetReferenceList(l.cfg.PullSecrets),
			Volumes:            volumes,
			InitContainers:     initContainers,
			Containers: []corev1.Container{
				{
					Name:            DeploymentName,
					Image:           l.linseedImage,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					VolumeMounts:    volumeMounts,
					SecurityContext: securitycontext.NewNonRootContext(),
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{"/linseed", "-ready"},
							},
						},
						InitialDelaySeconds: 10,
						PeriodSeconds:       5,
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							Exec: &corev1.ExecAction{
								Command: []string{"/linseed", "-live"},
							},
						},
						InitialDelaySeconds: 10,
						PeriodSeconds:       5,
					},
				},
			},
		},
	}

	if l.cfg.Installation.ControlPlaneReplicas != nil && *l.cfg.Installation.ControlPlaneReplicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(DeploymentName, l.namespace)
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName,
			Namespace: l.namespace,
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
			Replicas: l.cfg.Installation.ControlPlaneReplicas,
		},
	}
}

func (l *linseed) linseedServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceAccountName,
			Namespace: l.namespace,
		},
	}
}

func (l *linseed) linseedService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.LinseedServiceName,
			Namespace: l.namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": DeploymentName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       PortName,
					Port:       Port,
					TargetPort: intstr.FromInt(TargetPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// Allow access to Linseed from components that need it.
func (l *linseed) linseedAllowTigeraPolicy() *v3.NetworkPolicy {
	// Egress needs to be allowed to:
	// - Kubernetes API
	// - Cluster DNS
	// - Elasticsearch
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, l.cfg.Installation.KubernetesProvider == operatorv1.ProviderOpenShift)
	egressRules = append(egressRules, []v3.Rule{
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
	}...)

	if l.cfg.ManagementCluster {
		// For management clusters, linseed talks to Voltron to create tokens.
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.ManagerEntityRule,
		})
	}

	// Ingress needs to be allowed from all clients.
	linseedIngressDestinationEntityRule := v3.EntityRule{
		Ports: networkpolicy.Ports(TargetPort),
	}
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyName,
			Namespace: l.namespace,
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
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.EKSLogForwarderEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.IntrusionDetectionInstallerSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ESCuratorSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ManagerSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ComplianceBenchmarkerSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ComplianceControllerSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ComplianceServerSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ComplianceSnapshotterSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ComplianceReporterSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.IntrusionDetectionSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      render.ECKOperatorSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      esmetrics.ESMetricsSourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      dpi.DPISourceEntityRule,
					Destination: linseedIngressDestinationEntityRule,
				},
			},
			Egress: egressRules,
		},
	}
}
