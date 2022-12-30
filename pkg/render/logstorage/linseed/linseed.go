// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	"strings"

	"github.com/tigera/operator/pkg/render/common/securitycontext"

	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	DeploymentName             = "tigera-linseed"
	ServiceAccountName         = "tigera-linseed"
	RoleName                   = "tigera-linseed"
	ServiceName                = "tigera-linseed"
	PolicyName                 = networkpolicy.TigeraComponentPolicyPrefix + "linseed-access"
	PortName                   = "tigera-linseed"
	TargetPort                 = 8444
	Port                       = 443
	ElasticsearchHTTPSEndpoint = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
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

	// Trusted bundle to use when validating client certificates.
	TrustedBundle certificatemanagement.TrustedBundle

	// ClusterDomain to use when building service URLs.
	ClusterDomain string
}

func (e *linseed) ResolveImages(is *operatorv1.ImageSet) error {
	reg := e.cfg.Installation.Registry
	path := e.cfg.Installation.ImagePath
	prefix := e.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	// Calculate the image(s) to use for Linseed, given user registry configuration.
	e.linseedImage, err = components.GetReference(components.ComponentLinseed, reg, path, prefix, is)
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

func (e *linseed) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, e.linseedAllowTigeraPolicy())
	toCreate = append(toCreate, e.linseedService())
	toCreate = append(toCreate, e.linseedRole())
	toCreate = append(toCreate, e.linseedRoleBinding())
	toCreate = append(toCreate, e.linseedServiceAccount())
	toCreate = append(toCreate, e.linseedDeployment())
	return toCreate, toDelete
}

func (e *linseed) Ready() bool {
	return true
}

func (e *linseed) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e linseed) linseedRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RoleName,
			Namespace: e.namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Linseed uses subject access review to perform authorization of clients.
				APIGroups:     []string{"authorization.k8s.io"},
				Resources:     []string{"subjectaccessreview"},
				ResourceNames: []string{},
				Verbs:         []string{"create"},
			},
		},
	}
}

func (e linseed) linseedRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RoleName,
			Namespace: e.namespace,
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
				Namespace: e.namespace,
			},
		},
	}
}

func (e linseed) linseedDeployment() *appsv1.Deployment {
	envVars := []corev1.EnvVar{
		{Name: "LINSEED_LOG_LEVEL", Value: "INFO"},

		// Configuration for linseed API.
		{Name: "LINSEED_FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(e.cfg.Installation.FIPSMode)},
		{Name: "LINSEED_HTTPS_CERT", Value: e.cfg.KeyPair.VolumeMountCertificateFilePath()},
		{Name: "LINSEED_HTTPS_KEY", Value: e.cfg.KeyPair.VolumeMountKeyFilePath()},

		// Configuration for connection to Elasticsearch.
		{Name: "LINSEED_ELASTIC_ENDPOINT", Value: ElasticsearchHTTPSEndpoint},
	}

	var initContainers []corev1.Container
	if e.cfg.KeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, e.cfg.KeyPair.InitContainer(e.namespace))
	}

	volumes := []corev1.Volume{
		e.cfg.KeyPair.Volume(),
		e.cfg.TrustedBundle.Volume(),
	}

	volumeMounts := []corev1.VolumeMount{
		e.cfg.KeyPair.VolumeMount(e.SupportedOSType()),
		e.cfg.TrustedBundle.VolumeMount(e.SupportedOSType()),
	}

	annotations := e.cfg.TrustedBundle.HashAnnotations()
	annotations[e.cfg.KeyPair.HashAnnotationKey()] = e.cfg.KeyPair.HashAnnotationValue()
	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        DeploymentName,
			Namespace:   e.namespace,
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
					Name:         DeploymentName,
					Image:        e.linseedImage,
					Env:          envVars,
					VolumeMounts: volumeMounts,
					// UID 1001 is used in the Dockerfile.
					SecurityContext: securitycontext.NewBaseContext(1001, 0),
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/health",
								Port:   intstr.FromInt(TargetPort),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						InitialDelaySeconds: 10,
						PeriodSeconds:       5,
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/health",
								Port:   intstr.FromInt(TargetPort),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						InitialDelaySeconds: 10,
						PeriodSeconds:       5,
					},
				},
			},
		},
	}

	if e.cfg.Installation.ControlPlaneReplicas != nil && *e.cfg.Installation.ControlPlaneReplicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(DeploymentName, e.namespace)
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName,
			Namespace: e.namespace,
			Labels: map[string]string{
				"k8s-app": DeploymentName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
			Replicas: e.cfg.Installation.ControlPlaneReplicas,
		},
	}
}

func (e linseed) linseedServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceAccountName,
			Namespace: e.namespace,
		},
	}
}

func (e linseed) linseedService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName,
			Namespace: e.namespace,
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
func (e *linseed) linseedAllowTigeraPolicy() *v3.NetworkPolicy {
	// Egress needs to be allowed to:
	// - Kubernetes API
	// - Cluster DNS
	// - Elasticsearch
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, e.cfg.Installation.KubernetesProvider == operatorv1.ProviderOpenShift)
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

	// Ingress needs to be allowed from all clients.
	linseedIngressDestinationEntityRule := v3.EntityRule{
		Ports: networkpolicy.Ports(Port),
	}
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyName,
			Namespace: e.namespace,
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
