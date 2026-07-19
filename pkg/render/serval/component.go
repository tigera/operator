// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Package serval renders the Serval gateway: the single layer-7 entrypoint
// through which non-cluster hosts reach the cluster. It serves the
// kube-apiserver proxy, log ingestion, and the felix-to-typha WebSocket
// tunnel on one HTTPS endpoint.
package serval

import (
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/logcollector"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	ServalName               = "serval"
	ServalNamespace          = common.CalicoNamespace
	ServalServiceAccountName = ServalName
	ServalDeploymentName     = ServalName
	ServalServiceName        = ServalName
	ServalPolicyName         = networkpolicy.CalicoComponentPolicyPrefix + "serval"
	ServalKeyPairSecret      = "serval-key-pair"

	ServalServicePort = 443
	ServalTargetPort  = 8449
	ServalHealthPort  = 8080
)

func Serval(cfg *Configuration) render.Component {
	return &Component{cfg: cfg}
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets       []*corev1.Secret
	OpenShift         bool
	Installation      *operatorv1.InstallationSpec
	TrustedCertBundle certificatemanagement.TrustedBundleRO
	ServerKeyPair     certificatemanagement.KeyPairInterface
	Serval            *operatorv1.Serval
	ClusterDomain     string
}

type Component struct {
	cfg *Configuration

	calicoImage string
}

func (c *Component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error
	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	return err
}

func (c *Component) SupportedOSType() meta.OSType {
	return meta.OSTypeLinux
}

func (c *Component) Ready() bool {
	return true
}

func (c *Component) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.service(),
		c.deployment(),
		c.networkPolicy(),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ServalNamespace, c.cfg.PullSecrets...)...)...)
	return objs, nil
}

func (c *Component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ServalServiceAccountName, Namespace: ServalNamespace},
	}
}

func (c *Component) clusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ServalName},
		Rules: []rbacv1.PolicyRule{
			{
				// The apiserver proxy forwards requests as the authenticated
				// host user via impersonation headers.
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				// Kubernetes service account bearer tokens are authenticated
				// with TokenReviews.
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				// Log ingestion requests are authorized against the host's
				// RBAC with SubjectAccessReviews.
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				// The Tigera-JWT authenticator verifies that a token's
				// subject service account exists.
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get"},
			},
		},
	}
}

func (c *Component) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ServalName},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ServalName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ServalServiceAccountName,
				Namespace: ServalNamespace,
			},
		},
	}
}

// service is the in-cluster target for the customer's external load balancer
// or ingress; the operator does not provision the external exposure itself.
func (c *Component) service() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServalServiceName,
			Namespace: ServalNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": ServalDeploymentName},
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       ServalServicePort,
					TargetPort: intstr.FromInt32(ServalTargetPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *Component) typhaEndpoint() string {
	return fmt.Sprintf("%s%s.%s.svc.%s:%d",
		render.TyphaServiceName, render.TyphaNonClusterHostSuffix, common.CalicoNamespace, c.cfg.ClusterDomain, render.TyphaPort)
}

func (c *Component) ingestionEndpoint() string {
	return fmt.Sprintf("https://%s.%s.svc.%s:%d",
		render.FluentBitInputService, common.CalicoNamespace, c.cfg.ClusterDomain, logcollector.FluentBitInputPort)
}

func (c *Component) container() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "SERVAL_LOG_LEVEL", Value: "Info"},
		{Name: "SERVAL_PORT", Value: fmt.Sprintf("%d", ServalTargetPort)},
		{Name: "SERVAL_SERVER_CERT_PATH", Value: c.cfg.ServerKeyPair.VolumeMountCertificateFilePath()},
		{Name: "SERVAL_SERVER_KEY_PATH", Value: c.cfg.ServerKeyPair.VolumeMountKeyFilePath()},
		{Name: "SERVAL_TYPHA_ENDPOINT", Value: c.typhaEndpoint()},
		{Name: "SERVAL_INGESTION_ENDPOINT", Value: c.ingestionEndpoint()},
		{Name: "SERVAL_INGESTION_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		// The log collector input requires an mTLS client certificate signed
		// by the cluster CA; the server keypair doubles as it.
		{Name: "SERVAL_INGESTION_CLIENT_CERT_PATH", Value: c.cfg.ServerKeyPair.VolumeMountCertificateFilePath()},
		{Name: "SERVAL_INGESTION_CLIENT_KEY_PATH", Value: c.cfg.ServerKeyPair.VolumeMountKeyFilePath()},
		{Name: "SERVAL_TIGERA_ISSUER_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "SERVAL_HEALTH_PORT", Value: fmt.Sprintf("%d", ServalHealthPort)},
	}

	volumeMounts := []corev1.VolumeMount{c.cfg.ServerKeyPair.VolumeMount(c.SupportedOSType())}
	volumeMounts = append(volumeMounts, c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())...)

	return corev1.Container{
		Name:            ServalName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "serval"},
		Env:             env,
		SecurityContext: securitycontext.NewNonRootContext(),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
				Path: "/readiness",
				Port: intstr.FromInt32(ServalHealthPort),
			}},
			PeriodSeconds: 10,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
				Path: "/liveness",
				Port: intstr.FromInt32(ServalHealthPort),
			}},
			PeriodSeconds: 10,
		},
		VolumeMounts: volumeMounts,
	}
}

func (c *Component) deployment() *appsv1.Deployment {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, meta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, meta.TolerateGKEARM64NoSchedule)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServalDeploymentName,
			Namespace: ServalNamespace,
			Annotations: map[string]string{
				c.cfg.ServerKeyPair.HashAnnotationKey(): c.cfg.ServerKeyPair.HashAnnotationValue(),
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Installation.ControlPlaneReplicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: ServalDeploymentName,
					Labels: map[string]string{
						"k8s-app": ServalDeploymentName,
					},
				},
				Spec: corev1.PodSpec{
					// The "serval" Service would otherwise inject service-link
					// variables such as SERVAL_PORT=tcp://..., which collide
					// with the SERVAL_ envconfig prefix.
					EnableServiceLinks: ptr.To(false),
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: ServalServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         []corev1.Container{c.container()},
					Volumes: []corev1.Volume{
						c.cfg.ServerKeyPair.Volume(),
						c.cfg.TrustedCertBundle.Volume(),
					},
				},
			},
		},
	}

	if c.cfg.Installation.ControlPlaneReplicas != nil && *c.cfg.Installation.ControlPlaneReplicas > 1 {
		d.Spec.Template.Spec.Affinity = podaffinity.NewPodAntiAffinity(ServalDeploymentName, []string{ServalNamespace})
	}

	return d
}

func (c *Component) networkPolicy() *v3.NetworkPolicy {
	// Hosts connect from outside the cluster, so ingress is unrestricted by
	// source; every request is authenticated at the application layer.
	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(ServalTargetPort),
			},
		},
	}

	egressRules := networkpolicy.AppendDNSEgressRules([]v3.Rule{}, c.cfg.OpenShift)
	egressRules = append(egressRules,
		v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: networkpolicy.KubernetesAppSelector(render.TyphaServiceName + render.TyphaNonClusterHostSuffix),
				Ports:    networkpolicy.Ports(uint16(render.TyphaPort)),
			},
		},
		v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: networkpolicy.KubernetesAppSelector(logcollector.FluentBitNodeName),
				Ports:    networkpolicy.Ports(logcollector.FluentBitInputPort),
			},
		},
	)

	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: ServalPolicyName, Namespace: ServalNamespace},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(ServalDeploymentName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}
