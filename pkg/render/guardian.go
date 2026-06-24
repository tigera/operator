// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

// This renderer is responsible for all resources related to a Guardian Deployment in a
// multicluster setup.
package render

import (
	"fmt"

	"golang.org/x/net/http/httpproxy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	GuardianName                   = "guardian"
	GuardianNamespace              = common.CalicoNamespace
	GuardianServiceAccountName     = GuardianName
	GuardianClusterRoleName        = "calico-guardian"
	GuardianClusterRoleBindingName = "calico-guardian"
	GuardianDeploymentName         = GuardianName

	// GuardianContainerName name is the name of the container running guardian. It's named `tigera-guardian`, instead
	// of `guardian` so that the API for the container overrides don't have to change (`tigera-guardian` is a legacy name).
	GuardianContainerName = "tigera-guardian"
	GuardianServiceName   = "guardian"
	GuardianVolumeName    = "guardian-certs"
	GuardianSecretName    = "tigera-managed-cluster-connection"
	GuardianTargetPort    = 8080
	GuardianPolicyName    = networkpolicy.CalicoComponentPolicyPrefix + "guardian-access"
	GuardianKeyPairSecret = "guardian-key-pair"

	GoldmaneDeploymentName         = "goldmane"
	GuardianSecretsRole            = "calico-guardian-secrets"
	GuardianSecretsRoleBindingName = "calico-guardian-secrets"
)

var (
	GuardianEntityRule                = networkpolicy.CreateEntityRule(GuardianNamespace, GuardianDeploymentName, GuardianTargetPort)
	GuardianSourceEntityRule          = networkpolicy.CreateSourceEntityRule(GuardianNamespace, GuardianDeploymentName)
	GuardianServiceSelectorEntityRule = networkpolicy.CreateServiceSelectorEntityRule(GuardianNamespace, GuardianName)
)

func Guardian(cfg *GuardianConfiguration) Component {
	return &GuardianComponent{
		cfg: cfg,
	}
}

// GuardianPolicy renders the guardian network policy. The core operator renders
// the OSS policy; the enterprise modifier (keyed ComponentNameGuardianPolicy)
// replaces it with the management-cluster policy. The error return is retained
// for callers but is always nil now that the fallible enterprise computation
// lives in the modifier.
func GuardianPolicy(cfg *GuardianConfiguration) (Component, error) {
	return &guardianPolicyComponent{cfg: cfg}, nil
}

const ComponentNameGuardianPolicy = "guardian-policy"

type guardianPolicyComponent struct {
	cfg *GuardianConfiguration
}

func (c *guardianPolicyComponent) ResolveImages(*operatorv1.ImageSet) error { return nil }
func (c *guardianPolicyComponent) SupportedOSType() rmeta.OSType            { return rmeta.OSTypeAny }
func (c *guardianPolicyComponent) Ready() bool                              { return true }
func (c *guardianPolicyComponent) ModifierKey() string                      { return ComponentNameGuardianPolicy }

// GuardianPolicyExtensionContext is the per-component context the guardian
// policy modifier reads (via RenderContext.Component). The enterprise guardian
// network policy is built entirely from these inputs.
type GuardianPolicyExtensionContext struct {
	URL                        string
	PodProxies                 []*httpproxy.Config
	OpenShift                  bool
	IncludeEgressNetworkPolicy bool
}

func (c *guardianPolicyComponent) ExtensionContext() any {
	return GuardianPolicyExtensionContext{
		URL:                        c.cfg.URL,
		PodProxies:                 c.cfg.PodProxies,
		OpenShift:                  c.cfg.OpenShift,
		IncludeEgressNetworkPolicy: c.cfg.IncludeEgressNetworkPolicy,
	}
}

func (c *guardianPolicyComponent) Objects() ([]client.Object, []client.Object) {
	return []client.Object{ossNetworkPolicy(c.cfg)}, []client.Object{
		// allow-tigera Tier was renamed to calico-system
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("guardian-access", GuardianNamespace),
		networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", GuardianNamespace),
	}
}

// GuardianConfiguration contains all the config information needed to render the component.
type GuardianConfiguration struct {
	URL                         string
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	Installation                *operatorv1.InstallationSpec
	TunnelSecret                *corev1.Secret
	TrustedCertBundle           certificatemanagement.TrustedBundleRO
	TunnelCAType                operatorv1.CAType
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	IncludeEgressNetworkPolicy  bool

	// PodProxies represents the resolved proxy configuration for each Guardian pod.
	// If this slice is empty, then resolution has not yet occurred. Pods with no proxy
	// configured are represented with a nil value.
	PodProxies []*httpproxy.Config

	GuardianClientKeyPair certificatemanagement.KeyPairInterface

	// Version stores the version of the cluster, as reported by the ClusterInformation object. It is used to restart
	// guardian when the version changes, which triggers the management cluster to re-check for version skew.
	Version string
}

type GuardianComponent struct {
	cfg         *GuardianConfiguration
	calicoImage string
}

func (c *GuardianComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	return err
}

func (c *GuardianComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *GuardianComponent) ModifierKey() string { return GuardianName }

// GuardianExtensionContext is the per-component context the guardian modifier
// reads (via RenderContext.Component). It carries the inputs the enterprise
// guardian behavior needs that a modifier can't derive from the installation:
// the management cluster's impersonation config, whether we're on OpenShift,
// and the trusted bundle mount path the CA env vars reference.
type GuardianExtensionContext struct {
	OpenShift              bool
	Impersonation          *operatorv1.Impersonation
	TrustedBundleMountPath string
}

func (c *GuardianComponent) ExtensionContext() any {
	var impersonation *operatorv1.Impersonation
	if c.cfg.ManagementClusterConnection != nil {
		impersonation = c.cfg.ManagementClusterConnection.Spec.Impersonation
	}
	return GuardianExtensionContext{
		OpenShift:              c.cfg.OpenShift,
		Impersonation:          impersonation,
		TrustedBundleMountPath: c.cfg.TrustedCertBundle.MountPath(),
	}
}

func (c *GuardianComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.deployment(),
		c.service(),
		secret.CopyToNamespace(GuardianNamespace, c.cfg.TunnelSecret)[0],
	}

	return objs, deprecatedObjects()
}

func (c *GuardianComponent) Ready() bool {
	return true
}

func (c *GuardianComponent) service() *corev1.Service {
	ports := []corev1.ServicePort{
		{
			Name: "https",
			Port: 443,
			TargetPort: intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: 8080,
			},
			Protocol: corev1.ProtocolTCP,
		},
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianServiceName,
			Namespace: GuardianNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": GuardianName,
			},
			Ports: ports,
		},
	}
}

func (c *GuardianComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianServiceAccountName, Namespace: GuardianNamespace},
	}
}

func (c *GuardianComponent) clusterRole() *rbacv1.ClusterRole {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces", "services", "pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"clusterinformations",
				"tiers",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"tier.stagedkubernetesnetworkpolicies",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"globalnetworksets",
				"networksets",
			},
			Verbs: []string{"get", "list", "watch"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleName,
		},
		Rules: policyRules,
	}
}

func (c *GuardianComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     GuardianClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GuardianServiceAccountName,
				Namespace: GuardianNamespace,
			},
		},
	}
}

func (c *GuardianComponent) deployment() *appsv1.Deployment {
	var replicas int32 = 1

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianDeploymentName,
			Namespace: GuardianNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        GuardianDeploymentName,
					Namespace:   GuardianNamespace,
					Annotations: c.annotations(),
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: GuardianServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         c.container(),
					Volumes:            c.volumes(),
				},
			},
		},
	}

	if c.cfg.ManagementClusterConnection != nil {
		if overrides := c.cfg.ManagementClusterConnection.Spec.GuardianDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *GuardianComponent) volumes() []corev1.Volume {
	volumes := []corev1.Volume{
		c.cfg.TrustedCertBundle.Volume(),
		{
			Name: GuardianVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: GuardianSecretName,
				},
			},
		},
	}
	if c.cfg.GuardianClientKeyPair != nil {
		volumes = append(volumes, c.cfg.GuardianClientKeyPair.Volume())
	}
	return volumes
}

func (c *GuardianComponent) container() []corev1.Container {
	envVars := []corev1.EnvVar{
		{Name: "GUARDIAN_PORT", Value: "9443"},
		{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
		{Name: "GUARDIAN_VOLTRON_URL", Value: c.cfg.URL},
		{Name: "GUARDIAN_VOLTRON_CA_TYPE", Value: string(c.cfg.TunnelCAType)},
		{Name: "GUARDIAN_CA_FILE", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
	}
	envVars = append(envVars, c.cfg.Installation.Proxy.EnvVars()...)

	if c.cfg.GuardianClientKeyPair != nil {
		envVars = append(envVars,
			corev1.EnvVar{
				Name:  "GUARDIAN_GOLDMANE_ENDPOINT",
				Value: "https://goldmane.calico-system.svc.cluster.local:7443",
			},
			corev1.EnvVar{
				Name:  "GUARDIAN_GOLDMANE_CLIENT_CERT",
				Value: c.cfg.GuardianClientKeyPair.VolumeMountCertificateFilePath(),
			},
			corev1.EnvVar{
				Name:  "GUARDIAN_GOLDMANE_CLIENT_KEY",
				Value: c.cfg.GuardianClientKeyPair.VolumeMountKeyFilePath(),
			},
		)
	}

	return []corev1.Container{
		{
			Name:         GuardianContainerName,
			Image:        c.calicoImage,
			Command:      []string{components.CalicoBinaryPath, "component", "guardian"},
			Env:          envVars,
			VolumeMounts: c.volumeMounts(),
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/liveness",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 90,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/readiness",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 10,
			},
			SecurityContext: securitycontext.NewNonRootContext(),
		},
	}
}

func (c *GuardianComponent) volumeMounts() []corev1.VolumeMount {
	volumeMounts := append(
		c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
		corev1.VolumeMount{Name: GuardianVolumeName, MountPath: "/certs/", ReadOnly: true},
	)
	if c.cfg.GuardianClientKeyPair != nil {
		volumeMounts = append(volumeMounts, c.cfg.GuardianClientKeyPair.VolumeMount(c.SupportedOSType()))
	}
	return volumeMounts
}

func (c *GuardianComponent) annotations() map[string]string {
	annotations := c.cfg.TrustedCertBundle.HashAnnotations()
	annotations["hash.operator.tigera.io/tigera-managed-cluster-connection"] = rmeta.AnnotationHash(c.cfg.TunnelSecret.Data)

	if len(c.cfg.Version) != 0 {
		annotations["hash.operator.tigera.io/version"] = c.cfg.Version
	}
	return annotations
}

func ossNetworkPolicy(cfg *GuardianConfiguration) *v3.NetworkPolicy {
	egressRules := networkpolicy.AppendDNSEgressRules([]v3.Rule{}, cfg.OpenShift)

	// Allow egress to the Kubernetes API server.
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.KubeAPIServerEntityRule,
	})

	// Guardian's tunnel destination is the management cluster, whose address is
	// environment-specific and often a hostname. OSS policy can't express a
	// domain-based egress rule, so Pass and let the cluster's default posture
	// govern the tunnel (and the management cluster's queries back to Goldmane).
	egressRules = append(egressRules, v3.Rule{Action: v3.Pass})

	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianPolicyName, Namespace: GuardianNamespace},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(GuardianName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source: v3.EntityRule{
						Selector: networkpolicy.KubernetesAppSelector(GoldmaneDeploymentName),
					},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(GuardianTargetPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

func ProcessPodProxies(podProxies []*httpproxy.Config) []*httpproxy.Config {
	// If pod proxies are empty, then pod proxy resolution has not yet occurred.
	// Assume that a single Guardian pod is running without a proxy.
	if len(podProxies) == 0 {
		return []*httpproxy.Config{nil}
	}

	return podProxies
}

func GuardianService(clusterDomain string) string {
	return fmt.Sprintf("https://%s.%s.svc.%s:%d", GuardianServiceName, GuardianNamespace, clusterDomain, 443)
}

func deprecatedObjects() []client.Object {
	return []client.Object{
		// All the Guardian objects were moved to "calico-system" circa Calico v3.30, and so the legacy tigera-guardian
		// Namespace and everything within it should be removed.
		&corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"},
		},
		// All the Guardian objects were moved to "calico-system" circa Calico v3.30, and so the legacy `tigera-`
		// prefix is replaced with `calico-` for consistency, which means removing the old global resources.
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-guardian"},
		},

		// Remove manager namespace objects since the guardian identity is responsible for handling manager requests
		&corev1.ServiceAccount{
			TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager", Namespace: "tigera-manager"},
		},
		&corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager"},
		},
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-role"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-manager-binding"},
		},

		// Clean up deprecated k8s NetworkPolicy
		&netv1.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "guardian", Namespace: GuardianNamespace},
		},
	}
}
