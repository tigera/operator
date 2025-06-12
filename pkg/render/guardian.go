// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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
	"net"
	"net/url"

	operatorurl "github.com/tigera/operator/pkg/url"
	"golang.org/x/net/http/httpproxy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/api/pkg/lib/numorstring"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/render/common/selector"
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
	GuardianPolicyName    = networkpolicy.TigeraComponentPolicyPrefix + "guardian-access"
	GuardianKeyPairSecret = "guardian-key-pair"

	GoldmaneDeploymentName = "goldmane"
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

func GuardianPolicy(cfg *GuardianConfiguration) (Component, error) {
	guardianAccessPolicy, err := guardianAllowTigeraPolicy(cfg)
	if err != nil {
		return nil, err
	}

	return NewPassthrough(
		guardianAccessPolicy,
		networkpolicy.AllowTigeraDefaultDeny(GuardianNamespace),
	), nil
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

	// PodProxies represents the resolved proxy configuration for each Guardian pod.
	// If this slice is empty, then resolution has not yet occurred. Pods with no proxy
	// configured are represented with a nil value.
	PodProxies []*httpproxy.Config

	GuardianClientKeyPair certificatemanagement.KeyPairInterface
}

type GuardianComponent struct {
	cfg   *GuardianConfiguration
	image string
}

func (c *GuardianComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.image, err = components.GetReference(components.ComponentGuardian, reg, path, prefix, is)
	} else {
		c.image, err = components.GetReference(components.ComponentCalicoGuardian, reg, path, prefix, is)
	}
	return err
}

func (c *GuardianComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
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

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		objs = append(objs,
			// Install default UI settings for this managed cluster.
			managerClusterWideSettingsGroup(),
			managerUserSpecificSettingsGroup(),
			managerClusterWideTigeraLayer(),
			managerClusterWideDefaultView(),
		)
	} else {
		objs = append(objs, c.networkPolicy())
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

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		ports = append(ports,
			corev1.ServicePort{
				Name: "elasticsearch",
				Port: 9200,
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: 8080,
				},
				Protocol: corev1.ProtocolTCP,
			},
			corev1.ServicePort{
				Name: "kibana",
				Port: 5601,
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: 8080,
				},
				Protocol: corev1.ProtocolTCP,
			},
		)
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
	var policyRules []rbacv1.PolicyRule

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		policyRules = append(policyRules, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"users", "groups", "serviceaccounts"},
			Verbs:     []string{"impersonate"},
		})

		// to remove isManagedCluster and tenant param from this func.
		// since isManagedcluster would be always true and tenant is always nil in managed cluster where guardian resides
		policyRules = append(policyRules, AddClusterRoleRulesForManagementBackendRequest(true, c.cfg.OpenShift, nil)...)

		if c.cfg.OpenShift {
			policyRules = append(policyRules, rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.NonRootV2},
			})
		}
	} else {
		policyRules = append(policyRules,
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"namespaces", "services", "pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
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
		)
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
					Namespace:   ManagerNamespace,
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

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		envVars = append(envVars,
			corev1.EnvVar{Name: "GUARDIAN_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
			corev1.EnvVar{Name: "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
			corev1.EnvVar{Name: "GUARDIAN_QUERYSERVER_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		)
	}

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
			Name:            GuardianContainerName,
			Image:           c.image,
			ImagePullPolicy: ImagePullPolicy(),
			Env:             envVars,
			VolumeMounts:    c.volumeMounts(),
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 90,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
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
	return annotations
}

func (c *GuardianComponent) networkPolicy() *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianName, Namespace: GuardianNamespace},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: *selector.PodLabelSelector(GuardianDeploymentName),
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					From: []netv1.NetworkPolicyPeer{
						{
							PodSelector: selector.PodLabelSelector(GoldmaneDeploymentName),
						},
					},
					Ports: []netv1.NetworkPolicyPort{{
						Protocol: ptr.ToPtr(corev1.ProtocolTCP),
						Port:     ptr.ToPtr(intstr.FromInt32(GuardianTargetPort)),
					}},
				},
				{
					Ports: []netv1.NetworkPolicyPort{{
						Protocol: ptr.ToPtr(corev1.ProtocolUDP),
						Port:     ptr.ToPtr(intstr.FromInt32(53)),
					}},
				},
			},
		},
	}
}

func guardianAllowTigeraPolicy(cfg *GuardianConfiguration) (*v3.NetworkPolicy, error) {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: PacketCaptureEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.PrometheusEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: TigeraAPIServerEntityRule,
		},
	}...)

	// The loop below creates an egress rule for each unique destination that the Guardian pods connect to. If there are
	// multiple guardian pods and their proxy  settings differ, then there are multiple destinations that must have egress allowed.
	allowedDestinations := map[string]bool{}
	processedPodProxies := ProcessPodProxies(cfg.PodProxies)
	for _, podProxyConfig := range processedPodProxies {
		var proxyURL *url.URL
		var err error
		if podProxyConfig != nil && podProxyConfig.HTTPSProxy != "" {
			targetURL := &url.URL{
				// The scheme should be HTTPS, as we are establishing an mTLS session with the target.
				Scheme: "https",

				// We expect `target` to be of the form host:port.
				Host: cfg.URL,
			}

			proxyURL, err = podProxyConfig.ProxyFunc()(targetURL)
			if err != nil {
				return nil, err
			}
		}

		var tunnelDestinationHostPort string
		if proxyURL != nil {
			proxyHostPort, err := operatorurl.ParseHostPortFromHTTPProxyURL(proxyURL)
			if err != nil {
				return nil, err
			}

			tunnelDestinationHostPort = proxyHostPort
		} else {
			// cfg.URL has host:port form
			tunnelDestinationHostPort = cfg.URL
		}

		// Check if we've already created an egress rule for this destination.
		if allowedDestinations[tunnelDestinationHostPort] {
			continue
		}

		host, port, err := net.SplitHostPort(tunnelDestinationHostPort)
		if err != nil {
			return nil, err
		}
		parsedPort, err := numorstring.PortFromString(port)
		if err != nil {
			return nil, err
		}
		parsedIp := net.ParseIP(host)
		if parsedIp == nil {
			// Assume host is a valid hostname.
			egressRules = append(egressRules, v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Domains: []string{host},
					Ports:   []numorstring.Port{parsedPort},
				},
			})
			allowedDestinations[tunnelDestinationHostPort] = true

		} else {
			var netSuffix string
			if parsedIp.To4() != nil {
				netSuffix = "/32"
			} else {
				netSuffix = "/128"
			}

			egressRules = append(egressRules, v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Nets:  []string{parsedIp.String() + netSuffix},
					Ports: []numorstring.Port{parsedPort},
				},
			})
			allowedDestinations[tunnelDestinationHostPort] = true
		}
	}

	egressRules = append(egressRules, v3.Rule{Action: v3.Pass})

	guardianIngressDestinationEntityRule := v3.EntityRule{Ports: networkpolicy.Ports(8080)}
	networkpolicyHelper := networkpolicy.DefaultHelper()
	var ingressRules []v3.Rule
	if cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		ingressRules = append(ingressRules, []v3.Rule{
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      FluentdSourceEntityRule,
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      networkpolicyHelper.ComplianceBenchmarkerSourceEntityRule(),
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      networkpolicyHelper.ComplianceReporterSourceEntityRule(),
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      networkpolicyHelper.ComplianceSnapshotterSourceEntityRule(),
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      networkpolicyHelper.ComplianceControllerSourceEntityRule(),
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      IntrusionDetectionSourceEntityRule,
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Source:      IntrusionDetectionInstallerSourceEntityRule,
				Destination: guardianIngressDestinationEntityRule,
			},
			{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Destination: guardianIngressDestinationEntityRule,
			},
		}...)
	}

	policy := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianPolicyName,
			Namespace: GuardianNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(GuardianName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}

	return policy, nil
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

// rulesForManagementClusterRequests returns the set of RBAC rules needed by Guardian in order to 
// satisfy requests from the management cluster over the tunnel.
func rulesForManagementClusterRequests(isManagedCluster, isOpenShift bool, tenant *operatorv1.Tenant) []rbacv1.PolicyRule {

	// Sort ap
	// General rules need for more than one of the following managemen cluster backend components
	// such as linseed, manager, policy, calico-kube-controller, intrusion detection

	rules := []rbacv1.PolicyRule{}

	// Rules needed  by guardian to handle linseed requests

	// This permission allows Linseed to watch for namespace creation and existence in the managed cluster
	// before attempting to copy the Linseed token into those namespaces.
	rules = append(rules, rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"namespaces"},
		Verbs:     []string{"get", "list", "watch"},
	})

	// Rules needed by guardian to handle manager request
	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts", "namespaces", "nodes", "events", "services", "pods"},
			Verbs:     []string{"list"},
		},

		// When a request is made in the manager UI, they are proxied through the Voltron backend server. If the
		// request is targeting a k8s api or when it is targeting a managed cluster, Voltron will authenticate the
		// user based on the auth header and then impersonate the user.
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"users", "groups", "serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},

		rbacv1.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"replicasets", "statefulsets", "daemonsets"},
			Verbs:     []string{"list"},
		},

		// Allow query server talk to Prometheus via the manager user.
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:tigera-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs:     []string{"get", "list"},
		},
		rbacv1.PolicyRule{
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
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
			},
			Verbs: []string{"patch"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
			},
			Verbs: []string{"get", "list"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"hostendpoints",
			},
			Verbs: []string{"list"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"felixconfigurations",
			},
			ResourceNames: []string{
				"default",
			},
			Verbs: []string{"get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
			},
			Verbs: []string{"get", "list", "update"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"list"},
		},
	)
	/* This logic could be removed for Guardian
	if !isManagedCluster {
		rules = append(rules,
			rbacv1.PolicyRule{
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
			rbacv1.PolicyRule{
				// Dismiss events.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{
					"events",
				},
				Verbs: []string{"dismiss", "delete"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch", "update"},
			},
		)
	}
	*/

	if isOpenShift {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{securitycontextconstraints.NonRootV2},
			},
		)
	}

	/* In a managed cluster, tenant is nil, so this logic can be safely removed.
	if tenant.MultiTenant() {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"localsubjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		)

		if tenant.ManagedClusterIsCalico() {
			// Voltron needs permissions to write flow logs.
			rules = append(rules,
				rbacv1.PolicyRule{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"flowlogs"},
					Verbs:     []string{"create"},
				})
		}
	}
	*/

	// End of manager rules

	// Rules needed  by guardian to handle policy recommendation request
	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworksets",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		rbacv1.PolicyRule{
			// Add read access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{
				"flows",
			},
			Verbs: []string{"get"},
		},
	)

	/* this could be removed
	if !isManagedCluster {
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys", "managedclusters"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "list", "watch"},
			},
		}...)
	}
	*/

	if isOpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.HostNetworkV2},
		})
	}

	/* this could be removed
	if tenant.MultiTenant() {
		// These rules are used by policy-recommendation in a management cluster serving multiple tenants in order to appear to managed
		// clusters as the expected serviceaccount. They're only needed when there are multiple tenants sharing the same
		// management cluster.
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{PolicyRecommendationName},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
				ResourceNames: []string{
					serviceaccount.AllServiceAccountsGroup,
					"system:authenticated",
					fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, PolicyRecommendationNamespace),
				},
			},
		}...)
	}
	*/

	// Rules needed  by guardian to handle calico-kube-controller request

	// Is it possible to differentiate between the RBAC rules required for calico-kube-controllers
	// and those needed by Guardian to handle management cluster requests?

	// kc common rules
	rules = append(rules,
		rbacv1.PolicyRule{
			// Nodes are watched to monitor for deletions.
			APIGroups: []string{""},
			Resources: []string{"nodes", "endpoints", "services"},
			Verbs:     []string{"watch", "list", "get"},
		},
		rbacv1.PolicyRule{
			// Pods are watched to check for existence as part of IPAM GC.
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"services", "services/status"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		rbacv1.PolicyRule{
			// IPAM resources are manipulated in response to node and block updates, as well as periodic triggers.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"ipreservations"},
			Verbs:     []string{"list"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"blockaffinities", "ipamblocks", "ipamhandles", "networksets", "ipamconfigs"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		rbacv1.PolicyRule{
			// Pools are watched to maintain a mapping of blocks to IP pools.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"ippools"},
			Verbs:     []string{"list", "watch"},
		},
		rbacv1.PolicyRule{
			// Needs access to update clusterinformations.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "create", "update", "list", "watch"},
		},
		rbacv1.PolicyRule{
			// Needs to manage hostendpoints.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		rbacv1.PolicyRule{
			// Needs to manipulate kubecontrollersconfiguration, which contains
			// its config.  It creates a default if none exists, and updates status
			// as well.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"kubecontrollersconfigurations"},
			Verbs:     []string{"get", "create", "list", "update", "watch"},
		},
		rbacv1.PolicyRule{
			// calico-kube-controllers requires tiers create
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create"},
		},
	)

	if isOpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	// is enterprise cluster for kc- KubeControllersRoleEnterpriseCommonRules
	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"watch", "list", "get", "update", "create", "delete"},
		},
		rbacv1.PolicyRule{
			// The Federated Services Controller needs access to the remote kubeconfig secret
			// in order to create a remote syncer.
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"watch", "list", "get"},
		},
		rbacv1.PolicyRule{
			// Needed to validate the license
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch", "list"},
		},
		rbacv1.PolicyRule{
			// Needed to validate the license
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "watch", "list"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections/status"},
			Verbs:     []string{"update"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "update"},
		},
	)

	if isManagedCluster {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "create", "update", "list", "watch"},
			},
			// Grant permissions to access ClusterInformation resources in managed clusters.
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"clusterinformations"},
				Verbs:     []string{"get", "list", "watch"},
			},
		)
	}

	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"remoteclusterconfigurations"},
			Verbs:     []string{"watch", "list", "get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"endpoints"},
			Verbs:     []string{"create", "update", "delete"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"usage.tigera.io"},
			Resources: []string{"licenseusagereports"},
			Verbs:     []string{"create", "update", "delete", "watch", "list", "get"},
		},
	)

	// End of calico-kube-controller

	// Rules needed  by guardian to handle Intrusion detection request

	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups: []string{
				"projectcalico.org",
			},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"globalnetworksets",
			},
			Verbs: []string{
				"get", "list", "watch", "create", "update", "patch", "delete",
			},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{
				"crd.projectcalico.org",
			},
			Resources: []string{
				"licensekeys",
			},
			Verbs: []string{
				"get", "watch",
			},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"podtemplates"},
			Verbs:     []string{"get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get"},
		},
		rbacv1.PolicyRule{
			// Add write access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"events"},
			Verbs:     []string{"create"},
		},
		rbacv1.PolicyRule{
			// Add write/read/delete access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"threatfeeds_ipset", "threatfeeds_domainnameset"},
			Verbs:     []string{"create", "delete", "get"},
		},
		rbacv1.PolicyRule{
			// Add read access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{
				"waflogs",
				"dnslogs",
				"l7logs",
				"flowlogs",
				"auditlogs",
				"events",
			},
			Verbs: []string{"get"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"secrets", "configmaps"},
			Verbs:     []string{"get", "list", "watch"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list", "watch", "update"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"alertexceptions"},
			Verbs:     []string{"get", "list"},
		},
	)

	/* should be good to remove
	if !isManagedCluster {
		managementRule := []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs", "jobs"},
				Verbs: []string{
					"get", "list", "watch", "create", "update", "patch", "delete",
				},
			},
		}

		// We don't have AD CronJobs any more, but leaving this here in case it now applies
		// to more cases, as there's nothing actual specific to AD CronJobs in the following
		// rule definition.
		//
		// "Used when IDS Controller creates Cronjobs for AD as the IDS deployment
		// is the owner of the AD Cronjobs - Openshift blocks setting an
		// blockOwnerDeletion to true if an ownerReference refers to a resource
		// you can't set finalizers on"
		if isOpenShift {
			managementRule = append(managementRule,
				rbacv1.PolicyRule{
					APIGroups: []string{"apps"},
					Resources: []string{"deployments/finalizers"},
					Verbs:     []string{"update"},
				})
		}

		rules = append(rules, managementRule...)
	}
	*/

	/* should be good to delete
	// evaluates to tenant != nil && tenatn.GetNamespace() != ""
	if isMultiTenant {
		// These rules are used by Intrusion Detection Controller in a management cluster serving multiple tenants in order to appear to managed
		// clusters as the expected serviceaccount. They're only needed when there are multiple tenants sharing the same
		// management cluster.
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{IntrusionDetectionControllerName},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
				ResourceNames: []string{
					serviceaccount.AllServiceAccountsGroup,
					"system:authenticated",
					fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, IntrusionDetectionNamespace),
				},
			},
		}...)
	}
	*/

	if isOpenShift {
		sccName := securitycontextconstraints.NonRootV2
		// this might not be needed for guardian
		//might be needed only for intrusion detection pods in managed cluster
		/*
			if isSyslogForwardingEnabled {
				sccName = securitycontextconstraints.Privileged
			}
		*/
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{sccName},
		})
	}

	return rules
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
			ObjectMeta: metav1.ObjectMeta{Name: ManagerServiceAccount, Namespace: ManagerNamespace},
		},
		&corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerNamespace},
		},
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerClusterRole},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerClusterRoleBinding},
		},
	}
}
