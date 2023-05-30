// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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
	"net"

	appsv1 "k8s.io/api/apps/v1"
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
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	GuardianName                   = "tigera-guardian"
	GuardianNamespace              = GuardianName
	GuardianServiceAccountName     = GuardianName
	GuardianClusterRoleName        = GuardianName
	GuardianClusterRoleBindingName = GuardianName
	GuardianDeploymentName         = GuardianName
	GuardianPodSecurityPolicyName  = GuardianName
	GuardianServiceName            = "tigera-guardian"
	GuardianVolumeName             = "tigera-guardian-certs"
	GuardianSecretName             = "tigera-managed-cluster-connection"
	GuardianTargetPort             = 8080
	GuardianPolicyName             = networkpolicy.TigeraComponentPolicyPrefix + "guardian-access"
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
	URL               string
	PullSecrets       []*corev1.Secret
	Openshift         bool
	Installation      *operatorv1.InstallationSpec
	TunnelSecret      *corev1.Secret
	TrustedCertBundle certificatemanagement.TrustedBundle
	TunnelCAType      operatorv1.CAType

	// Whether the cluster supports pod security policies.
	UsePSP bool
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
	c.image, err = components.GetReference(components.ComponentGuardian, reg, path, prefix, is)
	return err
}

func (c *GuardianComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *GuardianComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		CreateNamespace(GuardianNamespace, c.cfg.Installation.KubernetesProvider, PSSRestricted),
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(GuardianNamespace, c.cfg.PullSecrets...)...)...)
	objs = append(objs,
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.deployment(),
		c.service(),
		secret.CopyToNamespace(GuardianNamespace, c.cfg.TunnelSecret)[0],
		c.cfg.TrustedCertBundle.ConfigMap(GuardianNamespace),
		// Add tigera-manager service account for impersonation
		CreateNamespace(ManagerNamespace, c.cfg.Installation.KubernetesProvider, PSSRestricted),
		managerServiceAccount("tigera-manager"), // TODO
		managerClusterRole(false, true, c.cfg.UsePSP),
		// TODO: Use dynamic namespace. This might actually be tricky, because
		// we need namespaces in the managed cluster to match up with the management cluster
		// for RBAC to work properly. We may need to rethink this appraoch a bit.
		managerClusterRoleBinding(ManagerNamespace),
		managerClusterWideSettingsGroup(),
		managerUserSpecificSettingsGroup(),
		managerClusterWideTigeraLayer(),
		managerClusterWideDefaultView(),
	)

	if c.cfg.UsePSP {
		objs = append(objs, c.podSecurityPolicy())
	}
	return objs, nil
}

func (c *GuardianComponent) Ready() bool {
	return true
}

func (c *GuardianComponent) service() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianServiceName,
			Namespace: GuardianNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": GuardianName,
			},
			Ports: []corev1.ServicePort{
				{
					Name: "linseed",
					Port: 443,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
					Protocol: corev1.ProtocolTCP,
				},
				{
					Name: "elasticsearch",
					Port: 9200,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
					Protocol: corev1.ProtocolTCP,
				},
				{
					Name: "kibana",
					Port: 5601,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *GuardianComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianServiceAccountName, Namespace: GuardianNamespace},
	}
}

func (c *GuardianComponent) podSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy(GuardianPodSecurityPolicyName)
}

func (c *GuardianComponent) clusterRole() *rbacv1.ClusterRole {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"users", "groups", "serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},
	}

	if c.cfg.UsePSP {
		// Allow access to the pod security policy in case this is enforced on the cluster
		policyRules = append(policyRules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{GuardianPodSecurityPolicyName},
		})
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

	return &appsv1.Deployment{
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
					Tolerations:        append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...),
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         c.container(),
					Volumes:            c.volumes(),
				},
			},
		},
	}
}

func (c *GuardianComponent) volumes() []corev1.Volume {
	return []corev1.Volume{
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
}

func (c *GuardianComponent) container() []corev1.Container {
	return []corev1.Container{
		{
			Name:            GuardianDeploymentName,
			Image:           c.image,
			ImagePullPolicy: ImagePullPolicy(),
			Env: []corev1.EnvVar{
				{Name: "GUARDIAN_PORT", Value: "9443"},
				{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
				{Name: "GUARDIAN_VOLTRON_URL", Value: c.cfg.URL},
				{Name: "GUARDIAN_VOLTRON_CA_TYPE", Value: string(c.cfg.TunnelCAType)},
				{Name: "GUARDIAN_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
				{Name: "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
				{Name: "GUARDIAN_QUERYSERVER_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
				{Name: "GUARDIAN_FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode)},
			},
			VolumeMounts: c.volumeMounts(),
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 90,
				PeriodSeconds:       10,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 10,
				PeriodSeconds:       5,
			},
			SecurityContext: securitycontext.NewNonRootContext(),
		},
	}
}

func (c *GuardianComponent) volumeMounts() []corev1.VolumeMount {
	return append(
		c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
		corev1.VolumeMount{Name: GuardianVolumeName, MountPath: "/certs/", ReadOnly: true},
	)
}

func (c *GuardianComponent) annotations() map[string]string {
	annotations := c.cfg.TrustedCertBundle.HashAnnotations()
	annotations["hash.operator.tigera.io/tigera-managed-cluster-connection"] = rmeta.AnnotationHash(c.cfg.TunnelSecret.Data)
	return annotations
}

func guardianAllowTigeraPolicy(cfg *GuardianConfiguration) (*v3.NetworkPolicy, error) {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: PacketCaptureEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Openshift)
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

	// Assumes address has the form "host:port", required by net.Dial for TCP.
	host, port, err := net.SplitHostPort(cfg.URL)
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
	}

	egressRules = append(egressRules, v3.Rule{Action: v3.Pass})

	guardianIngressDestinationEntityRule := v3.EntityRule{Ports: networkpolicy.Ports(8080)}
	ingressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      FluentdSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      ComplianceBenchmarkerSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      ComplianceReporterSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      ComplianceSnapshotterSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      ComplianceControllerSourceEntityRule,
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
