// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
//

package render

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v2"

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
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	DexNamespace             = "tigera-dex"
	DexObjectName            = "tigera-dex"
	DexPodSecurityPolicyName = "tigera-dex"
	DexPort                  = 5556
	DexTLSSecretName         = "tigera-dex-tls"
	DexClientId              = "tigera-manager"
	DexPolicyName            = networkpolicy.TigeraComponentPolicyPrefix + "allow-tigera-dex"
)

var DexEntityRule = networkpolicy.CreateEntityRule(DexNamespace, DexObjectName, DexPort)

func Dex(cfg *DexComponentConfiguration) Component {
	return &dexComponent{
		cfg:       cfg,
		connector: cfg.DexConfig.Connector(),
	}
}

// DexComponentConfiguration contains all the config information needed to render the component.
type DexComponentConfiguration struct {
	PullSecrets   []*corev1.Secret
	Openshift     bool
	Installation  *operatorv1.InstallationSpec
	DexConfig     DexConfig
	ClusterDomain string
	DeleteDex     bool
	TLSKeyPair    certificatemanagement.KeyPairInterface
	TrustedBundle certificatemanagement.TrustedBundle

	// Whether the cluster supports pod security policies.
	UsePSP bool

	Authentication *operatorv1.Authentication
}

type dexComponent struct {
	cfg          *DexComponentConfiguration
	connector    map[string]interface{}
	image        string
	csrInitImage string
}

func (c *dexComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.image, err = components.GetReference(components.ComponentDex, reg, path, prefix, is)

	var errMsgs []string
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if c.cfg.Installation.CertificateManagement != nil {
		c.csrInitImage, err = certificatemanagement.ResolveCSRInitImage(c.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (*dexComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *dexComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.allowTigeraNetworkPolicy(),
		networkpolicy.AllowTigeraDefaultDeny(DexNamespace),
		c.serviceAccount(),
		c.deployment(),
		c.service(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.configMap(),
	}

	// TODO Some of the secrets created in the operator namespace are created by the customer (i.e. oidc credentials)
	// TODO so we can't just do a blanket delete of the secrets in the operator namespace. We need to refactor
	// TODO the RequiredSecrets in the dex condig to not pass back secrets of this type.
	if !c.cfg.DeleteDex {
		objs = append(objs, secret.ToRuntimeObjects(c.cfg.DexConfig.RequiredSecrets(common.OperatorNamespace())...)...)
	}

	objs = append(objs, secret.ToRuntimeObjects(c.cfg.DexConfig.RequiredSecrets(DexNamespace)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(DexNamespace, c.cfg.PullSecrets...)...)...)

	if c.cfg.Installation.CertificateManagement != nil {
		objs = append(objs, certificatemanagement.CSRClusterRoleBinding(DexObjectName, DexNamespace))
	}

	if c.cfg.UsePSP {
		objs = append(objs, c.podSecurityPolicy())
	}

	if c.cfg.DeleteDex {
		return nil, objs
	}

	return objs, nil
}

func (c *dexComponent) Ready() bool {
	return true
}

func (c *dexComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: DexObjectName, Namespace: DexNamespace},
	}
}

func (c *dexComponent) clusterRole() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"dex.coreos.com"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{"apiextensions.k8s.io"},
			Resources: []string{"customresourcedefinitions"},
			Verbs:     []string{"create"},
		},
	}

	if c.cfg.UsePSP {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{DexPodSecurityPolicyName},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DexObjectName,
		},
		Rules: rules,
	}
}

func (c *dexComponent) clusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DexObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     DexObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      DexObjectName,
				Namespace: DexNamespace,
			},
		},
	}
}

func (c *dexComponent) podSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy(DexPodSecurityPolicyName)
}

func (c *dexComponent) deployment() client.Object {
	var initContainers []corev1.Container
	if c.cfg.TLSKeyPair.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TLSKeyPair.InitContainer(DexNamespace))
	}

	annotations := c.cfg.DexConfig.RequiredAnnotations()
	for k, v := range c.cfg.TrustedBundle.HashAnnotations() {
		annotations[k] = v
	}
	annotations[c.cfg.TLSKeyPair.HashAnnotationKey()] = c.cfg.TLSKeyPair.HashAnnotationValue()

	mounts := c.cfg.DexConfig.RequiredVolumeMounts()
	mounts = append(mounts, c.cfg.TLSKeyPair.VolumeMount(c.SupportedOSType()))
	mounts = append(mounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Installation.ControlPlaneReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        DexObjectName,
					Namespace:   DexNamespace,
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: DexObjectName,
					Tolerations:        append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...),
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					InitContainers:     initContainers,
					Containers: []corev1.Container{
						{
							Name:            DexObjectName,
							Image:           c.image,
							ImagePullPolicy: ImagePullPolicy(),
							Env: append(
								[]corev1.EnvVar{
									{Name: "FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode)},
								},
								c.cfg.DexConfig.RequiredEnv("")...),
							LivenessProbe:   c.probe(),
							SecurityContext: securitycontext.NewNonRootContext(),

							Command: []string{"/dex", "serve", "/etc/dex/baseCfg/config.yaml"},

							Ports: []corev1.ContainerPort{
								{
									Name:          "https",
									ContainerPort: DexPort,
								},
							},
							VolumeMounts: mounts,
						},
					},
					Volumes: append(c.cfg.DexConfig.RequiredVolumes(), c.cfg.TLSKeyPair.Volume(), trustedBundleVolume(c.cfg.TrustedBundle)),
				},
			},
		},
	}

	if c.cfg.Installation.ControlPlaneReplicas != nil && *c.cfg.Installation.ControlPlaneReplicas > 1 {
		d.Spec.Template.Spec.Affinity = podaffinity.NewPodAntiAffinity(DexObjectName, DexNamespace)
	}

	if c.cfg.Authentication != nil {
		if overrides := c.cfg.Authentication.Spec.DexDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (c *dexComponent) service() client.Object {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": DexObjectName,
			},
			Ports: []corev1.ServicePort{
				{
					Name: DexObjectName,
					Port: DexPort,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: DexPort,
					},
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}

// Perform a HTTP GET to determine if an endpoint is available.
func (c *dexComponent) probe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/dex/.well-known/openid-configuration",
				Port:   intstr.FromInt(DexPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
	}
}

func (c *dexComponent) configMap() *corev1.ConfigMap {
	bytes, err := yaml.Marshal(map[string]interface{}{
		"issuer": c.cfg.DexConfig.Issuer(),
		"storage": map[string]interface{}{
			"type": "kubernetes",
			"config": map[string]bool{
				"inCluster": true,
			},
		},
		"web": map[string]interface{}{
			"https":                   "0.0.0.0:5556",
			"tlsCert":                 c.cfg.TLSKeyPair.VolumeMountCertificateFilePath(),
			"tlsKey":                  c.cfg.TLSKeyPair.VolumeMountKeyFilePath(),
			"allowedOrigins":          []string{"*"},
			"discoveryAllowedOrigins": []string{"*"},
		},
		"connectors": []map[string]interface{}{c.connector},
		"oauth2": map[string]interface{}{
			"skipApprovalScreen": true,
			"responseTypes":      []string{"id_token", "code", "token"},
		},
		"staticClients": []map[string]interface{}{
			{
				"id":           DexClientId,
				"redirectURIs": c.cfg.DexConfig.RedirectURIs(),
				"name":         "Calico Enterprise Manager",
				"secretEnv":    dexSecretEnv,
			},
		},
		"expiry": map[string]string{
			// Default duration is 24h. This is too high for most organizations. Setting it to 15m.
			"idTokens": "15m",
		},
	})
	if err != nil {
		// Panic since this would be a developer error, as the marshaled struct is one created by our code.
		panic(err)
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
		},
		Data: map[string]string{
			"config.yaml": string(bytes),
		},
	}
}

func (c *dexComponent) allowTigeraNetworkPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Openshift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},

		// These rules allow egress between dex and identity providers.
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets:  []string{"0.0.0.0/0"},
				Ports: networkpolicy.Ports(443, 6443, 389, 636),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets:  []string{"::/0"},
				Ports: networkpolicy.Ports(443, 6443, 389, 636),
			},
		},
	}...)

	dexIngressPortDestination := v3.EntityRule{
		Ports: networkpolicy.Ports(DexPort),
	}

	networkpolicyHelper := networkpolicy.DefaultHelper()

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexPolicyName,
			Namespace: DexNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(DexObjectName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().ManagerSourceEntityRule(),
					Destination: dexIngressPortDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.DefaultHelper().ESGatewaySourceEntityRule(),
					Destination: dexIngressPortDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicyHelper.ComplianceServerSourceEntityRule(),
					Destination: dexIngressPortDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      PacketCaptureSourceEntityRule,
					Destination: dexIngressPortDestination,
				},
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Source:      networkpolicy.PrometheusSourceEntityRule,
					Destination: dexIngressPortDestination,
				},
			},
			Egress: egressRules,
		},
	}
}
