// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package whisker

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	_ "embed"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	WhiskerName               = "whisker"
	WhiskerNamespace          = common.CalicoNamespace
	WhiskerServiceAccountName = WhiskerName
	WhiskerDeploymentName     = WhiskerName
	WhiskerPolicyName         = networkpolicy.CalicoComponentPolicyPrefix + WhiskerName

	WhiskerContainerName        = "whisker"
	WhiskerBackendContainerName = "whisker-backend"

	WhiskerBackendKeyPairSecret   = "whisker-backend-key-pair"
	WhiskerBackendClusterRoleName = "whisker-backend"
	WhiskerBackendLinseedAPIGroup = "linseed.tigera.io"

	GoldmaneDeploymentName = "goldmane"
	GoldmaneServicePort    = 7443
	GoldmaneNamespace      = common.CalicoNamespace

	configMapName    = "whisker-nginx-config"
	configVolumeName = "nginx-config"
	configMountPath  = "/etc/nginx/conf.d"
)

var (
	// Embed the nginx config files.
	//go:embed nginx-v4.conf
	NginxConfigV4 string

	//go:embed nginx.conf
	NginxConfigDual string
)

func Whisker(cfg *Configuration) render.Component {
	c := &Component{cfg: cfg}

	return c
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets           []*corev1.Secret
	OpenShift             bool
	Installation          *operatorv1.InstallationSpec
	TrustedCertBundle     certificatemanagement.TrustedBundleRO
	WhiskerBackendKeyPair certificatemanagement.KeyPairInterface
	Whisker               *operatorv1.Whisker
	ClusterID             string
	CalicoVersion         string
	ClusterType           string
	ClusterDomain         string
}

type Component struct {
	cfg *Configuration

	whiskerImage string
	calicoImage  string
}

func (c *Component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error

	c.whiskerImage, err = components.GetReference(components.ComponentCalicoWhisker, reg, path, prefix, is)
	if err != nil {
		return err
	}
	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	return err
}

func (c *Component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *Component) Objects() ([]client.Object, []client.Object) {
	deployment := c.deployment()
	if overrides := c.cfg.Whisker.Spec.WhiskerDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(deployment, overrides)
	}

	toCreate := []client.Object{
		c.serviceAccount(),
		deployment,
		c.networkPolicy(),
	}

	if c.isEnterprise() {
		toCreate = append(toCreate, c.whiskerBackendClusterRole(), c.whiskerBackendClusterRoleBinding())
	} else {
		// The nginx config and Service front the Whisker UI, which is not rendered for enterprise.
		toCreate = append(toCreate, c.nginxConfigMap(), c.whiskerService())
	}

	toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(WhiskerNamespace, c.cfg.PullSecrets...)...)...)

	var toDelete []client.Object

	toDelete = append(toDelete, c.deprecatedObjects()...)

	return toCreate, toDelete
}

func (c *Component) Ready() bool {
	return true
}

func (c *Component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerServiceAccountName, Namespace: WhiskerNamespace},
	}
}

func (c *Component) whiskerBackendClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerBackendClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{WhiskerBackendLinseedAPIGroup},
				Resources: []string{"flows"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

func (c *Component) whiskerBackendClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerBackendClusterRoleName},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     WhiskerBackendClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      WhiskerServiceAccountName,
				Namespace: WhiskerNamespace,
			},
		},
	}
}

func (c *Component) whiskerContainer() corev1.Container {
	return corev1.Container{
		Name:  WhiskerContainerName,
		Image: c.whiskerImage,
		Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "INFO"},
			{Name: "CALICO_VERSION", Value: c.cfg.CalicoVersion},
			{Name: "CLUSTER_ID", Value: c.cfg.ClusterID},
			{Name: "CLUSTER_TYPE", Value: c.cfg.ClusterType},
			{Name: "NOTIFICATIONS", Value: string(*c.cfg.Whisker.Spec.Notifications)},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      configVolumeName,
				MountPath: configMountPath,
				ReadOnly:  true,
			},
		},
	}
}

func (c *Component) whiskerService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "whisker",
			Namespace: WhiskerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8081}},
			Selector: map[string]string{
				"k8s-app": WhiskerDeploymentName,
			},
		},
	}
}

func (c *Component) isEnterprise() bool {
	return c.cfg.Installation.Variant.IsEnterprise()
}

func (c *Component) whiskerBackendContainer() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "INFO"},
		{Name: "PORT", Value: "3002"},
	}

	if c.isEnterprise() {
		env = append(env,
			corev1.EnvVar{Name: "TLS_CERT_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath()},
			corev1.EnvVar{Name: "TLS_KEY_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath()},
			corev1.EnvVar{Name: "WHISKER_BACKEND_UPSTREAM", Value: "linseed"},
			corev1.EnvVar{
				Name:  "LINSEED_URL",
				Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, render.ElasticsearchNamespace, false, false),
			},
			corev1.EnvVar{Name: "LINSEED_CA_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
			corev1.EnvVar{Name: "LINSEED_TOKEN_PATH", Value: render.GetLinseedTokenPath(false)},
			corev1.EnvVar{Name: "LINSEED_CLUSTER_ID", Value: render.DefaultElasticsearchClusterName},
			corev1.EnvVar{Name: "LINSEED_CLIENT_CERT_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath()},
			corev1.EnvVar{Name: "LINSEED_CLIENT_KEY_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath()},
		)
	} else {
		env = append(env,
			corev1.EnvVar{Name: "GOLDMANE_HOST", Value: fmt.Sprintf("goldmane.%s.svc.%s:7443", GoldmaneNamespace, c.cfg.ClusterDomain)},
			corev1.EnvVar{Name: "TLS_CERT_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath()},
			corev1.EnvVar{Name: "TLS_KEY_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath()},
		)
	}

	return corev1.Container{
		Name:            WhiskerBackendContainerName,
		Image:           c.calicoImage,
		Command:         []string{components.CalicoBinaryPath, "component", "whisker-backend"},
		Env:             env,
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts: append(
			c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
			c.cfg.WhiskerBackendKeyPair.VolumeMount(c.SupportedOSType())),
	}
}

func (c *Component) deployment() *appsv1.Deployment {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	volumes := []corev1.Volume{
		// Add the trusted cert bundle volume to the pod.
		c.cfg.TrustedCertBundle.Volume(),

		// Add the whisker backend key pair volume to the pod.
		c.cfg.WhiskerBackendKeyPair.Volume(),
	}

	// For enterprise only the whisker-backend is rendered; the Whisker UI (SPA) and its
	// nginx config are managed separately.
	ctrs := []corev1.Container{c.whiskerBackendContainer()}
	if !c.isEnterprise() {
		ctrs = []corev1.Container{c.whiskerContainer(), c.whiskerBackendContainer()}

		// Volume for nginx config from config map.
		volumes = append(volumes, corev1.Volume{
			Name: configVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
				},
			},
		})
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WhiskerDeploymentName,
			Namespace: WhiskerNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: WhiskerDeploymentName,
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: WhiskerServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         ctrs,
					Volumes:            volumes,
				},
			},
		},
	}
}

func (c *Component) networkPolicy() *v3.NetworkPolicy {
	var egressRules []v3.Rule

	if c.isEnterprise() {
		egressRules = append(egressRules,
			v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Destination: networkpolicy.DefaultHelper().LinseedEntityRule(),
			},
			v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Destination: networkpolicy.KubeAPIServerEntityRule,
			},
		)
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: networkpolicy.KubernetesAppSelector(GoldmaneDeploymentName),
				Ports:    networkpolicy.Ports(GoldmaneServicePort),
			},
		})
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.OpenShift)

	return &v3.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerPolicyName, Namespace: WhiskerNamespace},
		Spec: v3.NetworkPolicySpec{
			Tier:     networkpolicy.CalicoTierName,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Selector: networkpolicy.KubernetesAppSelector(WhiskerDeploymentName),
			Egress:   egressRules,
		},
	}
}

func (c *Component) nginxConfigMap() *corev1.ConfigMap {
	// Determine which config to use based on supported IP families.
	config := NginxConfigV4
	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.NodeAddressAutodetectionV6 != nil {
		config = NginxConfigDual
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: WhiskerNamespace,
		},
		Data: map[string]string{
			"default.conf": config,
		},
	}
}

// deprecatedObjects returns any objects that should be removed when Whisker is enabled, but were used in
// previous versions of the operator.
func (c *Component) deprecatedObjects() []client.Object {
	return []client.Object{
		// Deprecates k8s NetworkPolicy because Calico components now also have Tiers component enabled.
		&netv1.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "whisker", Namespace: WhiskerNamespace},
		},
	}
}
