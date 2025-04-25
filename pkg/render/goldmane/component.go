// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package goldmane

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	GoldmaneName               = "goldmane"
	GoldmaneNamespace          = common.CalicoNamespace
	GoldmaneServiceAccountName = GoldmaneName
	GoldmaneDeploymentName     = GoldmaneName
	GoldmaneRoleName           = GoldmaneName
	GoldmaneServicePort        = 7443
	GoldmaneContainerName      = "goldmane"

	GoldmaneKeyPairSecret = "goldmane-key-pair"
	GoldmaneServiceName   = "goldmane"

	GoldmaneConfigVolumeName = "config"
	GoldmaneConfigFilePath   = "/config"
	GoldmaneConfigFileName   = "config.json"
)

func Goldmane(cfg *Configuration) render.Component {
	c := &Component{cfg: cfg}

	return c
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	Installation                *operatorv1.InstallationSpec
	TrustedCertBundle           certificatemanagement.TrustedBundleRO
	GoldmaneServerKeyPair       certificatemanagement.KeyPairInterface
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	ClusterDomain               string
	Goldmane                    *operatorv1.Goldmane
}

type Component struct {
	cfg *Configuration

	goldmaneImage string
}

func (c *Component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error

	c.goldmaneImage, err = components.GetReference(components.ComponentCalicoGoldmane, reg, path, prefix, is)
	if err != nil {
		return err
	}

	return nil
}

func (c *Component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *Component) Objects() ([]client.Object, []client.Object) {
	deployment := c.deployment()
	if overrides := c.cfg.Goldmane.Spec.GoldmaneDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(deployment, overrides)
	}

	objs := []client.Object{
		c.serviceAccount(),
		c.role(),
		c.roleBinding(),
		c.hotReloadConfigMap(),
		c.goldmaneService(),
		deployment,
		c.networkPolicy(),
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(GoldmaneNamespace, c.cfg.PullSecrets...)...)...)

	// Goldmane needs to be removed if the installation is not Calico, since it's not supported (yet!) for any other variant.
	if c.cfg.Installation.Variant == operatorv1.Calico {
		return objs, nil
	} else {
		return nil, objs
	}
}

func (c *Component) Ready() bool {
	return true
}

func (c *Component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GoldmaneServiceAccountName, Namespace: GoldmaneNamespace},
	}
}

// hotReloadConfigMap returns a ConfigMap containing configuration for Goldmane that does not require a restart of the pod.
// This is mounted as a file within the Pod, which can be dynamically reloaded when changed.
func (c *Component) hotReloadConfigMap() *corev1.ConfigMap {
	type configMapData struct {
		EmitFlows bool `json:"emitFlows"`
	}

	d, err := json.Marshal(configMapData{EmitFlows: c.cfg.ManagementClusterConnection != nil})
	if err != nil {
		panic(fmt.Sprintf("BUG: failed to marshal config map data: %s", err))
	}

	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GoldmaneName, Namespace: GoldmaneNamespace},
		Data: map[string]string{
			GoldmaneConfigFileName: string(d),
		},
	}
}

func (c *Component) goldmaneContainer() corev1.Container {
	guardianSvc := render.GuardianService(c.cfg.ClusterDomain)
	env := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "INFO"},
		{Name: "PORT", Value: fmt.Sprintf("%d", GoldmaneServicePort)},
		{Name: "SERVER_CERT_PATH", Value: c.cfg.GoldmaneServerKeyPair.VolumeMountCertificateFilePath()},
		{Name: "SERVER_KEY_PATH", Value: c.cfg.GoldmaneServerKeyPair.VolumeMountKeyFilePath()},
		{Name: "CA_CERT_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "PUSH_URL", Value: fmt.Sprintf("%s/api/v1/flows/bulk", guardianSvc)},
		{Name: "FILE_CONFIG_PATH", Value: filepath.Join(GoldmaneConfigFilePath, GoldmaneConfigFileName)},
		{Name: "HEALTH_ENABLED", Value: "true"},
	}

	volumeMounts := []corev1.VolumeMount{c.cfg.GoldmaneServerKeyPair.VolumeMount(c.SupportedOSType())}
	volumeMounts = append(volumeMounts, c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())...)
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      GoldmaneConfigVolumeName,
		ReadOnly:  true,
		MountPath: GoldmaneConfigFilePath,
	})

	return corev1.Container{
		Name:            GoldmaneContainerName,
		Image:           c.goldmaneImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env:             env,
		SecurityContext: securitycontext.NewNonRootContext(),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
				Command: []string{"/health", "-ready"},
			}},
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{"/health", "-live"},
				},
			},
		},
		VolumeMounts: volumeMounts,
	}
}

func (c *Component) goldmaneService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoldmaneServiceName,
			Namespace: GoldmaneNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: GoldmaneServicePort}},
			Selector: map[string]string{
				"k8s-app": GoldmaneDeploymentName,
			},
		},
	}
}

func (c *Component) deployment() *appsv1.Deployment {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	ctrs := []corev1.Container{c.goldmaneContainer()}
	volumes := []corev1.Volume{
		c.cfg.GoldmaneServerKeyPair.Volume(),
		c.cfg.TrustedCertBundle.Volume(),
		{
			Name: GoldmaneConfigVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: GoldmaneName},
				},
			},
		},
	}

	// Add an annotation for the key pair as it requires a server restart (may as well restart the pod). Don't add an
	// annotation for the mount CA since it's used for a client that can pick up the changes without a pod restart.
	annotations := map[string]string{
		c.cfg.GoldmaneServerKeyPair.HashAnnotationKey(): c.cfg.GoldmaneServerKeyPair.HashAnnotationValue(),
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        GoldmaneDeploymentName,
			Namespace:   GoldmaneNamespace,
			Annotations: annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.ToPtr(int32(1)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: GoldmaneDeploymentName,
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: GoldmaneServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         ctrs,
					Volumes:            volumes,
				},
			},
		},
	}
}

func (c *Component) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoldmaneRoleName,
			Namespace: GoldmaneNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     GoldmaneRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GoldmaneRoleName,
				Namespace: GoldmaneNamespace,
			},
		},
	}
}

func (c *Component) role() *rbacv1.Role {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
	}

	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GoldmaneRoleName,
			Namespace: GoldmaneNamespace,
		},
		Rules: policyRules,
	}
}

func (c *Component) deploymentSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app.kubernetes.io/name": GoldmaneDeploymentName,
		},
	}
}

func (c *Component) networkPolicy() *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GoldmaneName, Namespace: GoldmaneNamespace},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: *c.deploymentSelector(),
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					Ports: []netv1.NetworkPolicyPort{{
						Protocol: ptr.ToPtr(corev1.ProtocolTCP),
						Port:     ptr.ToPtr(intstr.FromInt32(GoldmaneServicePort)),
					}},
				},
			},
		},
	}
}
