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

package whisker

import (
	"fmt"

	"github.com/tigera/operator/pkg/components"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	WhiskerName               = "whisker"
	WhiskerNamespace          = common.CalicoNamespace
	WhiskerServiceAccountName = WhiskerName
	WhiskerDeploymentName     = WhiskerName
	WhiskerClusterRoleName    = WhiskerName

	GoldmaneContainerName              = "goldmane"
	WhiskerContainerName               = "whisker"
	WhiskerBackendContainerName        = "whisker-backend"
	ManagedClusterConnectionSecretName = "tigera-managed-cluster-connection"
)

func Whisker(cfg *Configuration) render.Component {
	c := &Component{cfg: cfg}

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	return c
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets           []*corev1.Secret
	OpenShift             bool
	Installation          *operatorv1.InstallationSpec
	TrustedCertBundle     certificatemanagement.TrustedBundle
	LinseedPublicCASecret *corev1.Secret
}

type Component struct {
	cfg *Configuration

	goldmaneImage       string
	whiskerImage        string
	whiskerBackendImage string
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

	c.whiskerBackendImage, err = components.GetReference(components.ComponentCalicoWhiskerBackend, reg, path, prefix, is)
	if err != nil {
		return err
	}

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
	objs := []client.Object{
		render.CreateNamespace(WhiskerNamespace, c.cfg.Installation.KubernetesProvider, render.PSSRestricted, c.cfg.Installation.Azure),
	}

	objs = append(objs,
		render.CreateOperatorSecretsRoleBinding(WhiskerNamespace),
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.goldmaneService(),
		c.whiskerService(),
		c.cfg.TrustedCertBundle.ConfigMap(WhiskerNamespace))

	objs = append(objs, c.cfg.TrustedCertBundle.ConfigMap(WhiskerNamespace))
	objs = append(objs, c.deployment())
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(WhiskerNamespace, c.cfg.PullSecrets...)...)...)

	return objs, nil
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

func (c *Component) whiskerContainer() corev1.Container {
	return corev1.Container{
		Name:            WhiskerContainerName,
		Image:           c.whiskerImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "INFO"},
			{Name: "CA_CERT_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    c.cfg.TrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux),
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

func (c *Component) whiskerBackendContainer() corev1.Container {
	return corev1.Container{
		Name:            WhiskerBackendContainerName,
		Image:           c.whiskerBackendImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "INFO"},
			{Name: "CA_CERT_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
			{Name: "PORT", Value: "3002"},
			{Name: "GOLDMANE_HOST", Value: "localhost:7443"},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    c.cfg.TrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux),
	}
}

func (c *Component) goldmaneContainer() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "INFO"},
		{Name: "CA_CERT_PATH", Value: "/certs/tls.crt"},
		{Name: "PORT", Value: "7443"},
	}
	var volumeMounts []corev1.VolumeMount
	if c.cfg.LinseedPublicCASecret != nil {
		env = append(env, corev1.EnvVar{
			Name:  "PUSH_URL",
			Value: "https://localhost:8080/api/v1/flows/bulk"})
		volumeMounts = []corev1.VolumeMount{
			secretMount("/certs", c.cfg.LinseedPublicCASecret),
		}
	}

	return corev1.Container{
		Name:            GoldmaneContainerName,
		Image:           c.goldmaneImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env:             env,
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}
}

func (c *Component) goldmaneService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "goldmane",
			Namespace: WhiskerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 7443}},
			Selector: map[string]string{
				"k8s-app": WhiskerDeploymentName,
			},
		},
	}
}

func (c *Component) deployment() *appsv1.Deployment {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	ctrs := []corev1.Container{c.whiskerContainer(), c.whiskerBackendContainer(), c.goldmaneContainer()}
	volumes := []corev1.Volume{c.cfg.TrustedCertBundle.Volume()}
	if c.cfg.LinseedPublicCASecret != nil {
		volumes = append(volumes, secretVolume(c.cfg.LinseedPublicCASecret))
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WhiskerDeploymentName,
			Namespace: WhiskerNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.ToPtr(int32(1)),
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

func secretMount(path string, scrt *corev1.Secret) corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      fmt.Sprintf("%s-%s", scrt.Name, "scrt"),
		MountPath: path,
	}
}

func secretVolume(scrt *corev1.Secret) corev1.Volume {
	return corev1.Volume{
		Name:         fmt.Sprintf("%s-%s", scrt.Name, "scrt"),
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: scrt.Name}},
	}
}

func (c *Component) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: WhiskerClusterRoleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     WhiskerClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      WhiskerClusterRoleName,
				Namespace: WhiskerNamespace,
			},
		},
	}
}

func (c *Component) clusterRole() *rbacv1.ClusterRole {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: WhiskerClusterRoleName,
		},
		Rules: policyRules,
	}
}
