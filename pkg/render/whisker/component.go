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
)

// The names of the components related to the Guardian related rendered objects.
const (
	WhiskerName               = "whisker"
	WhiskerNamespace          = common.CalicoNamespace
	WhiskerServiceAccountName = WhiskerName
	WhiskerDeploymentName     = WhiskerName
	WhiskerRoleName           = WhiskerName

	GoldmaneContainerName              = "goldmane"
	WhiskerContainerName               = "whisker"
	WhiskerBackendContainerName        = "whisker-backend"
	ManagedClusterConnectionSecretName = "tigera-managed-cluster-connection"
)

func Whisker(cfg *Configuration) render.Component {
	c := &Component{cfg: cfg}

	return c
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets  []*corev1.Secret
	OpenShift    bool
	Installation *operatorv1.InstallationSpec
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
		c.role(),
		c.roleBinding(),
		c.goldmaneService(),
		c.whiskerService(),
	)

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
		},
		SecurityContext: securitycontext.NewNonRootContext(),
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
			{Name: "PORT", Value: "3002"},
			{Name: "GOLDMANE_HOST", Value: "localhost:7443"},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
	}
}

func (c *Component) goldmaneContainer() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "INFO"},
		{Name: "CA_CERT_PATH", Value: "/certs/tls.crt"},
		{Name: "PORT", Value: "7443"},
	}

	return corev1.Container{
		Name:            GoldmaneContainerName,
		Image:           c.goldmaneImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env:             env,
		SecurityContext: securitycontext.NewNonRootContext(),
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
				},
			},
		},
	}
}

func (c *Component) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WhiskerRoleName,
			Namespace: WhiskerNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     WhiskerRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      WhiskerRoleName,
				Namespace: WhiskerNamespace,
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
			Name:      WhiskerRoleName,
			Namespace: WhiskerNamespace,
		},
		Rules: policyRules,
	}
}
