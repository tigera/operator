// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	"github.com/tigera/operator/pkg/common"
	_k8s "github.com/tigera/operator/pkg/k8s"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/guardian"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
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
)

func Whisker(cfg *Configuration) render.Component {
	c := &WhiskerComponent{cfg: cfg}

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	dep := _k8s.NewDeployment(appsv1.Deployment{
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
				},
			},
		},
	})

	dep.AddContainers(c.whisker(), c.whiskerBackend(), c.goldmane())
	if c.cfg.ManagementClusterConnection != nil {
		guardianCtr := guardian.Container(cfg.ManagementClusterConnection.Spec.TLS.CA, c.cfg.ManagementClusterConnection.Spec.ManagementClusterAddr, c.cfg.TrustedCertBundle, c.cfg.TunnelSecret, c.cfg.Installation.Proxy.EnvVars())
		dep.AddContainers(guardianCtr)
	}

	c.dep = dep
	return c
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	Installation                *operatorv1.InstallationSpec
	TunnelSecret                *corev1.Secret
	TrustedCertBundle           certificatemanagement.TrustedBundle
	LinseedPublicCASecret       *corev1.Secret
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
}

type WhiskerComponent struct {
	cfg   *Configuration
	dep   *_k8s.Deployment
	image string
}

func (c *WhiskerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return c.dep.ApplyImageSet(c.cfg.Installation, is)
}

func (c *WhiskerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *WhiskerComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		render.CreateNamespace(WhiskerNamespace, c.cfg.Installation.KubernetesProvider, render.PSSRestricted, c.cfg.Installation.Azure),
	}

	objs = append(objs,
		render.CreateOperatorSecretsRoleBinding(WhiskerNamespace),
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding())
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(WhiskerNamespace, c.cfg.PullSecrets...)...)...)

	objs = append(objs, c.cfg.TrustedCertBundle.ConfigMap(WhiskerNamespace))
	objs = append(objs, c.dep.Objects()...)

	if c.cfg.ManagementClusterConnection != nil && c.cfg.TunnelSecret != nil {
		objs = append(objs, secret.CopyToNamespace(WhiskerNamespace, c.cfg.TunnelSecret)[0])
	}

	return objs, nil
}

func (c *WhiskerComponent) Ready() bool {
	return true
}

func (c *WhiskerComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerServiceAccountName, Namespace: WhiskerNamespace},
	}
}

func (c *WhiskerComponent) whisker() *_k8s.Container {
	return _k8s.NewContainer("whisker", components.Component{
		Image:    "calico/whisker",
		Version:  "bmv1.10",
		Registry: "gcr.io/unique-caldron-775/brianmcmahon/",
	}).AddEnv(
		[]corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "DEBUG"},
			{Name: "CA_CERT_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		}...).MountConfigMap(c.cfg.TrustedCertBundle.VolumeMountPath(rmeta.OSTypeLinux), c.cfg.TrustedCertBundle.ConfigMap("")).
		AddService(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "whisker"},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8081}}},
		})
}

func (c *WhiskerComponent) whiskerBackend() *_k8s.Container {
	return _k8s.NewContainer("whisker-backend", components.Component{
		Image:    "calico/whisker-backend",
		Version:  "bmv1.10",
		Registry: "gcr.io/unique-caldron-775/brianmcmahon/",
	}).AddEnv([]corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "DEBUG"},
		{Name: "CA_CERT_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "PORT", Value: "3002"},
		{Name: "GOLDMANE_HOST", Value: "localhost:7443"},
	}...).
		MountConfigMap(c.cfg.TrustedCertBundle.VolumeMountPath(rmeta.OSTypeLinux), c.cfg.TrustedCertBundle.ConfigMap(""))
}

func (c *WhiskerComponent) goldmane() *_k8s.Container {
	ctr := _k8s.NewContainer("goldmane", components.Component{
		Image:    "calico/goldmane",
		Version:  "bmv1.10",
		Registry: "gcr.io/unique-caldron-775/brianmcmahon/",
	}).
		AddEnv(
			[]corev1.EnvVar{
				{Name: "LOG_LEVEL", Value: "INFO"},
				{Name: "CA_CERT_PATH", Value: "/certs/tls.crt"},
				{Name: "PORT", Value: "7443"},
			}...,
		).
		AddService(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "goldmane",
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 7443}},
			},
		})
	if c.cfg.LinseedPublicCASecret != nil {
		ctr.
			MountSecret("/certs", copySecret(c.cfg.LinseedPublicCASecret)).
			AddEnv([]corev1.EnvVar{
				{Name: "PUSH_URL", Value: fmt.Sprintf("https://%s.%s.svc/api/v1/flows/bulk", "tigera-guardian", WhiskerNamespace)},
			}...)
	}

	return ctr
}

func (c *WhiskerComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
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

func (c *WhiskerComponent) clusterRole() *rbacv1.ClusterRole {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
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

func copySecret(s *corev1.Secret) *corev1.Secret {
	x := s.DeepCopy()
	x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: s.Namespace}

	return x

}
