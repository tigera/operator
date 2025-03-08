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
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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

	WhiskerContainerName        = "whisker"
	WhiskerBackendContainerName = "whisker-backend"

	WhiskerBackendKeyPairSecret = "whisker-backend-key-pair"
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
}

type Component struct {
	cfg *Configuration

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

	return nil
}

func (c *Component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *Component) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.serviceAccount(),
		c.deployment(),
		c.whiskerService(),
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(WhiskerNamespace, c.cfg.PullSecrets...)...)...)

	// Whisker needs to be removed if the installation is not Calico, since it's not supported (yet!) for any other variant.
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
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerServiceAccountName, Namespace: WhiskerNamespace},
	}
}

func (c *Component) whiskerContainer() corev1.Container {
	env := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "INFO"},
		{Name: "PORT", Value: "3002"},
		{Name: "GOLDMANE_HOST", Value: "localhost:7443"},
	}
	volumeMounts := c.cfg.TrustedCertBundle.VolumeMounts(rmeta.OSTypeLinux)
	if c.cfg.WhiskerBackendKeyPair != nil {
		env = append(env,
			corev1.EnvVar{
				Name:  "TLS_KEY_PATH",
				Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath(),
			},
			corev1.EnvVar{
				Name:  "TLS_CERT_PATH",
				Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath(),
			},
		)
		volumeMounts = append(volumeMounts, c.cfg.WhiskerBackendKeyPair.VolumeMount(c.SupportedOSType()))
	}

	return corev1.Container{
		Name:            WhiskerBackendContainerName,
		Image:           c.whiskerBackendImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env:             env,
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
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
			{Name: "GOLDMANE_HOST", Value: "goldmane.calico-system.svc.cluster.local:7443"},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
	}
}

func (c *Component) deployment() *appsv1.Deployment {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	ctrs := []corev1.Container{c.whiskerContainer(), c.whiskerBackendContainer()}
	volumes := []corev1.Volume{c.cfg.TrustedCertBundle.Volume()}

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
