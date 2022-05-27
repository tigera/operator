// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
//
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

package render

import (
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritycontext"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the PacketCapture APIs related rendered objects.
const (
	PacketCaptureContainerName          = "tigera-packetcapture-server"
	PacketCaptureName                   = "tigera-packetcapture"
	PacketCaptureNamespace              = PacketCaptureName
	PacketCaptureServiceAccountName     = PacketCaptureName
	PacketCaptureClusterRoleName        = PacketCaptureName
	PacketCaptureClusterRoleBindingName = PacketCaptureName
	PacketCaptureDeploymentName         = PacketCaptureName
	PacketCaptureServiceName            = PacketCaptureName
	PacketCapturePort                   = 8444

	PacketCaptureCertSecret = "tigera-packetcapture-server-tls"
)

var PacketCaptureEntityRule = networkpolicy.CreateEntityRule(PacketCaptureNamespace, PacketCaptureDeploymentName, PacketCapturePort)
var PacketCaptureSourceEntityRule = networkpolicy.CreateSourceEntityRule(PacketCaptureNamespace, PacketCaptureDeploymentName)

// PacketCaptureApiConfiguration contains all the config information needed to render the component.
type PacketCaptureApiConfiguration struct {
	PullSecrets        []*corev1.Secret
	Openshift          bool
	Installation       *operatorv1.InstallationSpec
	KeyValidatorConfig authentication.KeyValidatorConfig
	ServerCertSecret   certificatemanagement.KeyPairInterface
	TrustedBundle      certificatemanagement.TrustedBundle
	ClusterDomain      string
}

type packetCaptureApiComponent struct {
	cfg   *PacketCaptureApiConfiguration
	image string
}

func PacketCaptureAPI(cfg *PacketCaptureApiConfiguration) Component {

	return &packetCaptureApiComponent{
		cfg: cfg,
	}
}

func (pc *packetCaptureApiComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := pc.cfg.Installation.Registry
	path := pc.cfg.Installation.ImagePath
	prefix := pc.cfg.Installation.ImagePrefix

	var err error
	pc.image, err = components.GetReference(components.ComponentPacketCapture, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return nil
}

func (pc *packetCaptureApiComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (pc *packetCaptureApiComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		CreateNamespace(PacketCaptureNamespace, pc.cfg.Installation.KubernetesProvider),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(PacketCaptureNamespace, pc.cfg.PullSecrets...)...)...)

	objs = append(objs,
		pc.serviceAccount(),
		pc.clusterRole(),
		pc.clusterRoleBinding(),
		pc.deployment(),
		pc.service(),
	)

	if pc.cfg.KeyValidatorConfig != nil {
		objs = append(objs, secret.ToRuntimeObjects(pc.cfg.KeyValidatorConfig.RequiredSecrets(PacketCaptureNamespace)...)...)
		objs = append(objs, configmap.ToRuntimeObjects(pc.cfg.KeyValidatorConfig.RequiredConfigMaps(PacketCaptureNamespace)...)...)
	}

	if pc.cfg.TrustedBundle != nil {
		objs = append(objs, pc.cfg.TrustedBundle.ConfigMap(PacketCaptureNamespace))
	}
	return objs, nil
}

func (pc *packetCaptureApiComponent) Ready() bool {
	return true
}

func (pc *packetCaptureApiComponent) service() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCaptureServiceName,
			Namespace: PacketCaptureNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": PacketCaptureName,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       PacketCaptureName,
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(PacketCapturePort),
				},
			},
		},
	}
}

func (pc *packetCaptureApiComponent) serviceAccount() client.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PacketCaptureServiceAccountName, Namespace: PacketCaptureNamespace},
	}
}

func (pc *packetCaptureApiComponent) clusterRole() client.Object {

	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/status"},
			Verbs:     []string{"update"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PacketCaptureClusterRoleName,
		},
		Rules: rules,
	}
}

func (pc *packetCaptureApiComponent) clusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PacketCaptureClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     PacketCaptureClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      PacketCaptureServiceAccountName,
				Namespace: PacketCaptureNamespace,
			},
		},
	}
}

func (pc *packetCaptureApiComponent) deployment() client.Object {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCaptureDeploymentName,
			Namespace: PacketCaptureNamespace,
			Labels: map[string]string{
				"k8s-app": PacketCaptureName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": PacketCaptureName,
				},
			},
			Replicas: ptr.Int32ToPtr(1),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      PacketCaptureDeploymentName,
					Namespace: PacketCaptureNamespace,
					Labels: map[string]string{
						"k8s-app": PacketCaptureName,
					},
					Annotations: pc.annotations(),
				},
				Spec: corev1.PodSpec{
					NodeSelector:       pc.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: PacketCaptureServiceAccountName,
					Tolerations:        append(pc.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly),
					ImagePullSecrets:   secret.GetReferenceList(pc.cfg.PullSecrets),
					InitContainers:     pc.initContainers(),
					Containers:         []corev1.Container{pc.container()},
					Volumes:            pc.volumes(),
				},
			},
		},
	}
}

func (pc *packetCaptureApiComponent) initContainers() []corev1.Container {
	var initContainers []corev1.Container
	if pc.cfg.ServerCertSecret.UseCertificateManagement() {
		initContainers = append(initContainers, pc.cfg.ServerCertSecret.InitContainer(PacketCaptureNamespace))
	}
	return initContainers
}

func (pc *packetCaptureApiComponent) container() corev1.Container {
	var volumeMounts = []corev1.VolumeMount{
		pc.cfg.ServerCertSecret.VolumeMount(),
	}
	env := []corev1.EnvVar{
		{Name: "PACKETCAPTURE_API_LOG_LEVEL", Value: "Info"},
		{Name: "PACKETCAPTURE_API_HTTPS_KEY", Value: pc.cfg.ServerCertSecret.VolumeMountKeyFilePath()},
		{Name: "PACKETCAPTURE_API_HTTPS_CERT", Value: pc.cfg.ServerCertSecret.VolumeMountCertificateFilePath()},
	}

	if pc.cfg.KeyValidatorConfig != nil {
		env = append(env, pc.cfg.KeyValidatorConfig.RequiredEnv("PACKETCAPTURE_API_")...)
	}
	if pc.cfg.TrustedBundle != nil {
		volumeMounts = append(volumeMounts, pc.cfg.TrustedBundle.VolumeMount())
	}

	return corev1.Container{
		Name:            PacketCaptureContainerName,
		Image:           pc.image,
		LivenessProbe:   pc.healthProbe(),
		ReadinessProbe:  pc.healthProbe(),
		SecurityContext: podsecuritycontext.NewBaseContext(),
		Env:             env,
		VolumeMounts:    volumeMounts,
	}
}

func (pc *packetCaptureApiComponent) healthProbe() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/health",
				Port:   intstr.FromInt(PacketCapturePort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 30,
		PeriodSeconds:       10,
	}
}

func (pc *packetCaptureApiComponent) volumes() []corev1.Volume {
	var volumes = []corev1.Volume{
		pc.cfg.ServerCertSecret.Volume(),
	}

	if pc.cfg.TrustedBundle != nil {
		volumes = append(volumes, pc.cfg.TrustedBundle.Volume())
	}

	return volumes
}

func (pc *packetCaptureApiComponent) annotations() map[string]string {
	var annotations = map[string]string{
		pc.cfg.ServerCertSecret.HashAnnotationKey(): pc.cfg.ServerCertSecret.HashAnnotationValue(),
	}

	return annotations
}
