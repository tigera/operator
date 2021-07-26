// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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
	"fmt"
	"strings"

	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritycontext"
	"github.com/tigera/operator/pkg/render/common/secret"
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

	PacketCaptureCertSecret        = "tigera-packetcapture-server-tls"
	PacketCaptureTLSHashAnnotation = "hash.operator.tigera.io/packetcapture-certificate"
)

type packetCaptureApiComponent struct {
	pullSecrets        []*v1.Secret
	openshift          bool
	installation       *operatorv1.InstallationSpec
	image              string
	csrInitImage       string
	keyValidatorConfig authentication.KeyValidatorConfig
	serverCertSecret   *corev1.Secret
	clusterDomain      string
}

func PacketCaptureAPI(pullSecrets []*v1.Secret, openshift bool,
	installation *operatorv1.InstallationSpec,
	keyValidatorConfig authentication.KeyValidatorConfig,
	serverCertSecret *corev1.Secret,
	clusterDomain string) Component {

	return &packetCaptureApiComponent{
		pullSecrets:        pullSecrets,
		openshift:          openshift,
		installation:       installation,
		keyValidatorConfig: keyValidatorConfig,
		serverCertSecret:   serverCertSecret,
		clusterDomain:      clusterDomain,
	}
}

func (pc *packetCaptureApiComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := pc.installation.Registry
	path := pc.installation.ImagePath
	prefix := pc.installation.ImagePrefix

	var err error
	var errMsg []string
	pc.image, err = components.GetReference(components.ComponentPacketCapture, reg, path, prefix, is)
	if err != nil {
		errMsg = append(errMsg, err.Error())
	}

	if pc.installation.CertificateManagement != nil {
		pc.csrInitImage, err = ResolveCSRInitImage(pc.installation, is)
		if err != nil {
			errMsg = append(errMsg, err.Error())
		}
	}

	if len(errMsg) != 0 {
		return fmt.Errorf(strings.Join(errMsg, ","))
	}

	return nil
}

func (pc *packetCaptureApiComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (pc *packetCaptureApiComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		createNamespace(PacketCaptureNamespace, pc.installation.KubernetesProvider),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(PacketCaptureNamespace, pc.pullSecrets...)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(PacketCaptureNamespace, pc.serverCertSecret)...)...)

	objs = append(objs,
		pc.serviceAccount(),
		pc.clusterRole(),
		pc.clusterRoleBinding(),
		pc.deployment(),
		pc.service(),
	)

	if pc.keyValidatorConfig != nil {
		objs = append(objs, secret.ToRuntimeObjects(pc.keyValidatorConfig.RequiredSecrets(PacketCaptureNamespace)...)...)
		objs = append(objs, configmap.ToRuntimeObjects(pc.keyValidatorConfig.RequiredConfigMaps(PacketCaptureNamespace)...)...)
	}

	if pc.installation.CertificateManagement != nil {
		objs = append(objs, CsrClusterRoleBinding(PacketCaptureServiceName, PacketCaptureNamespace))
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
					TargetPort: intstr.FromInt(8444),
				},
			},
		},
	}
}

func (pc *packetCaptureApiComponent) serviceAccount() client.Object {
	return &v1.ServiceAccount{
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
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authenticationreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get"},
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
			Replicas: &replicas,
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
					NodeSelector:       pc.installation.ControlPlaneNodeSelector,
					ServiceAccountName: PacketCaptureServiceAccountName,
					Tolerations:        append(pc.installation.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly),
					ImagePullSecrets:   secret.GetReferenceList(pc.pullSecrets),
					InitContainers:     pc.initContainers(),
					Containers:         []corev1.Container{pc.container()},
					Volumes:            pc.volumes(),
				},
			},
		},
	}
}

func (pc *packetCaptureApiComponent) initContainers() []v1.Container {
	var initContainers []corev1.Container
	if pc.installation.CertificateManagement != nil {
		initContainers = append(initContainers, CreateCSRInitContainer(
			pc.installation.CertificateManagement,
			pc.csrInitImage,
			PacketCaptureCertSecret,
			PacketCaptureServiceName,
			APIServerSecretKeyName,
			APIServerSecretCertName,
			dns.GetServiceDNSNames(PacketCaptureServiceName, PacketCaptureNamespace, pc.clusterDomain),
			PacketCaptureNamespace))
	}
	return initContainers
}

func (pc *packetCaptureApiComponent) container() corev1.Container {
	var volumeMounts = []corev1.VolumeMount{{
		Name:      PacketCaptureCertSecret,
		MountPath: "/certs/https",
		ReadOnly:  true,
	}}
	env := []v1.EnvVar{
		{Name: "PACKETCAPTURE_API_LOG_LEVEL", Value: "Info"},
	}

	if pc.keyValidatorConfig != nil {
		env = append(env, pc.keyValidatorConfig.RequiredEnv("PACKETCAPTURE_API_")...)
		volumeMounts = append(volumeMounts, pc.keyValidatorConfig.RequiredVolumeMounts()...)
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

func (pc *packetCaptureApiComponent) healthProbe() *v1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/health",
				Port:   intstr.FromInt(8444),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

func (pc *packetCaptureApiComponent) volumes() []corev1.Volume {
	var volumes = []corev1.Volume{{
		Name:         PacketCaptureCertSecret,
		VolumeSource: certificateVolumeSource(pc.installation.CertificateManagement, PacketCaptureCertSecret),
	}}

	if pc.keyValidatorConfig != nil {
		volumes = append(volumes, pc.keyValidatorConfig.RequiredVolumes()...)
	}

	return volumes
}

func (pc *packetCaptureApiComponent) annotations() map[string]string {
	var annotations = map[string]string{
		PacketCaptureTLSHashAnnotation: rmeta.AnnotationHash(pc.serverCertSecret.Data),
	}

	return annotations
}
