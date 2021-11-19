// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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

// The names of the components related to the Guardian related rendered objects.
const (
	GuardianName                   = "tigera-guardian"
	GuardianNamespace              = GuardianName
	GuardianServiceAccountName     = GuardianName
	GuardianClusterRoleName        = GuardianName
	GuardianClusterRoleBindingName = GuardianName
	GuardianDeploymentName         = GuardianName
	GuardianServiceName            = "tigera-guardian"
	GuardianVolumeName             = "tigera-guardian-certs"
	GuardianSecretName             = "tigera-managed-cluster-connection"
)

func Guardian(cfg *GuardianConfiguration) Component {
	return &GuardianComponent{
		cfg: cfg,
	}
}

// GuardianConfiguration contains all the config information needed to render the component.
type GuardianConfiguration struct {
	URL                  string
	PullSecrets          []*corev1.Secret
	Openshift            bool
	Installation         *operatorv1.InstallationSpec
	TunnelSecret         *corev1.Secret
	PacketCaptureSecret  *corev1.Secret
	PrometheusCertSecret *corev1.Secret
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
		CreateNamespace(GuardianNamespace, c.cfg.Installation.KubernetesProvider),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(GuardianNamespace, c.cfg.PullSecrets...)...)...)
	objs = append(objs,
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.deployment(),
		c.service(),
		secret.CopyToNamespace(GuardianNamespace, c.cfg.TunnelSecret)[0],
		secret.CopyToNamespace(GuardianNamespace, c.cfg.PacketCaptureSecret)[0],
		// Add tigera-manager service account for impersonation
		CreateNamespace(ManagerNamespace, c.cfg.Installation.KubernetesProvider),
		managerServiceAccount(),
		managerClusterRole(false, true, c.cfg.Openshift),
		managerClusterRoleBinding(),
	)
	if c.cfg.PrometheusCertSecret != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(GuardianNamespace, c.cfg.PrometheusCertSecret)...)...)
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

func (c *GuardianComponent) serviceAccount() client.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianServiceAccountName, Namespace: GuardianNamespace},
	}
}

func (c *GuardianComponent) clusterRole() client.Object {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				// Guardian forwards its token when sending the request to other services
				// PacketCapture will authenticate the token from the request and check if impersonation is allowed
				// AuthenticationReview API can authenticate a bearer token from the request if the token can create
				// authenticationreviews
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"authenticationreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

func (c *GuardianComponent) clusterRoleBinding() client.Object {
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

func (c *GuardianComponent) deployment() client.Object {
	var replicas int32 = 1

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianDeploymentName,
			Namespace: GuardianNamespace,
			Labels: map[string]string{
				"k8s-app": GuardianName,
			},
			Annotations: c.annotations(),
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": GuardianName,
				},
			},
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      GuardianDeploymentName,
					Namespace: ManagerNamespace,
					Labels: map[string]string{
						"k8s-app": GuardianName,
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: GuardianServiceAccountName,
					Tolerations:        append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly),
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         c.container(),
					Volumes:            c.volumes(),
				},
			},
		},
	}
}

func (c *GuardianComponent) volumes() []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: GuardianVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: GuardianSecretName,
				},
			},
		},
		{
			Name: PacketCaptureCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					Items: []corev1.KeyToPath{{
						Key:  "tls.crt",
						Path: "tls.crt",
					}},
					SecretName: PacketCaptureCertSecret,
				},
			},
		},
	}
	if c.cfg.PrometheusCertSecret != nil {
		volumes = append(volumes, corev1.Volume{
			Name: PrometheusTLSSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{

					SecretName: PrometheusTLSSecretName,
				},
			},
		})
	}
	return volumes
}

func (c *GuardianComponent) container() []corev1.Container {
	return []corev1.Container{
		{
			Name:  GuardianDeploymentName,
			Image: c.image,
			Env: []corev1.EnvVar{
				{Name: "GUARDIAN_PORT", Value: "9443"},
				{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
				{Name: "GUARDIAN_VOLTRON_URL", Value: c.cfg.URL},
			},
			VolumeMounts: c.volumeMounts(),
			LivenessProbe: &corev1.Probe{
				Handler: corev1.Handler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 90,
				PeriodSeconds:       10,
			},
			ReadinessProbe: &corev1.Probe{
				Handler: corev1.Handler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/health",
						Port: intstr.FromInt(9080),
					},
				},
				InitialDelaySeconds: 10,
				PeriodSeconds:       5,
			},
			SecurityContext: podsecuritycontext.NewBaseContext(),
		},
	}
}

func (c *GuardianComponent) volumeMounts() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{
			Name:      GuardianVolumeName,
			MountPath: "/certs/",
			ReadOnly:  true,
		},
		{
			Name:      PacketCaptureCertSecret,
			MountPath: "/certs/packetcapture",
			ReadOnly:  true,
		},
	}
	if c.cfg.PrometheusCertSecret != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: PrometheusTLSSecretName, MountPath: "/certs/prometheus", ReadOnly: true})
	}

	return mounts
}

func (c *GuardianComponent) annotations() map[string]string {
	var annotations = make(map[string]string)

	annotations[PacketCaptureTLSHashAnnotation] = rmeta.AnnotationHash(c.cfg.PacketCaptureSecret.Data)

	if c.cfg.PrometheusCertSecret != nil {
		annotations[prometheusTLSHashAnnotation] = rmeta.AnnotationHash(c.cfg.PrometheusCertSecret.Data)
	}
	return annotations
}
