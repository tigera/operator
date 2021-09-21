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

func Guardian(
	url string,
	pullSecrets []*corev1.Secret,
	openshift bool,
	installation *operatorv1.InstallationSpec,
	tunnelSecret *corev1.Secret,
	packetCaptureSecret *corev1.Secret,
) Component {
	return &GuardianComponent{
		url:                 url,
		pullSecrets:         pullSecrets,
		openshift:           openshift,
		installation:        installation,
		tunnelSecret:        tunnelSecret,
		packetCaptureSecret: packetCaptureSecret,
	}
}

type GuardianComponent struct {
	url                 string
	pullSecrets         []*corev1.Secret
	openshift           bool
	installation        *operatorv1.InstallationSpec
	tunnelSecret        *corev1.Secret
	packetCaptureSecret *corev1.Secret
	image               string
}

func (c *GuardianComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.installation.Registry
	path := c.installation.ImagePath
	prefix := c.installation.ImagePrefix
	var err error
	c.image, err = components.GetReference(components.ComponentGuardian, reg, path, prefix, is)
	return err
}

func (c *GuardianComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *GuardianComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		CreateNamespace(GuardianNamespace, c.installation.KubernetesProvider),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(GuardianNamespace, c.pullSecrets...)...)...)
	objs = append(objs,
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.deployment(),
		c.service(),
		secret.CopyToNamespace(GuardianNamespace, c.tunnelSecret)[0],
		secret.CopyToNamespace(GuardianNamespace, c.packetCaptureSecret)[0],
		// Add tigera-manager service account for impersonation
		CreateNamespace(ManagerNamespace, c.installation.KubernetesProvider),
		managerServiceAccount(),
		managerClusterRole(false, true, c.openshift),
		managerClusterRoleBinding(),
	)

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
					NodeSelector:       c.installation.ControlPlaneNodeSelector,
					ServiceAccountName: GuardianServiceAccountName,
					Tolerations:        append(c.installation.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly),
					ImagePullSecrets:   secret.GetReferenceList(c.pullSecrets),
					Containers:         c.container(),
					Volumes:            c.volumes(),
				},
			},
		},
	}
}

func (c *GuardianComponent) volumes() []corev1.Volume {
	return []corev1.Volume{
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
}

func (c *GuardianComponent) container() []corev1.Container {
	return []corev1.Container{
		{
			Name:  GuardianDeploymentName,
			Image: c.image,
			Env: []corev1.EnvVar{
				{Name: "GUARDIAN_PORT", Value: "9443"},
				{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
				{Name: "GUARDIAN_VOLTRON_URL", Value: c.url},
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
	return []corev1.VolumeMount{
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
}

func (c *GuardianComponent) annotations() map[string]string {
	var annotations = make(map[string]string)

	annotations[PacketCaptureTLSHashAnnotation] = rmeta.AnnotationHash(c.packetCaptureSecret.Data)

	return annotations
}
