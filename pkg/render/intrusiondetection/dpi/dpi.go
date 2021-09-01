// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package dpi

import (
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/configmap"
	"github.com/tigera/operator/pkg/render/common/meta"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DeepPacketInspectionNamespace = "tigera-dpi"
	DeepPacketInspectionName      = "tigera-dpi"
	DefaultMemoryLimitDPI         = "1Gi"
	DefaultMemoryRequestDPI       = "100Mi"
	DefaultCPULimitDPI            = "1"
	DefaultCPURequestDPI          = "100m"
)

func DPI(
	ids *operatorv1.IntrusionDetection,
	installation *operatorv1.InstallationSpec,
	nodeTLSSecret *corev1.Secret,
	typhaTLSSecret *corev1.Secret,
	typhaCAConfigMap *corev1.ConfigMap,
	pullSecrets []*corev1.Secret,
	openshift bool,
	hasNoLicense bool,
) render.Component {
	return &dpi{
		ids:              ids,
		installation:     installation,
		nodeTLSSecret:    nodeTLSSecret,
		typhaTLSSecret:   typhaTLSSecret,
		typhaCAConfigMap: typhaCAConfigMap,
		pullSecrets:      pullSecrets,
		openshift:        openshift,
		hasNoLicense:     hasNoLicense,
	}
}

type dpi struct {
	ids              *operatorv1.IntrusionDetection
	installation     *operatorv1.InstallationSpec
	nodeTLSSecret    *corev1.Secret
	typhaTLSSecret   *corev1.Secret
	typhaCAConfigMap *corev1.ConfigMap
	pullSecrets      []*corev1.Secret
	openshift        bool
	hasNoLicense     bool
	dpiImage         string
}

func (d *dpi) ResolveImages(is *operatorv1.ImageSet) error {
	reg := d.installation.Registry
	path := d.installation.ImagePath
	prefix := d.installation.ImagePrefix
	var err error
	d.dpiImage, err = components.GetReference(components.ComponentDeepPacketInspection, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return nil
}

func (d *dpi) Objects() (objsToCreate, objsToDelete []client.Object) {
	var toDelete []client.Object
	var toCreate []client.Object
	// Add DeepPacketInspection related objects if all necessary bit of TLS config are set.
	addDPIDaemonSet := d.nodeTLSSecret != nil && d.typhaTLSSecret != nil && d.typhaCAConfigMap != nil

	// toCreate is populated only if DPI daemonset needs to be created and there is valid license,
	// for all other combinations delete the DPI namespace.
	if addDPIDaemonSet && !d.hasNoLicense {
		// Update the IDS resource with the default values for DPI ComponentResources if it doesn't exist,
		// these values are used for setting container resource requirements in DPI daemonset.
		d.defaultIntrusionDetectionComponentResources()
		toCreate = append(toCreate, d.ids)

		toCreate = append(toCreate, render.CreateNamespace(DeepPacketInspectionNamespace, d.installation.KubernetesProvider))
		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, d.nodeTLSSecret)...)...)
		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, d.typhaTLSSecret)...)...)
		toCreate = append(toCreate, configmap.ToRuntimeObjects(configmap.CopyToNamespace(DeepPacketInspectionNamespace, d.typhaCAConfigMap)...)...)
		toCreate = append(toCreate,
			d.dpiServiceAccount(),
			d.dpiClusterRole(),
			d.dpiClusterRoleBinding(),
			d.dpiDaemonset(),
		)
		return toCreate, nil
	}

	toDelete = append(toDelete, d.dpiNamespace())
	return nil, toDelete
}

func (d *dpi) Ready() bool {
	return true
}

func (d *dpi) SupportedOSType() meta.OSType {
	return rmeta.OSTypeLinux
}

// defaultIntrusionDetectionComponentResources sets the default requirements value for DPI in IDS resource if it is not set.
func (d *dpi) defaultIntrusionDetectionComponentResources() {
	if d.ids.Spec.ComponentResources == nil {
		d.ids.Spec.ComponentResources = []operatorv1.IntrusionDetectionComponentResource{
			{
				ComponentName: operatorv1.ComponentNameDeepPacketInspection,
				ResourceRequirements: &corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse(DefaultMemoryLimitDPI),
						corev1.ResourceCPU:    resource.MustParse(DefaultCPULimitDPI),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse(DefaultMemoryRequestDPI),
						corev1.ResourceCPU:    resource.MustParse(DefaultCPURequestDPI),
					},
				},
			},
		}
	}
}

func (d *dpi) dpiDaemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: DeepPacketInspectionNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": DeepPacketInspectionName}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": DeepPacketInspectionName,
					},
					Annotations: d.dpiAnnotations(),
				},
				Spec: corev1.PodSpec{
					Tolerations:                   rmeta.TolerateAll,
					ImagePullSecrets:              secret.GetReferenceList(d.pullSecrets),
					ServiceAccountName:            DeepPacketInspectionName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					Containers:                    []corev1.Container{d.dpiContainer()},
					Volumes:                       d.dpiVolumes(),
				},
			},
		},
	}
}

func (d *dpi) dpiContainer() corev1.Container {
	privileged := false
	// On OpenShift Snort needs privileged access to access host network
	if d.openshift {
		privileged = true
	}

	return corev1.Container{
		Name:         DeepPacketInspectionName,
		Image:        d.dpiImage,
		Resources:    *d.ids.Spec.ComponentResources[0].ResourceRequirements,
		Env:          d.dpiEnvVars(),
		VolumeMounts: d.dpiVolumeMounts(),
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		ReadinessProbe: d.dpiReadinessProbes(),
	}
}

func (d *dpi) dpiVolumes() []corev1.Volume {
	var defaultMode int32 = 420

	return []corev1.Volume{
		{
			Name: "typha-ca",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaCAConfigMapName,
					},
				},
			},
		},
		{
			Name: "node-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  render.NodeTLSSecretName,
					DefaultMode: &defaultMode,
				},
			},
		},
	}
}

func (d *dpi) dpiEnvVars() []corev1.EnvVar {
	var cnEnv corev1.EnvVar
	if d.installation.CertificateManagement != nil {
		cnEnv = corev1.EnvVar{
			Name: "DPI_TYPHACN", Value: render.TyphaCommonName,
		}
	} else {
		cnEnv = corev1.EnvVar{
			Name: "DPI_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: ptr.BoolToPtr(true),
				},
			},
		}
	}

	return []corev1.EnvVar{
		{
			Name: "NODENAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{Name: "DPI_TYPHAK8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "DPI_TYPHAK8SSERVICENAME", Value: render.TyphaServiceName},
		{Name: "DPI_TYPHACAFILE", Value: "/typha-ca/caBundle"},
		{Name: "DPI_TYPHACERTFILE", Value: fmt.Sprintf("/node-certs/%s", render.TLSSecretCertName)},
		{Name: "DPI_TYPHAKEYFILE", Value: fmt.Sprintf("/node-certs/%s", render.TLSSecretKeyName)},
		// We need at least the CN or URISAN set, we depend on the validation
		// done by the core_controller that the Secret will have one.
		cnEnv,
		{Name: "DPI_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: render.TyphaTLSSecretName,
				},
				Key:      render.URISAN,
				Optional: ptr.BoolToPtr(true),
			},
		}},
	}
}

func (d *dpi) dpiVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
		{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
	}
}

func (d *dpi) dpiReadinessProbes() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Host:   "localhost",
				Path:   "/readiness",
				Port:   intstr.FromInt(9097),
				Scheme: corev1.URISchemeHTTP,
			},
		},
		TimeoutSeconds:      10,
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

func (d *dpi) dpiServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: DeepPacketInspectionNamespace,
		},
	}
}

func (d *dpi) dpiClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   DeepPacketInspectionName,
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     DeepPacketInspectionName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      DeepPacketInspectionName,
				Namespace: DeepPacketInspectionNamespace,
			},
		},
	}
}

func (d *dpi) dpiClusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DeepPacketInspectionName,
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"deeppacketinspections",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Used to update the DPI resource status
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"deeppacketinspections/status",
				},
				Verbs: []string{"update"},
			},
			{
				// Used to discover Typha endpoints and service IPs for advertisement.
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
		},
	}
	if d.installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{DeepPacketInspectionName},
		})
	}
	return role
}

func (d *dpi) dpiNamespace() *corev1.Namespace {
	return &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DeepPacketInspectionNamespace,
		},
	}
}

func (d *dpi) dpiAnnotations() map[string]string {
	return map[string]string{
		render.TyphaCAHashAnnotation:   rmeta.AnnotationHash(d.typhaCAConfigMap.Data),
		render.NodeCertHashAnnotation:  rmeta.AnnotationHash(d.nodeTLSSecret.Data),
		render.TyphaCertHashAnnotation: rmeta.AnnotationHash(d.typhaTLSSecret.Data),
	}
}
