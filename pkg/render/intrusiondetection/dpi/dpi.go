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
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/meta"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DeepPacketInspectionNamespace = "tigera-dpi"
	DeepPacketInspectionName      = "tigera-dpi"
	DefaultMemoryLimit            = "1Gi"
	DefaultMemoryRequest          = "100Mi"
	DefaultCPULimit               = "1"
	DefaultCPURequest             = "100m"
)

type DPIConfig struct {
	IntrusionDetection *operatorv1.IntrusionDetection
	Installation       *operatorv1.InstallationSpec
	NodeTLSSecret      *corev1.Secret
	TyphaTLSSecret     *corev1.Secret
	TyphaCAConfigMap   *corev1.ConfigMap
	PullSecrets        []*corev1.Secret
	Openshift          bool
	HasNoLicense       bool
	HasNoDPIResource   bool
	ESSecrets          []*corev1.Secret
	ESClusterConfig    *relasticsearch.ClusterConfig
	ClusterDomain      string
}

func DPI(cfg *DPIConfig) render.Component {
	return &dpiComponent{cfg: cfg}
}

type dpiComponent struct {
	cfg      *DPIConfig
	dpiImage string
}

func (d *dpiComponent) ResolveImages(is *operatorv1.ImageSet) error {
	var err error
	d.dpiImage, err = components.GetReference(
		components.ComponentDeepPacketInspection,
		d.cfg.Installation.Registry,
		d.cfg.Installation.ImagePath,
		d.cfg.Installation.ImagePrefix,
		is)
	if err != nil {
		return err
	}
	return nil
}

func (d *dpiComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	var commonObjs []client.Object

	nsObj := []client.Object{render.CreateNamespace(DeepPacketInspectionNamespace, d.cfg.Installation.KubernetesProvider)}

	if d.cfg.HasNoDPIResource || d.cfg.HasNoLicense {
		// create empty secrets and configMap when resource needs to be deleted.
		commonObjs = append(commonObjs, &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: render.NodeTLSSecretName, Namespace: DeepPacketInspectionNamespace}})
		commonObjs = append(commonObjs, &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: render.TyphaTLSSecretName, Namespace: DeepPacketInspectionNamespace}})
		commonObjs = append(commonObjs, &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: DeepPacketInspectionNamespace}})
		commonObjs = append(commonObjs, &corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: render.TyphaCAConfigMapName, Namespace: DeepPacketInspectionNamespace}})
	} else {
		commonObjs = append(commonObjs, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, d.cfg.NodeTLSSecret)...)...)
		commonObjs = append(commonObjs, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, d.cfg.TyphaTLSSecret)...)...)
		commonObjs = append(commonObjs, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, d.cfg.ESSecrets...)...)...)
		commonObjs = append(commonObjs, configmap.ToRuntimeObjects(configmap.CopyToNamespace(DeepPacketInspectionNamespace, d.cfg.TyphaCAConfigMap)...)...)
	}

	commonObjs = append(commonObjs, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, d.cfg.PullSecrets...)...)...)
	commonObjs = append(commonObjs,
		d.dpiServiceAccount(),
		d.dpiClusterRole(),
		d.dpiClusterRoleBinding(),
		d.dpiDaemonset(),
	)

	if d.cfg.HasNoLicense {
		return nil, append(nsObj, commonObjs...)
	}
	if d.cfg.HasNoDPIResource {
		return nsObj, commonObjs
	}
	return append(nsObj, commonObjs...), nil
}

func (d *dpiComponent) Ready() bool {
	return true
}

func (d *dpiComponent) SupportedOSType() meta.OSType {
	return rmeta.OSTypeLinux
}

func (d *dpiComponent) dpiDaemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0

	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"k8s-app": DeepPacketInspectionName,
			},
			Annotations: d.dpiAnnotations(),
		},
		Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
			Tolerations:                   rmeta.TolerateAll,
			ImagePullSecrets:              secret.GetReferenceList(d.cfg.PullSecrets),
			ServiceAccountName:            DeepPacketInspectionName,
			TerminationGracePeriodSeconds: &terminationGracePeriod,
			HostNetwork:                   true,
			// Adjust DNS policy so we can access in-cluster services.
			DNSPolicy:  corev1.DNSClusterFirstWithHostNet,
			Containers: []corev1.Container{d.dpiContainer()},
			Volumes:    d.dpiVolumes(),
		}),
	}, d.cfg.ESClusterConfig, d.cfg.ESSecrets).(*corev1.PodTemplateSpec)
	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: DeepPacketInspectionNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": DeepPacketInspectionName}},
			Template: *podTemplate,
		},
	}
}

func (d *dpiComponent) dpiContainer() corev1.Container {
	privileged := false
	// On OpenShift Snort needs privileged access to access host network
	if d.cfg.Openshift {
		privileged = true
	}

	dpiContainer := corev1.Container{
		Name:         DeepPacketInspectionName,
		Image:        d.dpiImage,
		Resources:    *d.cfg.IntrusionDetection.Spec.ComponentResources[0].ResourceRequirements,
		Env:          d.dpiEnvVars(),
		VolumeMounts: d.dpiVolumeMounts(),
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		ReadinessProbe: d.dpiReadinessProbes(),
	}

	return relasticsearch.ContainerDecorateIndexCreator(
		relasticsearch.ContainerDecorate(dpiContainer, d.cfg.ESClusterConfig.ClusterName(),
			render.ElasticsearchIntrusionDetectionUserSecret, d.cfg.ClusterDomain, rmeta.OSTypeLinux),
		d.cfg.ESClusterConfig.Replicas(), d.cfg.ESClusterConfig.Shards())
}

func (d *dpiComponent) dpiVolumes() []corev1.Volume {
	var defaultMode int32 = 420
	dirOrCreate := corev1.HostPathDirectoryOrCreate

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
		{
			Name: "log-snort-alters",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/snort-alerts",
					Type: &dirOrCreate,
				},
			},
		},
	}
}

func (d *dpiComponent) dpiEnvVars() []corev1.EnvVar {
	var cnEnv corev1.EnvVar
	if d.cfg.Installation.CertificateManagement != nil {
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
			Name: "DPI_NODENAME",
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

func (d *dpiComponent) dpiVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
		{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
		{MountPath: "/var/log/calico/snort-alerts", Name: "log-snort-alters"},
	}
}

func (d *dpiComponent) dpiReadinessProbes() *corev1.Probe {
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

func (d *dpiComponent) dpiServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: DeepPacketInspectionNamespace,
		},
	}
}

func (d *dpiComponent) dpiClusterRoleBinding() *rbacv1.ClusterRoleBinding {
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

func (d *dpiComponent) dpiClusterRole() *rbacv1.ClusterRole {
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
	if d.cfg.Installation.KubernetesProvider != operatorv1.ProviderOpenShift {
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

func (d *dpiComponent) dpiNamespace() *corev1.Namespace {
	return &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DeepPacketInspectionNamespace,
		},
	}
}

func (d *dpiComponent) dpiAnnotations() map[string]string {
	if d.cfg.HasNoDPIResource || d.cfg.HasNoLicense {
		return nil
	}
	return map[string]string{
		render.TyphaCAHashAnnotation:   rmeta.AnnotationHash(d.cfg.TyphaCAConfigMap.Data),
		render.NodeCertHashAnnotation:  rmeta.AnnotationHash(d.cfg.NodeTLSSecret.Data),
		render.TyphaCertHashAnnotation: rmeta.AnnotationHash(d.cfg.TyphaTLSSecret.Data),
	}
}
