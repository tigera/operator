// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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

	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

const (
	DeepPacketInspectionNamespace  = "tigera-dpi"
	DeepPacketInspectionName       = "tigera-dpi"
	DeepPacketInspectionPolicyName = networkpolicy.TigeraComponentPolicyPrefix + DeepPacketInspectionName
	DefaultMemoryLimit             = "1Gi"
	DefaultMemoryRequest           = "100Mi"
	DefaultCPULimit                = "1"
	DefaultCPURequest              = "100m"
)

var DPISourceEntityRule = networkpolicy.CreateSourceEntityRule(DeepPacketInspectionNamespace, DeepPacketInspectionName)

type DPIConfig struct {
	IntrusionDetection *operatorv1.IntrusionDetection
	Installation       *operatorv1.InstallationSpec
	TyphaNodeTLS       *render.TyphaNodeTLS
	PullSecrets        []*corev1.Secret
	Openshift          bool
	ManagedCluster     bool
	HasNoLicense       bool
	HasNoDPIResource   bool
	ESClusterConfig    *relasticsearch.ClusterConfig
	ClusterDomain      string
	DPICertSecret      certificatemanagement.KeyPairInterface
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
	var toCreate, toDelete []client.Object
	if d.cfg.HasNoLicense {
		toDelete = append(toDelete, render.CreateNamespace(DeepPacketInspectionNamespace, d.cfg.Installation.KubernetesProvider, render.PSSPrivileged))
	} else {
		toCreate = append(toCreate, render.CreateNamespace(DeepPacketInspectionNamespace, d.cfg.Installation.KubernetesProvider, render.PSSPrivileged))
	}
	if d.cfg.HasNoDPIResource || d.cfg.HasNoLicense {
		toDelete = append(toDelete, d.dpiAllowTigeraPolicy())
		toDelete = append(toDelete, &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: DeepPacketInspectionNamespace},
		})
		toDelete = append(toDelete, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, d.cfg.PullSecrets...)...)...)
		toDelete = append(toDelete,
			d.dpiServiceAccount(),
			d.dpiClusterRole(),
			d.dpiClusterRoleBinding(),
			d.dpiDaemonset(),
		)
	} else {
		toCreate = append(toCreate, d.dpiAllowTigeraPolicy())
		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace)...)...)
		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, d.cfg.PullSecrets...)...)...)
		toCreate = append(toCreate,
			d.dpiServiceAccount(),
			d.dpiClusterRole(),
			d.dpiClusterRoleBinding(),
			d.dpiDaemonset(),
		)
	}
	if d.cfg.ManagedCluster {
		// For managed clusters, we must create a role binding to allow Linseed to
		// manage access token secrets in our namespace.
		toCreate = append(toCreate, d.externalLinseedRoleBinding())
	} else {
		// We can delete the role binding for management and standalone clusters, since
		// for these cluster types normal serviceaccount tokens are used.
		toDelete = append(toDelete, d.externalLinseedRoleBinding())
	}

	return toCreate, toDelete
}

func (d *dpiComponent) Ready() bool {
	return true
}

func (d *dpiComponent) SupportedOSType() meta.OSType {
	return meta.OSTypeLinux
}

func (d *dpiComponent) dpiDaemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0
	var initContainers []corev1.Container
	if d.cfg.TyphaNodeTLS.NodeSecret.UseCertificateManagement() {
		initContainers = append(initContainers, d.cfg.TyphaNodeTLS.NodeSecret.InitContainer(DeepPacketInspectionNamespace))
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: d.dpiAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:                   meta.TolerateAll,
			ImagePullSecrets:              secret.GetReferenceList(d.cfg.PullSecrets),
			ServiceAccountName:            DeepPacketInspectionName,
			TerminationGracePeriodSeconds: &terminationGracePeriod,
			HostNetwork:                   true,
			// Adjust DNS policy so we can access in-cluster services.
			DNSPolicy:      corev1.DNSClusterFirstWithHostNet,
			InitContainers: initContainers,
			Containers:     []corev1.Container{d.dpiContainer()},
			Volumes:        d.dpiVolumes(),
		},
	}
	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: DeepPacketInspectionNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: *podTemplate,
		},
	}
}

func (d *dpiComponent) dpiContainer() corev1.Container {
	sc := securitycontext.NewRootContext(d.cfg.Openshift)
	sc.Capabilities.Add = []corev1.Capability{
		"NET_ADMIN",
		"NET_RAW",
	}
	dpiContainer := corev1.Container{
		Name:         DeepPacketInspectionName,
		Image:        d.dpiImage,
		Resources:    *d.cfg.IntrusionDetection.Spec.ComponentResources[0].ResourceRequirements,
		Env:          d.dpiEnvVars(),
		VolumeMounts: d.dpiVolumeMounts(),
		// On OpenShift Snort needs privileged access to access host network
		SecurityContext: sc,
		ReadinessProbe:  d.dpiReadinessProbes(),
	}

	return dpiContainer
}

func (d *dpiComponent) dpiVolumes() []corev1.Volume {
	dirOrCreate := corev1.HostPathDirectoryOrCreate

	volumes := []corev1.Volume{
		d.cfg.DPICertSecret.Volume(),
		d.cfg.TyphaNodeTLS.TrustedBundle.Volume(),
		d.cfg.TyphaNodeTLS.NodeSecret.Volume(),
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

	if d.cfg.ManagedCluster {
		volumes = append(volumes,
			corev1.Volume{
				Name: render.LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(render.LinseedTokenSecret, DeepPacketInspectionName),
						Items:      []corev1.KeyToPath{{Key: render.LinseedTokenKey, Path: render.LinseedTokenSubPath}},
					},
				},
			})
	}

	return volumes
}

func (d *dpiComponent) dpiEnvVars() []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			Name: "DPI_NODENAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{Name: "DPI_TYPHAK8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "DPI_TYPHAK8SSERVICENAME", Value: render.TyphaServiceName},
		{Name: "DPI_TYPHACAFILE", Value: d.cfg.TyphaNodeTLS.TrustedBundle.MountPath()},
		{Name: "DPI_TYPHACERTFILE", Value: d.cfg.TyphaNodeTLS.NodeSecret.VolumeMountCertificateFilePath()},
		{Name: "DPI_TYPHAKEYFILE", Value: d.cfg.TyphaNodeTLS.NodeSecret.VolumeMountKeyFilePath()},
		{Name: "CLUSTER_NAME", Value: d.cfg.ESClusterConfig.ClusterName()},
		{Name: "LINSEED_CLIENT_CERT", Value: d.cfg.DPICertSecret.VolumeMountCertificateFilePath()},
		{Name: "LINSEED_CLIENT_KEY", Value: d.cfg.DPICertSecret.VolumeMountKeyFilePath()},
		{Name: "LINSEED_TOKEN", Value: render.GetLinseedTokenPath(d.cfg.ManagedCluster)},
		{Name: "FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(d.cfg.Installation.FIPSMode)},
	}

	// We need at least the CN or URISAN set, we depend on the validation
	// done by the core_controller that the Secret will have one.
	if d.cfg.TyphaNodeTLS.TyphaCommonName != "" {
		env = append(env, corev1.EnvVar{Name: "DPI_TYPHACN", Value: d.cfg.TyphaNodeTLS.TyphaCommonName})
	}
	if d.cfg.TyphaNodeTLS.TyphaURISAN != "" {
		env = append(env, corev1.EnvVar{Name: "DPI_TYPHAURISAN", Value: d.cfg.TyphaNodeTLS.TyphaURISAN})
	}
	return env
}

func (d *dpiComponent) dpiVolumeMounts() []corev1.VolumeMount {
	volumeMounts := append(
		d.cfg.TyphaNodeTLS.TrustedBundle.VolumeMounts(d.SupportedOSType()),
		d.cfg.TyphaNodeTLS.NodeSecret.VolumeMount(d.SupportedOSType()),
		corev1.VolumeMount{MountPath: "/var/log/calico/snort-alerts", Name: "log-snort-alters"},
		d.cfg.DPICertSecret.VolumeMount(d.SupportedOSType()),
	)
	if d.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      render.LinseedTokenVolumeName,
				MountPath: render.LinseedVolumeMountPath,
			})
	}
	return volumeMounts
}

func (d *dpiComponent) dpiReadinessProbes() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
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
			{
				// Add write access to Linseed APIs.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"events"},
				Verbs:     []string{"create"},
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

func (d *dpiComponent) dpiAnnotations() map[string]string {
	if d.cfg.HasNoDPIResource || d.cfg.HasNoLicense {
		return nil
	}
	annotations := d.cfg.TyphaNodeTLS.TrustedBundle.HashAnnotations()
	annotations[d.cfg.TyphaNodeTLS.NodeSecret.HashAnnotationKey()] = d.cfg.TyphaNodeTLS.NodeSecret.HashAnnotationValue()
	annotations[d.cfg.DPICertSecret.HashAnnotationKey()] = d.cfg.DPICertSecret.HashAnnotationValue()
	return annotations
}

func (c *dpiComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	// For managed clusters, we must create a role binding to allow Linseed to manage access token secrets
	// in our namespace.
	linseed := "tigera-linseed"
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      linseed,
			Namespace: DeepPacketInspectionNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     linseed,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      linseed,
				Namespace: render.ElasticsearchNamespace,
			},
		},
	}
}

// This policy uses service selectors.
func (d *dpiComponent) dpiAllowTigeraPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
	}
	egressRules = networkpolicy.AppendServiceSelectorDNSEgressRules(egressRules, d.cfg.Openshift)

	if d.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.GuardianServiceSelectorEntityRule,
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.LinseedServiceSelectorEntityRule,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionPolicyName,
			Namespace: DeepPacketInspectionNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(DeepPacketInspectionName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}
