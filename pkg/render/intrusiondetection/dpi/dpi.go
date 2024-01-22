// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
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
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

const (
	DeepPacketInspectionNamespace       = "tigera-dpi"
	DeepPacketInspectionName            = "tigera-dpi"
	DeepPacketInspectionPolicyName      = networkpolicy.TigeraComponentPolicyPrefix + DeepPacketInspectionName
	DefaultMemoryLimit                  = "1Gi"
	DefaultMemoryRequest                = "100Mi"
	DefaultCPULimit                     = "1"
	DefaultCPURequest                   = "100m"
	DeepPacketInspectionLinseedRBACName = "tigera-dpi-linseed-permissions"
)

type DPIConfig struct {
	IntrusionDetection *operatorv1.IntrusionDetection
	Installation       *operatorv1.InstallationSpec
	TyphaNodeTLS       *render.TyphaNodeTLS
	PullSecrets        []*corev1.Secret
	Openshift          bool
	ManagedCluster     bool
	ManagementCluster  bool
	HasNoLicense       bool
	HasNoDPIResource   bool
	ClusterDomain      string
	DPICertSecret      certificatemanagement.KeyPairInterface
	Namespace          string
	BindNamespaces     []string
	Tenant             *operatorv1.Tenant
}

func DPI(cfg *DPIConfig) render.Component {
	return &dpiComponent{cfg: cfg}
}

type dpiComponent struct {
	cfg      *DPIConfig
	dpiImage string
}

func (c *dpiComponent) ResolveImages(is *operatorv1.ImageSet) error {
	var err error
	c.dpiImage, err = components.GetReference(
		components.ComponentDeepPacketInspection,
		c.cfg.Installation.Registry,
		c.cfg.Installation.ImagePath,
		c.cfg.Installation.ImagePrefix,
		is)
	if err != nil {
		return err
	}
	return nil
}

func (c *dpiComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	var toCreate, toDelete []client.Object

	if !c.cfg.Tenant.MultiTenant() {
		// In multi-tenant management clusters, namespace management is external to the operator. So skip this logic.
		if c.cfg.HasNoLicense {
			toDelete = append(toDelete, render.CreateNamespace(c.cfg.Namespace, c.cfg.Installation.KubernetesProvider, render.PSSPrivileged))
		} else {
			toCreate = append(toCreate, render.CreateNamespace(c.cfg.Namespace, c.cfg.Installation.KubernetesProvider, render.PSSPrivileged))
		}

		// This secret is deprecated in this namespace and should be removed in upgrade scenarios
		toDelete = append(toDelete, &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: c.cfg.Namespace},
		})
	}

	if c.cfg.HasNoDPIResource || c.cfg.HasNoLicense {
		toDelete = append(toDelete, c.dpiAllowTigeraPolicy())
		toDelete = append(toDelete, secret.ToRuntimeObjects(secret.CopyToNamespace(c.cfg.Namespace, c.cfg.PullSecrets...)...)...)
		toDelete = append(toDelete,
			c.dpiServiceAccount(),
			c.dpiClusterRole(),
			c.dpiClusterRoleBinding(),
			c.dpiDaemonset(),
		)
	} else {
		toCreate = append(toCreate, c.dpiAllowTigeraPolicy())
		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(c.cfg.Namespace, c.cfg.PullSecrets...)...)...)
		toCreate = append(toCreate,
			c.dpiServiceAccount(),
			c.dpiClusterRole(),
			c.dpiClusterRoleBinding(),
			c.dpiDaemonset(),
		)
	}

	if c.cfg.ManagementCluster {
		// We always want to create these permissions when a management
		// cluster is configured, to allow any DPI running inside a
		// managed cluster to write data
		toCreate = append(toCreate, c.dpiLinseedAccessClusterRole())
		toCreate = append(toCreate, c.dpiLinseedAccessClusterRoleBinding())
	} else if !c.cfg.ManagedCluster && !c.cfg.HasNoDPIResource && !c.cfg.HasNoLicense {
		// We want to create these permissions when a standalone
		// cluster is configured to run DPI
		toCreate = append(toCreate, c.dpiLinseedAccessClusterRole())
		toCreate = append(toCreate, c.dpiLinseedAccessClusterRoleBinding())
	} else {
		// We want to remove these permissions when a standalone
		// cluster is no longer configured, to run DPI or for managed clusters
		toDelete = append(toDelete,
			c.dpiLinseedAccessClusterRole(),
			c.dpiLinseedAccessClusterRoleBinding(),
		)
	}

	if c.cfg.ManagedCluster {
		// For managed clusters, we must create a role binding to allow Linseed to
		// manage access token secrets in our namespace.
		toCreate = append(toCreate, c.externalLinseedRoleBinding())
	} else {
		// We can delete the role binding for management and standalone clusters, since
		// for these cluster types normal serviceaccount tokens are used.
		toDelete = append(toDelete, c.externalLinseedRoleBinding())
	}

	return toCreate, toDelete
}

func (c *dpiComponent) Ready() bool {
	return true
}

func (c *dpiComponent) SupportedOSType() meta.OSType {
	return meta.OSTypeLinux
}

func (c *dpiComponent) dpiDaemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0
	var initContainers []corev1.Container
	if c.cfg.TyphaNodeTLS.NodeSecret.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TyphaNodeTLS.NodeSecret.InitContainer(c.cfg.Namespace))
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: c.dpiAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:                   meta.TolerateAll,
			ImagePullSecrets:              secret.GetReferenceList(c.cfg.PullSecrets),
			ServiceAccountName:            DeepPacketInspectionName,
			TerminationGracePeriodSeconds: &terminationGracePeriod,
			HostNetwork:                   true,
			// Adjust DNS policy so we can access in-cluster services.
			DNSPolicy:      corev1.DNSClusterFirstWithHostNet,
			InitContainers: initContainers,
			Containers:     []corev1.Container{c.dpiContainer()},
			Volumes:        c.dpiVolumes(),
		},
	}
	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: *podTemplate,
		},
	}
}

func (c *dpiComponent) dpiContainer() corev1.Container {
	sc := securitycontext.NewRootContext(c.cfg.Openshift)
	sc.Capabilities.Add = []corev1.Capability{
		"NET_ADMIN",
		"NET_RAW",
	}
	dpiContainer := corev1.Container{
		Name:            DeepPacketInspectionName,
		Image:           c.dpiImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Resources:       *c.cfg.IntrusionDetection.Spec.ComponentResources[0].ResourceRequirements,
		Env:             c.dpiEnvVars(),
		VolumeMounts:    c.dpiVolumeMounts(),
		// On OpenShift Snort needs privileged access to access host network
		SecurityContext: sc,
		ReadinessProbe:  c.dpiReadinessProbes(),
	}

	return dpiContainer
}

func (c *dpiComponent) dpiVolumes() []corev1.Volume {
	dirOrCreate := corev1.HostPathDirectoryOrCreate

	volumes := []corev1.Volume{
		c.cfg.DPICertSecret.Volume(),
		c.cfg.TyphaNodeTLS.TrustedBundle.Volume(),
		c.cfg.TyphaNodeTLS.NodeSecret.Volume(),
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

	if c.cfg.ManagedCluster {
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

func (c *dpiComponent) dpiEnvVars() []corev1.EnvVar {
	env := []corev1.EnvVar{
		{
			Name: "DPI_NODENAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{Name: "DPI_TYPHAK8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "DPI_TYPHAK8SSERVICENAME", Value: render.TyphaServiceName},
		{Name: "DPI_TYPHACAFILE", Value: c.cfg.TyphaNodeTLS.TrustedBundle.MountPath()},
		{Name: "DPI_TYPHACERTFILE", Value: c.cfg.TyphaNodeTLS.NodeSecret.VolumeMountCertificateFilePath()},
		{Name: "DPI_TYPHAKEYFILE", Value: c.cfg.TyphaNodeTLS.NodeSecret.VolumeMountKeyFilePath()},
		{Name: "LINSEED_CLIENT_CERT", Value: c.cfg.DPICertSecret.VolumeMountCertificateFilePath()},
		{Name: "LINSEED_CLIENT_KEY", Value: c.cfg.DPICertSecret.VolumeMountKeyFilePath()},
		{Name: "LINSEED_TOKEN", Value: render.GetLinseedTokenPath(c.cfg.ManagedCluster)},
		{Name: "FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode)},
	}

	// We need at least the CN or URISAN set, we depend on the validation
	// done by the core_controller that the Secret will have one.
	if c.cfg.TyphaNodeTLS.TyphaCommonName != "" {
		env = append(env, corev1.EnvVar{Name: "DPI_TYPHACN", Value: c.cfg.TyphaNodeTLS.TyphaCommonName})
	}
	if c.cfg.TyphaNodeTLS.TyphaURISAN != "" {
		env = append(env, corev1.EnvVar{Name: "DPI_TYPHAURISAN", Value: c.cfg.TyphaNodeTLS.TyphaURISAN})
	}
	return env
}

func (c *dpiComponent) dpiVolumeMounts() []corev1.VolumeMount {
	volumeMounts := append(
		c.cfg.TyphaNodeTLS.TrustedBundle.VolumeMounts(c.SupportedOSType()),
		c.cfg.TyphaNodeTLS.NodeSecret.VolumeMount(c.SupportedOSType()),
		corev1.VolumeMount{MountPath: "/var/log/calico/snort-alerts", Name: "log-snort-alters"},
		c.cfg.DPICertSecret.VolumeMount(c.SupportedOSType()),
	)
	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      render.LinseedTokenVolumeName,
				MountPath: render.LinseedVolumeMountPath,
			})
	}
	return volumeMounts
}

func (c *dpiComponent) dpiReadinessProbes() *corev1.Probe {
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
	}
}

func (c *dpiComponent) dpiServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: c.cfg.Namespace,
		},
	}
}

func (c *dpiComponent) dpiClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(DeepPacketInspectionName, DeepPacketInspectionName, DeepPacketInspectionName, c.cfg.BindNamespaces)
}

func (c *dpiComponent) dpiLinseedAccessClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return rcomponents.ClusterRoleBinding(DeepPacketInspectionLinseedRBACName, DeepPacketInspectionLinseedRBACName, DeepPacketInspectionName, c.cfg.BindNamespaces)
}

func (c *dpiComponent) dpiClusterRole() *rbacv1.ClusterRole {
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
	if c.cfg.Installation.KubernetesProvider != operatorv1.ProviderOpenShift {
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

func (c *dpiComponent) dpiLinseedAccessClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DeepPacketInspectionLinseedRBACName,
		},

		Rules: []rbacv1.PolicyRule{
			{
				// Add write access to Linseed APIs.
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"events"},
				Verbs:     []string{"create"},
			},
		},
	}
}

func (c *dpiComponent) dpiAnnotations() map[string]string {
	if c.cfg.HasNoDPIResource || c.cfg.HasNoLicense {
		return nil
	}
	annotations := c.cfg.TyphaNodeTLS.TrustedBundle.HashAnnotations()
	annotations[c.cfg.TyphaNodeTLS.NodeSecret.HashAnnotationKey()] = c.cfg.TyphaNodeTLS.NodeSecret.HashAnnotationValue()
	annotations[c.cfg.DPICertSecret.HashAnnotationKey()] = c.cfg.DPICertSecret.HashAnnotationValue()
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
			Namespace: c.cfg.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.TigeraLinseedSecretsClusterRole,
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
func (c *dpiComponent) dpiAllowTigeraPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
	}
	egressRules = networkpolicy.AppendServiceSelectorDNSEgressRules(egressRules, c.cfg.Openshift)

	if c.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.GuardianServiceSelectorEntityRule,
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace).LinseedServiceSelectorEntityRule(),
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionPolicyName,
			Namespace: c.cfg.Namespace,
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
