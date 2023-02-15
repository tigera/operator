// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.
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
	"path/filepath"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

const (
	CSIDriverName             = "csi.tigera.io"
	CSIDaemonSetName          = "csi-node-driver"
	CSIDaemonSetNamespace     = "calico-system"
	CSIContainerName          = "calico-csi"
	CSIRegistrarContainerName = "csi-node-driver-registrar"
)

type CSIConfiguration struct {
	Installation *operatorv1.InstallationSpec
	Terminating  bool
	Openshift    bool
	UsePSP       bool
}

type csiComponent struct {
	cfg *CSIConfiguration

	csiImage          string
	csiRegistrarImage string
}

func CSI(cfg *CSIConfiguration) Component {
	return &csiComponent{
		cfg: cfg,
	}
}

func (c *csiComponent) csiDriver() *v1.CSIDriver {
	meta := metav1.ObjectMeta{
		Name: CSIDriverName,
	}

	typeMeta := metav1.TypeMeta{
		Kind:       "CSIDriver",
		APIVersion: "storage/v1",
	}

	volumeLifecycleModes := []v1.VolumeLifecycleMode{
		v1.VolumeLifecycleEphemeral,
	}
	spec := v1.CSIDriverSpec{
		PodInfoOnMount:       ptr.BoolToPtr(true),
		VolumeLifecycleModes: volumeLifecycleModes,
	}

	return &v1.CSIDriver{
		TypeMeta:   typeMeta,
		ObjectMeta: meta,
		Spec:       spec,
	}
}

func (c *csiComponent) csiTolerations() []corev1.Toleration {
	return rmeta.TolerateAll
}

func (c *csiComponent) csiContainers() []corev1.Container {
	mountPropagation := corev1.MountPropagationBidirectional
	csiContainer := corev1.Container{
		Name:            CSIContainerName,
		Image:           c.csiImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args: []string{
			"--nodeid=$(KUBE_NODE_NAME)",
			"--loglevel=$(LOG_LEVEL)",
		},
		Env: []corev1.EnvVar{
			{
				Name:  "LOG_LEVEL",
				Value: "warn",
			},
			{
				Name: "KUBE_NODE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName"},
				},
			},
		},
		SecurityContext: securitycontext.NewRootContext(true),
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "varrun",
				MountPath: filepath.Clean("/var/run"),
			},
			{
				Name:      "etccalico",
				MountPath: filepath.Clean("/etc/calico"),
			},
			{
				Name:      "socket-dir",
				MountPath: filepath.Clean("/csi"),
			},
			{
				Name:             "kubelet-dir",
				MountPath:        c.cfg.Installation.KubeletVolumePluginPath,
				MountPropagation: &mountPropagation,
			},
		},
	}

	// Construct "csi-node-driver-registrar" container
	registrarContainer := corev1.Container{
		Name:            CSIRegistrarContainerName,
		Image:           c.csiRegistrarImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args: []string{
			"--v=5",
			"--csi-address=$(ADDRESS)",
			"--kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)",
		},
		Env: []corev1.EnvVar{
			{
				Name:  "ADDRESS",
				Value: filepath.Clean("/csi/csi.sock"),
			},
			{
				Name: "DRIVER_REG_SOCK_PATH",
				// This path cannot also reference "/csi" because /csi only exists inside of the pod, but this path
				// is used by the kubelet on the host node to issue CSI operations
				Value: filepath.Join(c.cfg.Installation.KubeletVolumePluginPath, "plugins/csi.tigera.io/csi.sock"),
			},
			{
				Name: "KUBE_NODE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
				},
			},
		},
		SecurityContext: securitycontext.NewRootContext(true),
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "socket-dir",
				MountPath: filepath.Clean("/csi"),
			},
			{
				Name:      "registration-dir",
				MountPath: filepath.Clean("/registration"),
			},
		},
	}

	return []corev1.Container{
		csiContainer,
		registrarContainer,
	}
}

func (c *csiComponent) csiVolumes() []corev1.Volume {
	hostPathTypeDir := corev1.HostPathDirectory
	hostPathTypeDirOrCreate := corev1.HostPathDirectoryOrCreate
	return []corev1.Volume{
		{
			Name: "varrun",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: filepath.Clean("/var/run"),
				},
			},
		},
		{
			Name: "etccalico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: filepath.Clean("/etc/calico"),
				},
			},
		},
		{
			Name: "kubelet-dir",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: c.cfg.Installation.KubeletVolumePluginPath,
					Type: &hostPathTypeDir,
				},
			},
		},
		{
			Name: "socket-dir",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: filepath.Join(c.cfg.Installation.KubeletVolumePluginPath, "plugins/csi.tigera.io"),
					Type: &hostPathTypeDirOrCreate,
				},
			},
		},
		{
			Name: "registration-dir",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: filepath.Join(c.cfg.Installation.KubeletVolumePluginPath, "plugins_registry"),
					Type: &hostPathTypeDir,
				},
			},
		},
	}
}

func (c *csiComponent) csiTemplate() corev1.PodTemplateSpec {
	templateLabels := map[string]string{
		"name": CSIDaemonSetName,
	}
	templateMeta := metav1.ObjectMeta{
		Labels: templateLabels,
	}
	templateSpec := corev1.PodSpec{
		Tolerations:      c.csiTolerations(),
		Containers:       c.csiContainers(),
		ImagePullSecrets: c.cfg.Installation.ImagePullSecrets,
		Volumes:          c.csiVolumes(),
	}

	if !c.cfg.Openshift && c.cfg.UsePSP {
		templateSpec.ServiceAccountName = CSIDaemonSetName
	}

	return corev1.PodTemplateSpec{
		ObjectMeta: templateMeta,
		Spec:       templateSpec,
	}
}

// csiDaemonset creates the daemonset necessary to enable the CSI driver
func (c *csiComponent) csiDaemonset() *appsv1.DaemonSet {
	dsMeta := metav1.ObjectMeta{
		Name:      CSIDaemonSetName,
		Namespace: CSIDaemonSetNamespace,
	}

	typeMeta := metav1.TypeMeta{
		Kind:       "DaemonSet",
		APIVersion: "apps/v1",
	}

	dsSpec := appsv1.DaemonSetSpec{
		Template: c.csiTemplate(),
	}

	setNodeCriticalPod(&(dsSpec.Template))

	ds := appsv1.DaemonSet{
		TypeMeta:   typeMeta,
		ObjectMeta: dsMeta,
		Spec:       dsSpec,
	}

	if overrides := c.cfg.Installation.CSINodeDriverDaemonSet; overrides != nil {
		rcomp.ApplyDaemonSetOverrides(&ds, overrides)
	}

	return &ds
}

func (c *csiComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CSIDaemonSetName,
			Namespace: CSIDaemonSetNamespace,
		},
	}
}

// podSecurityPolicy sets up a PodSecurityPolicy for CSI Driver to allow usage of privileged
// securityContext and hostPath volume.
func (c *csiComponent) podSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(CSIDaemonSetName)
	psp.Spec.Privileged = true
	psp.Spec.AllowPrivilegeEscalation = ptr.BoolToPtr(true)
	psp.Spec.Volumes = append(psp.Spec.Volumes, policyv1beta1.HostPath)
	psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny

	return psp
}

func (c *csiComponent) role() *rbacv1.Role {
	policyRules := []rbacv1.PolicyRule{}

	// Allow access to the pod security policy in case this is enforced on the cluster
	if !c.cfg.Openshift && c.cfg.UsePSP {
		policyRules = append(policyRules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{CSIDaemonSetName},
		})
	}

	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CSIDaemonSetName,
			Namespace: CSIDaemonSetNamespace,
		},
		Rules: policyRules,
	}
}

func (c *csiComponent) roleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CSIDaemonSetName,
			Namespace: CSIDaemonSetNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     CSIDaemonSetName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      CSIDaemonSetName,
				Namespace: CSIDaemonSetNamespace,
			},
		},
	}
}

func (c *csiComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.csiImage, err = components.GetReference(components.ComponentCSIPrivate, reg, path, prefix, is)
		if err != nil {
			return err
		}

		c.csiRegistrarImage, err = components.GetReference(components.ComponentCSINodeDriverRegistrarPrivate, reg, path, prefix, is)
	} else {
		c.csiImage, err = components.GetReference(components.ComponentCalicoCSI, reg, path, prefix, is)
		if err != nil {
			return err
		}

		c.csiRegistrarImage, err = components.GetReference(components.ComponentCalicoCSIRegistrar, reg, path, prefix, is)
	}

	return err
}

func (c *csiComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	objs := []client.Object{}

	objs = append(objs, c.csiDriver())
	objs = append(objs, c.csiDaemonset())

	// create PSP and corresponding clusterrole if it allows, clusterroles are currently
	// only for attaching the PSP to CSI's DaemonSet, do not render them if the PSPs
	// are also not rendered
	if !c.cfg.Openshift && c.cfg.UsePSP {
		objs = append(objs,
			c.serviceAccount(),
			c.podSecurityPolicy(),
			c.role(),
			c.roleBinding(),
		)
	}

	if c.cfg.Terminating || c.cfg.Installation.KubeletVolumePluginPath == "None" {
		objsToDelete = objs
	} else {
		objsToCreate = objs
	}

	return objsToCreate, objsToDelete
}

func (c *csiComponent) Ready() bool {
	return true
}

func (c *csiComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
