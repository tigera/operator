// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	CSIDriverName                = "csi.tigera.io"
	CSITolerationControlPlaneKey = "node-role.kubernetes.io/control-plane"
	CSITolerationMasterKey       = "node-role.kubernetes.io/master"
	CSITolerationOperator        = "Exists"
	CSIDaemonSetName             = "csi-node-driver"
	CSIDaemonSetNamespace        = "calico-system"
	CSIContainerName             = "calico-csi"
	CSIRegistrarContainerName    = "csi-node-driver-registrar"
)

type CSIConfiguration struct {
	Installation *operatorv1.InstallationSpec
	Terminating  bool
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
	operator := corev1.TolerationOperator(CSITolerationOperator)
	tolerations := []corev1.Toleration{
		corev1.Toleration{
			Key:      CSITolerationControlPlaneKey,
			Operator: operator,
			Effect:   corev1.TaintEffectNoSchedule,
		},
		corev1.Toleration{
			Key:      CSITolerationMasterKey,
			Operator: operator,
			Effect:   corev1.TaintEffectNoSchedule,
		},
	}
	return tolerations
}

func (c *csiComponent) csiContainers() []corev1.Container {
	mountPropagation := corev1.MountPropagationBidirectional
	csiContainer := corev1.Container{
		Name:            CSIContainerName,
		Image:           c.csiImage,
		ImagePullPolicy: corev1.PullAlways,
		Args: []string{
			"--nodeid=$(KUBE_NODE_NAME)",
			"--loglevel=$(LOG_LEVEL)",
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(true),
		},
		Env: []corev1.EnvVar{
			corev1.EnvVar{
				Name:  "LOG_LEVEL",
				Value: "warn",
			},
			corev1.EnvVar{
				Name: "KUBE_NODE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName"},
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			corev1.VolumeMount{
				Name:      "varrun",
				MountPath: "/var/run",
			},
			corev1.VolumeMount{
				Name:      "etccalico",
				MountPath: "/etc/calico",
			},
			corev1.VolumeMount{
				Name:      "socket-dir",
				MountPath: "/csi",
			},
			corev1.VolumeMount{
				Name:             "kubelet-dir",
				MountPath:        c.cfg.Installation.VolumePlugin.KubeletDir,
				MountPropagation: &mountPropagation,
			},
		},
	}

	// Construct "csi-node-driver-registrar" container
	registrarContainer := corev1.Container{
		Name:            CSIRegistrarContainerName,
		Image:           c.csiRegistrarImage,
		ImagePullPolicy: corev1.PullAlways,
		Args: []string{
			"--v=5",
			"--csi-address=$(ADDRESS)",
			"--kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)",
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(true),
		},
		Env: []corev1.EnvVar{
			corev1.EnvVar{
				Name:  "ADDRESS",
				Value: "/csi/csi.sock",
			},
			corev1.EnvVar{
				Name:  "DRIVER_REG_SOCK_PATH",
				Value: "/csi/csi.sock",
			},
			corev1.EnvVar{
				Name: "KUBE_NODE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			corev1.VolumeMount{
				Name:      "socket-dir",
				MountPath: "/csi",
			},
			corev1.VolumeMount{
				Name:      "registration-dir",
				MountPath: "/registration",
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
		corev1.Volume{
			Name: "varrun",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run",
				},
			},
		},
		corev1.Volume{
			Name: "etccalico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/etc/calico",
				},
			},
		},
		corev1.Volume{
			Name: "kubelet-dir",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: c.cfg.Installation.VolumePlugin.KubeletDir,
					Type: &hostPathTypeDir,
				},
			},
		},
		corev1.Volume{
			Name: "socket-dir",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: c.cfg.Installation.VolumePlugin.SockDir,
					Type: &hostPathTypeDirOrCreate,
				},
			},
		},
		corev1.Volume{
			Name: "registration-dir",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: c.cfg.Installation.VolumePlugin.RegistrationDir,
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
		Tolerations: c.csiTolerations(),
		Containers:  c.csiContainers(),
		Volumes:     c.csiVolumes(),
	}
	return corev1.PodTemplateSpec{
		ObjectMeta: templateMeta,
		Spec:       templateSpec,
	}
}

// csiDaemonset creates the daemonset necessary to enable the CSI driver
func (c *csiComponent) csiDaemonset() *appsv1.DaemonSet {
	dsLabels := map[string]string{
		"app.kubernetes.io/name": CSIDaemonSetName,
	}
	dsMeta := metav1.ObjectMeta{
		Name:      CSIDaemonSetName,
		Namespace: CSIDaemonSetNamespace,
		Labels:    dsLabels,
	}

	typeMeta := metav1.TypeMeta{
		Kind:       "DaemonSet",
		APIVersion: "apps/v1",
	}

	selector := &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"name": CSIDaemonSetName,
		},
	}

	dsSpec := appsv1.DaemonSetSpec{
		Selector: selector,
		Template: c.csiTemplate(),
	}

	return &appsv1.DaemonSet{
		TypeMeta:   typeMeta,
		ObjectMeta: dsMeta,
		Spec:       dsSpec,
	}
}

func (c *csiComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.csiImage, err = components.GetReference(components.ComponentCalicoCSI, reg, path, prefix, is)
	if err != nil {
		return err
	}

	c.csiRegistrarImage, err = components.GetReference(components.ComponentCalicoCSIRegistrar, reg, path, prefix, is)

	return err
}

func (c *csiComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	objs := []client.Object{}

	objs = append(objs, c.csiDriver())
	objs = append(objs, c.csiDaemonset())

	if c.cfg.Terminating || !c.cfg.Installation.VolumePlugin.Enable {
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
