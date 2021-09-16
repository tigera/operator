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

package render

import (
	"fmt"
	"strings"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ptr"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/statik"
)

const (
	CalicoSystemNamespace       = "calico-system"
	EnvoyConfigConfigMapName    = "envoy-config"
	L7LogCollectorDeamonsetName = "l7-log-collector"
	L7CollectorContainerName    = "l7-collector"
	ProxyContainerName          = "envoy-proxy"
	EnvoyLogsKey                = "envoy-logs"
	EnvoyConfigKey              = "envoy-config"
	EnvoyConfigMapKey           = "envoy-config.yaml"
)

func ApplicationLayer(pullSecrets []*corev1.Secret, installation *operatorv1.InstallationSpec, osType rmeta.OSType,
	applicationLayer *operatorv1.ApplicationLayer) Component {

	return &ApplicationLayerComponent{
		pullSecrets:      pullSecrets,
		installation:     installation,
		osType:           osType,
		applicationLayer: applicationLayer,
	}
}

type ApplicationLayerComponent struct {
	pullSecrets      []*corev1.Secret
	installation     *operatorv1.InstallationSpec
	osType           rmeta.OSType
	applicationLayer *operatorv1.ApplicationLayer
	proxyImage       string
	collectorImage   string
}

func (c *ApplicationLayerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.installation.Registry
	path := c.installation.ImagePath
	prefix := c.installation.ImagePrefix

	if c.osType != c.SupportedOSType() {
		return fmt.Errorf("l7 log collection is supported only on %s", c.SupportedOSType())
	}

	var err error
	var errMsgs []string

	c.proxyImage, err = components.GetReference(components.ComponentEnvoyProxy, reg, path, prefix, is)

	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	c.collectorImage, err = components.GetReference(components.ComponentL7Collector, reg, path, prefix, is)

	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}

	return nil
}

func (c *ApplicationLayerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *ApplicationLayerComponent) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object
	// TODO: ensure that namespace exists before proceeding
	objs = append(objs, c.envoyL7ConfigMap())
	objs = append(objs, c.daemonset())

	return objs, nil
}

func (c *ApplicationLayerComponent) Ready() bool {
	return true
}

// daemonset creates a daemonset for the L7 log collector component.
func (c *ApplicationLayerComponent) daemonset() *appsv1.DaemonSet {
	maxUnavailable := intstr.FromInt(1)

	annots := map[string]string{}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"k8s-app": L7LogCollectorDeamonsetName,
			},
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			HostIPC:          true,
			HostNetwork:      true,
			DNSPolicy:        corev1.DNSClusterFirstWithHostNet,
			NodeSelector:     map[string]string{},
			Tolerations:      c.tolerations(),
			ImagePullSecrets: secret.GetReferenceList(c.pullSecrets),
			Containers:       c.containers(),
			Volumes:          c.volumes(),
		},
	}

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      L7LogCollectorDeamonsetName,
			Namespace: CalicoSystemNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": L7LogCollectorDeamonsetName}},
			Template: *podTemplate,
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}

	return ds
}

func (c *ApplicationLayerComponent) containers() []corev1.Container {

	var containers []corev1.Container

	proxy := corev1.Container{
		Name:  ProxyContainerName,
		Image: c.proxyImage,
		Command: []string{
			"envoy", "-c", "/etc/envoy/envoy-config.yaml",
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(false),
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"},
			},
			RunAsUser:  ptr.Int64ToPtr(0),
			RunAsGroup: ptr.Int64ToPtr(0),
		},
		Env:          c.proxyEnv(),
		VolumeMounts: c.proxyVolMounts(),
	}
	containers = append(containers, proxy)

	collector := corev1.Container{
		Name:         L7CollectorContainerName,
		Image:        c.collectorImage,
		Env:          c.collectorEnv(),
		VolumeMounts: c.collectorVolMounts(),
	}
	containers = append(containers, collector)

	return containers
}

func (c *ApplicationLayerComponent) proxyEnv() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "ENVOY_UID", Value: "0"},
		{Name: "ENVOY_GID", Value: "0"},
	}

	return envs
}

func (c *ApplicationLayerComponent) collectorEnv() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "Info"},
		{Name: "FELIX_DIAL_TARGET", Value: "/var/run/felix/nodeagent/socket"},
	}

	return envs
}

// tolerations creates the node's toleration.
func (c *ApplicationLayerComponent) tolerations() []corev1.Toleration {
	// ensures that l7 log collector pods are scheduled on master node as well
	toleration := []corev1.Toleration{
		{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	}

	return toleration
}

func (c *ApplicationLayerComponent) volumes() []corev1.Volume {

	var volumes []corev1.Volume

	volumes = append(volumes, corev1.Volume{
		Name: EnvoyLogsKey,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})

	volumes = append(volumes, corev1.Volume{
		Name: EnvoyConfigKey,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: EnvoyConfigKey},
			},
		},
	})

	return volumes
}

func (c *ApplicationLayerComponent) proxyVolMounts() []corev1.VolumeMount {

	volumes := []corev1.VolumeMount{
		{Name: EnvoyConfigKey, MountPath: "/etc/envoy"},
		{Name: EnvoyLogsKey, MountPath: "/tmp/"},
	}

	return volumes
}

func (c *ApplicationLayerComponent) collectorVolMounts() []corev1.VolumeMount {

	volumes := []corev1.VolumeMount{
		{Name: EnvoyLogsKey, MountPath: "/tmp/"},
	}

	return volumes
}

func (c *ApplicationLayerComponent) envoyL7ConfigMap() *corev1.ConfigMap {
	config, err := statik.GetStatikFile("/envoy-config.yaml")

	if err != nil || config == "" {
		log.Error(err, "Failed to get envoy-config.yaml file")
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EnvoyConfigKey,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			EnvoyConfigMapKey: config,
		},
	}
}
