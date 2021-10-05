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

package applicationlayer

import (
	"fmt"
	"strconv"
	"strings"

	ocsv1 "github.com/openshift/api/security/v1"

	rbacv1 "k8s.io/api/rbac/v1"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"

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
	L7LogCollectorDeamonsetName = "l7-log-collector"
	L7CollectorContainerName    = "l7-collector"
	ProxyContainerName          = "envoy-proxy"
	EnvoyLogsVolumeName         = "envoy-logs"
	EnvoyConfigMapName          = "envoy-config"
	EnvoyConfigMapKey           = "envoy-config.yaml"
	APLName                     = "application-layer"
)

var log = logf.Log.WithName("applicationlayer")

func ApplicationLayer(
	pullSecrets []*corev1.Secret,
	installation *operatorv1.InstallationSpec,
	osType rmeta.OSType,
	logsEnabled bool,
	logIntervalSeconds *int64,
	logRequestsPerInterval *int64,
) render.Component {

	return &applicationLayerComponent{
		pullSecrets:            pullSecrets,
		installation:           installation,
		osType:                 osType,
		logsEnabled:            logsEnabled,
		logIntervalSeconds:     logIntervalSeconds,
		logRequestsPerInterval: logRequestsPerInterval,
	}
}

type applicationLayerComponent struct {
	pullSecrets            []*corev1.Secret
	installation           *operatorv1.InstallationSpec
	osType                 rmeta.OSType
	proxyImage             string
	collectorImage         string
	envoyConfigMap         *corev1.ConfigMap
	logsEnabled            bool
	logRequestsPerInterval *int64
	logIntervalSeconds     *int64
}

func (c *applicationLayerComponent) ResolveImages(is *operatorv1.ImageSet) error {
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

func (c *applicationLayerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *applicationLayerComponent) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object
	// TODO: ensure that namespace exists before proceeding

	// if l7spec is provided render the required objects
	if c.logsEnabled {
		c.envoyConfigMap = c.envoyL7ConfigMap()
		objs = append(objs, c.serviceAccount())
		objs = append(objs, c.envoyConfigMap)
		objs = append(objs, c.daemonset())
	}

	if c.installation.KubernetesProvider == operatorv1.ProviderDockerEE {
		objs = append(objs, c.clusterAdminClusterRoleBinding())
	}

	// If we're running on openshift, we need to add in an SCC.
	if c.installation.KubernetesProvider == operatorv1.ProviderOpenShift {
		objs = append(objs, c.securityContextConstraints())
	}

	return objs, nil
}

func (c *applicationLayerComponent) Ready() bool {
	return true
}

// daemonset creates a daemonset for the L7 log collector component.
func (c *applicationLayerComponent) daemonset() *appsv1.DaemonSet {
	maxUnavailable := intstr.FromInt(1)

	annots := map[string]string{}

	if c.envoyConfigMap != nil {
		annots[EnvoyConfigMapName] = rmeta.AnnotationHash(c.envoyConfigMap)
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"k8s-app": L7LogCollectorDeamonsetName,
			},
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			HostIPC:            true,
			HostNetwork:        true,
			ServiceAccountName: APLName,
			DNSPolicy:          corev1.DNSClusterFirstWithHostNet,
			NodeSelector:       map[string]string{},
			Tolerations:        c.tolerations(),
			ImagePullSecrets:   secret.GetReferenceList(c.pullSecrets),
			Containers:         c.containers(),
			Volumes:            c.volumes(),
		},
	}

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      L7LogCollectorDeamonsetName,
			Namespace: common.CalicoNamespace,
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

func (c *applicationLayerComponent) containers() []corev1.Container {

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

func (c *applicationLayerComponent) proxyEnv() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "ENVOY_UID", Value: "0"},
		{Name: "ENVOY_GID", Value: "0"},
	}

	return envs
}

func (c *applicationLayerComponent) collectorEnv() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "Info"},
		{Name: "FELIX_DIAL_TARGET", Value: "/var/run/felix/nodeagent/socket"},
	}

	// set rate limiters if provided
	if c.logRequestsPerInterval != nil {
		envs = append(envs, corev1.EnvVar{
			Name:  "ENVOY_LOG_REQUESTS_PER_INTERVAL",
			Value: strconv.FormatInt(*c.logRequestsPerInterval, 10),
		})
	}

	if c.logIntervalSeconds != nil {
		envs = append(envs, corev1.EnvVar{
			Name:  "ENVOY_LOG_INTERVAL_SECONDS",
			Value: strconv.FormatInt(*c.logIntervalSeconds, 10),
		})
	}

	return envs
}

// tolerations creates the node's toleration.
func (c *applicationLayerComponent) tolerations() []corev1.Toleration {
	// ensures that l7 log collector pods are scheduled on master node as well
	toleration := []corev1.Toleration{
		{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	}

	return toleration
}

func (c *applicationLayerComponent) volumes() []corev1.Volume {

	var volumes []corev1.Volume

	// this empty directory volume will be mounted at /tmp/ which will contain the access logs file generated by envoy
	volumes = append(volumes, corev1.Volume{
		Name: EnvoyLogsVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})

	volumes = append(volumes, corev1.Volume{
		Name: EnvoyConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: EnvoyConfigMapName},
			},
		},
	})

	return volumes
}

func (c *applicationLayerComponent) proxyVolMounts() []corev1.VolumeMount {

	volumes := []corev1.VolumeMount{
		{Name: EnvoyConfigMapName, MountPath: "/etc/envoy"},
		{Name: EnvoyLogsVolumeName, MountPath: "/tmp/"},
	}

	return volumes
}

func (c *applicationLayerComponent) collectorVolMounts() []corev1.VolumeMount {

	volumes := []corev1.VolumeMount{
		{Name: EnvoyLogsVolumeName, MountPath: "/tmp/"},
	}

	return volumes
}

func (c *applicationLayerComponent) envoyL7ConfigMap() *corev1.ConfigMap {
	config, err := statik.GetStatikFile("/envoy-config.yaml")

	if err != nil || config == "" {
		log.Error(err, "Failed to get envoy-config.yaml file")

		return nil
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EnvoyConfigMapName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			EnvoyConfigMapKey: config,
		},
	}
}

// aplServiceAccount creates application layer service account.
func (c *applicationLayerComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APLName, Namespace: common.CalicoNamespace},
	}
}

// in DockerEE (Mirantis) cluster-admin role is needed for envoy proxy to be able to use hostNetwork
func (c *applicationLayerComponent) clusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "application-layer-cluster-admin",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APLName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
	return crb
}

func (c *applicationLayerComponent) securityContextConstraints() *ocsv1.SecurityContextConstraints {
	privilegeEscalation := false
	return &ocsv1.SecurityContextConstraints{
		TypeMeta:                 metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
		ObjectMeta:               metav1.ObjectMeta{Name: common.CalicoNamespace},
		AllowHostDirVolumePlugin: false,
		AllowHostIPC:             true,
		AllowHostNetwork:         true,
		AllowHostPID:             false,
		AllowHostPorts:           false,
		AllowPrivilegeEscalation: &privilegeEscalation,
		AllowPrivilegedContainer: false,
		FSGroup:                  ocsv1.FSGroupStrategyOptions{Type: ocsv1.FSGroupStrategyRunAsAny},
		RunAsUser:                ocsv1.RunAsUserStrategyOptions{Type: ocsv1.RunAsUserStrategyRunAsAny},
		ReadOnlyRootFilesystem:   true,
		SELinuxContext:           ocsv1.SELinuxContextStrategyOptions{Type: ocsv1.SELinuxStrategyMustRunAs},
		SupplementalGroups:       ocsv1.SupplementalGroupsStrategyOptions{Type: ocsv1.SupplementalGroupsStrategyRunAsAny},
		Users:                    []string{fmt.Sprintf("system:serviceaccount:%s:%s", common.CalicoNamespace, APLName)},
		Volumes:                  []ocsv1.FSType{"*"},
	}
}
