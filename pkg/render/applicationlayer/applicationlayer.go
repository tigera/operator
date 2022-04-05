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

//go:generate go run gen.go

package applicationlayer

import (
	"bytes"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	ocsv1 "github.com/openshift/api/security/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
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
	APLName                          = "application-layer"
	ApplicationLayerDaemonsetName    = "l7-log-collector"
	L7CollectorContainerName         = "l7-collector"
	ProxyContainerName               = "envoy-proxy"
	EnvoyLogsVolumeName              = "envoy-logs"
	EnvoyConfigMapName               = "envoy-config"
	EnvoyConfigMapKey                = "envoy-config.yaml"
	FelixSync                        = "felix-sync"
	DikastesSyncVolumeName           = "dikastes-sync"
	DikastesContainerName            = "dikastes"
	ModSecurityRulesetVolumeName     = "modsecurity-ruleset"
	ModSecurityRulesetConfigMapName  = "modsecurity-ruleset"
	ModSecurityRulesetHashAnnotation = "hash.operator.tigera.io/modsecurity-ruleset"
	CalicoLogsVolumeName             = "var-log-calico"
)

func ApplicationLayer(
	config *Config,
) render.Component {
	return &component{
		config: config,
	}
}

type component struct {
	config *Config
}

// Config contains all the config information ApplicationLayer needs to render component.
type Config struct {
	// Required config.
	PullSecrets  []*corev1.Secret
	Installation *operatorv1.InstallationSpec
	OsType       rmeta.OSType

	// Optional config for WAF.
	WAFEnabled           bool
	ModSecurityConfigMap *corev1.ConfigMap

	// Optional config for L7 logs.
	LogsEnabled            bool
	LogRequestsPerInterval *int64
	LogIntervalSeconds     *int64

	// Calculated internal fields.
	proxyImage     string
	collectorImage string
	dikastesImage  string
	envoyConfigMap *corev1.ConfigMap
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.config.Installation.Registry
	path := c.config.Installation.ImagePath
	prefix := c.config.Installation.ImagePrefix

	if c.config.OsType != c.SupportedOSType() {
		return fmt.Errorf("layer 7 features are supported only on %s", c.SupportedOSType())
	}

	var err error
	var errMsgs []string

	c.config.proxyImage, err = components.GetReference(components.ComponentEnvoyProxy, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.collectorImage, err = components.GetReference(components.ComponentL7Collector, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.config.dikastesImage, err = components.GetReference(components.ComponentDikastes, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}

	return nil
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object
	// If l7spec is provided render the required objects.
	objs = append(objs, c.serviceAccount())

	// If Web Application Firewall is enabled, we need WAF ruleset ConfigMap present.
	if c.config.WAFEnabled {
		// this ConfigMap is a copy of the provided configuration from the operator namespace into the calico-system namespace
		objs = append(objs, c.modSecurityConfigMap())
	}

	// Envoy configuration
	c.config.envoyConfigMap = c.envoyL7ConfigMap()
	objs = append(objs, c.config.envoyConfigMap)

	// Envoy & Dikastes Daemonset
	objs = append(objs, c.daemonset())

	if c.config.Installation.KubernetesProvider == operatorv1.ProviderDockerEE {
		objs = append(objs, c.clusterAdminClusterRoleBinding())
	}

	// If we're running on openshift, we need to add in an SCC.
	if c.config.Installation.KubernetesProvider == operatorv1.ProviderOpenShift {
		objs = append(objs, c.securityContextConstraints())
	}

	return objs, nil
}

func (c *component) Ready() bool {
	return true
}

// daemonset creates a daemonset for the L7 log collector component.
func (c *component) daemonset() *appsv1.DaemonSet {
	maxUnavailable := intstr.FromInt(1)

	annots := map[string]string{}

	if c.config.envoyConfigMap != nil {
		annots[EnvoyConfigMapName] = rmeta.AnnotationHash(c.config.envoyConfigMap)
	}

	if c.config.ModSecurityConfigMap != nil {
		annots[ModSecurityRulesetHashAnnotation] = rmeta.AnnotationHash(c.config.ModSecurityConfigMap.Data)
	}

	podTemplate := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"k8s-app": ApplicationLayerDaemonsetName,
			},
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			HostIPC:            true,
			HostNetwork:        true,
			ServiceAccountName: APLName,
			DNSPolicy:          corev1.DNSClusterFirstWithHostNet,
			// Absence of l7 daemonset pod on a node will break the annotated services connectivity, so we tolerate all.
			Tolerations:      rmeta.TolerateAll,
			ImagePullSecrets: secret.GetReferenceList(c.config.PullSecrets),
			Containers:       c.containers(),
			Volumes:          c.volumes(),
		},
	}

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ApplicationLayerDaemonsetName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": ApplicationLayerDaemonsetName}},
			Template: podTemplate,
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &maxUnavailable,
				},
			},
		},
	}

}

func (c *component) containers() []corev1.Container {
	var containers []corev1.Container

	proxy := corev1.Container{
		Name:  ProxyContainerName,
		Image: c.config.proxyImage,
		Command: []string{
			"envoy", "-c", "/etc/envoy/envoy-config.yaml",
		},
		// Daemonset needs root and NET_ADMIN, NET_RAW permission to be able to use netfilter tproxy option.
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

	if c.config.LogsEnabled {
		// Log collection specific container
		collector := corev1.Container{
			Name:         L7CollectorContainerName,
			Image:        c.config.collectorImage,
			Env:          c.collectorEnv(),
			VolumeMounts: c.collectorVolMounts(),
		}
		containers = append(containers, collector)
	}

	if c.config.WAFEnabled {
		// Web Application Firewall (WAF) specific container
		dikastes := corev1.Container{
			Name:  DikastesContainerName,
			Image: c.config.dikastesImage,
			Command: []string{
				"/dikastes",
				"server",
				"--dial", "/var/run/felix/nodeagent/socket",
				"--listen", "/var/run/dikastes/dikastes.sock",
				"--rules", "/etc/modsecurity-ruleset",
			},
			Env: []corev1.EnvVar{
				{Name: "LOG_LEVEL", Value: "Info"},
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: FelixSync, MountPath: "/var/run/felix"},
				{Name: DikastesSyncVolumeName, MountPath: "/var/run/dikastes"},
				{Name: CalicoLogsVolumeName, MountPath: "/var/log/calico"},
				{Name: ModSecurityRulesetVolumeName, MountPath: "/etc/modsecurity-ruleset", ReadOnly: true},
			},
			SecurityContext: &corev1.SecurityContext{
				Privileged: ptr.BoolToPtr(true),
				RunAsUser:  ptr.Int64ToPtr(0),
				RunAsGroup: ptr.Int64ToPtr(0),
			},
		}
		containers = append(containers, dikastes)
	}

	return containers
}

func (c *component) proxyEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		// envoy needs to run as root to be able to use transparent flag (for tproxy)
		{Name: "ENVOY_UID", Value: "0"},
		{Name: "ENVOY_GID", Value: "0"},
	}
}

func (c *component) collectorEnv() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "Info"},
		{Name: "FELIX_DIAL_TARGET", Value: "/var/run/felix/nodeagent/socket"},
	}

	// Set rate limiters if provided.
	if c.config.LogRequestsPerInterval != nil {
		envs = append(envs, corev1.EnvVar{
			Name:  "ENVOY_LOG_REQUESTS_PER_INTERVAL",
			Value: strconv.FormatInt(*c.config.LogRequestsPerInterval, 10),
		})
	}

	if c.config.LogIntervalSeconds != nil {
		envs = append(envs, corev1.EnvVar{
			Name:  "ENVOY_LOG_INTERVAL_SECONDS",
			Value: strconv.FormatInt(*c.config.LogIntervalSeconds, 10),
		})
	}

	return envs
}

func (c *component) volumes() []corev1.Volume {
	var volumes []corev1.Volume

	// This empty directory volume will be mounted at /tmp/ which will contain the access logs file generated by envoy.
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

	volumes = append(volumes, corev1.Volume{
		Name: FelixSync,
		VolumeSource: corev1.VolumeSource{
			FlexVolume: &corev1.FlexVolumeSource{
				Driver: "nodeagent/uds",
			},
		},
	})

	if c.config.WAFEnabled {
		// Web Application Firewall specific volumes.

		// WAF logs need HostPath volume - logs to be consumed by fluentd.
		hostPathDirectoryOrCreate := corev1.HostPathDirectoryOrCreate
		volumes = append(volumes, corev1.Volume{
			Name: CalicoLogsVolumeName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico",
					Type: &hostPathDirectoryOrCreate,
				},
			},
		})

		// Needed for Dikastes' authz check server.
		volumes = append(volumes, corev1.Volume{
			Name: DikastesSyncVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})

		// Needed for ModSecurity library - contains rule set.
		volumes = append(volumes, corev1.Volume{
			Name: ModSecurityRulesetVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: ModSecurityRulesetConfigMapName,
					},
				},
			},
		})
	}

	return volumes
}

func (c *component) proxyVolMounts() []corev1.VolumeMount {
	volumes := []corev1.VolumeMount{
		{Name: EnvoyConfigMapName, MountPath: "/etc/envoy"},
		{Name: EnvoyLogsVolumeName, MountPath: "/tmp/"},
	}

	if c.config.WAFEnabled {
		volumes = append(volumes,
			corev1.VolumeMount{
				Name:      DikastesSyncVolumeName,
				MountPath: "/var/run/dikastes",
			},
		)
	}

	return volumes
}

func (c *component) collectorVolMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: EnvoyLogsVolumeName, MountPath: "/tmp/"},
		{Name: FelixSync, MountPath: "/var/run/felix"},
	}
}

func (c *component) modSecurityConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ModSecurityRulesetConfigMapName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data:       c.config.ModSecurityConfigMap.Data,
		BinaryData: c.config.ModSecurityConfigMap.BinaryData,
	}
}

//go:embed envoy-config.yaml.template
var envoyConfigTemplate string

func (c *component) envoyL7ConfigMap() *corev1.ConfigMap {
	var config bytes.Buffer

	tpl, err := template.New("envoyConfigTemplate").Parse(envoyConfigTemplate)
	if err != nil {
		return nil
	}

	err = tpl.Execute(&config, c.config)
	if err != nil {
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
			EnvoyConfigMapKey: config.String(),
		},
	}
}

// serviceAccount creates application layer service account.
func (c *component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: APLName, Namespace: common.CalicoNamespace},
	}
}

// In DockerEE (Mirantis) cluster-admin role is needed for envoy proxy to be able to use hostNetwork.
func (c *component) clusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
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
}

// securityContextConstraints returns SCC needed for daemonset to run on Openshift.
func (c *component) securityContextConstraints() *ocsv1.SecurityContextConstraints {
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
