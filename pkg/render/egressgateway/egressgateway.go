// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package egressgateway

import (
	"encoding/json"
	"fmt"
	"strings"

	ocsv1 "github.com/openshift/api/security/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	egwPortName               = "health"
	DefaultEGWVxlanPort int   = 4790
	DefaultEGWVxlanVNI  int   = 4097
	DefaultHealthPort   int32 = 8080
)

func EgressGateway(
	config *Config,
) render.Component {
	return &component{
		config: config,
	}
}

type component struct {
	config *Config
}

// Config contains all the config information EgressGateway needs to render component.
type Config struct {
	PullSecrets  []*corev1.Secret
	Installation *operatorv1.InstallationSpec
	OSType       rmeta.OSType
	EgressGW     *operatorv1.EgressGateway

	egwImage  string
	VXLANVNI  int
	VXLANPort int

	Openshift bool
	// Whether or not the cluster supports pod security policies.
	UsePSP bool
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.config.Installation.Registry
	path := c.config.Installation.ImagePath
	prefix := c.config.Installation.ImagePrefix

	if c.config.OSType != c.SupportedOSType() {
		return fmt.Errorf("Egress Gateway is supported only on %s", c.SupportedOSType())
	}

	var err error
	c.config.egwImage, err = components.GetReference(components.ComponentEgressGateway, reg, path, prefix, is)
	return err
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	objectsToCreate := []client.Object{}
	objectsToDelete := []client.Object{}
	objectsToCreate = append(objectsToCreate, c.egwServiceAccount())
	objectsToCreate = append(objectsToCreate, c.egwDeployment())
	if c.config.UsePSP {
		objectsToCreate = append(objectsToCreate, c.egwPodSecurityPolicy())
		objectsToCreate = append(objectsToCreate, c.egwClusterRole())
		objectsToCreate = append(objectsToCreate, c.egwClusterRoleBinding())
	} else if c.config.Openshift {
		objectsToCreate = append(objectsToCreate, c.egwSecurityContextConstraints())
	} else {
		objectsToDelete = append(objectsToDelete, c.egwClusterRole())
		objectsToDelete = append(objectsToDelete, c.egwClusterRoleBinding())
	}
	return objectsToCreate, objectsToDelete
}

func (c *component) Ready() bool {
	return true
}

func (c *component) egwDeployment() *appsv1.Deployment {
	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.config.EgressGW.Name,
			Namespace: c.config.EgressGW.Namespace,
			Labels:    c.config.EgressGW.Spec.Template.Metadata.Labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.config.EgressGW.Spec.Replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": c.config.EgressGW.Name}},
			Template: *c.deploymentPodTemplate(),
		},
	}

	if overrides := c.config.EgressGW; overrides != nil {
		rcomp.ApplyDeploymentOverrides(&d, overrides)
	}

	return &d
}

func (c *component) deploymentPodTemplate() *corev1.PodTemplateSpec {
	var ps []corev1.LocalObjectReference
	for _, x := range c.config.PullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}
	return &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: c.egwBuildAnnotations(),
		},
		Spec: corev1.PodSpec{
			ImagePullSecrets:   ps,
			InitContainers:     []corev1.Container{*c.egwInitContainer()},
			Containers:         []corev1.Container{*c.egwContainer()},
			ServiceAccountName: c.config.EgressGW.Name,
			Volumes:            []corev1.Volume{*c.egwVolume()},
		},
	}
}

func (c *component) egwBuildAnnotations() map[string]string {
	annotations := map[string]string{}
	annotations["cni.projectcalico.org/ipv4pools"] = c.getIPPools()
	if c.config.EgressGW.Spec.AWS != nil && len(c.config.EgressGW.Spec.AWS.ElasticIPs) > 0 {
		annotations["cni.projectcalico.org/awsElasticIPs"] = c.getElasticIPs()
	}
	return annotations
}

func (c *component) egwInitContainer() *corev1.Container {
	return &corev1.Container{
		Name:            "egress-gateway-init",
		Image:           c.config.egwImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/init-gateway.sh"},
		SecurityContext: &corev1.SecurityContext{Privileged: ptr.BoolToPtr(true)},
		Env:             c.egwInitEnvVars(),
	}
}

func (c *component) egwContainer() *corev1.Container {
	return &corev1.Container{
		Name:            "egress-gateway",
		Image:           c.config.egwImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Env:             c.egwEnvVars(),
		Resources:       c.getResources(),
		VolumeMounts:    c.egwVolumeMounts(),
		Ports:           c.egwPorts(),
		Command:         []string{"/start-gateway.sh"},
		ReadinessProbe:  c.egwReadinessProbe(),
		SecurityContext: c.egwSecurityContext(),
	}
}

func (c *component) egwReadinessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/readiness",
				Port: intstr.FromInt(int(DefaultHealthPort)),
			},
		},
		InitialDelaySeconds: 3,
		TimeoutSeconds:      1,
		SuccessThreshold:    1,
		PeriodSeconds:       3,
	}
}

func (c *component) egwSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{"NET_ADMIN"},
		},
	}
}

func (c *component) egwPorts() []corev1.ContainerPort {
	return []corev1.ContainerPort{
		{
			ContainerPort: DefaultHealthPort,
			Name:          egwPortName,
			Protocol:      corev1.ProtocolTCP,
		},
	}
}

func (c *component) egwVolume() *corev1.Volume {
	return &corev1.Volume{
		Name:         "policysync",
		VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "csi.tigera.io"}},
	}
}

func (c *component) egwVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		corev1.VolumeMount{Name: "policysync", MountPath: "/var/run/calico"},
	}
}

func (c *component) egwEnvVars() []corev1.EnvVar {
	egressPodIp := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}
	envVar := []corev1.EnvVar{
		{Name: "HEALTH_PORT", Value: fmt.Sprintf("%d", DefaultHealthPort)},
		{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
		{Name: "EGRESS_VXLAN_VNI", Value: fmt.Sprintf("%d", c.config.VXLANVNI)},
		{Name: "LOG_SEVERITY", Value: c.config.EgressGW.GetLogSeverity()},
	}

	icmpProbeIPs, icmpInterval, icmpTimeout := c.getICMPProbe()
	if icmpProbeIPs != "" {
		icmpEnvVar := []corev1.EnvVar{
			{Name: "ICMP_PROBE_IPS", Value: icmpProbeIPs},
			{Name: "ICMP_PROBE_INTERVAL", Value: icmpInterval},
			{Name: "ICMP_PROBE_TIMEOUT", Value: icmpTimeout},
		}
		envVar = append(envVar, icmpEnvVar...)
	}

	httpProbeURLs, httpInterval, httpTimeout := c.getHTTPProbe()
	if httpProbeURLs != "" {
		httpEnvVar := []corev1.EnvVar{
			{Name: "HTTP_PROBE_URLS", Value: httpProbeURLs},
			{Name: "HTTP_PROBE_INTERVAL", Value: httpInterval},
			{Name: "HTTP_PROBE_TIMEOUT", Value: httpTimeout},
		}
		envVar = append(envVar, httpEnvVar...)
	}
	healthTimeOutDS := c.getHealthTimeoutDs()
	if healthTimeOutDS != "" {
		dsEnv := corev1.EnvVar{Name: "HEALTH_TIMEOUT_DATASTORE", Value: healthTimeOutDS}
		envVar = append(envVar, dsEnv)
	}
	return envVar
}

func (c *component) egwInitEnvVars() []corev1.EnvVar {
	egressPodIp := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}
	return []corev1.EnvVar{
		{Name: "EGRESS_VXLAN_VNI", Value: fmt.Sprintf("%d", c.config.VXLANVNI)},
		{Name: "EGRESS_VXLAN_PORT", Value: fmt.Sprintf("%d", c.config.VXLANPort)},
		{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
	}
}

func (c *component) egwPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	boolTrue := true
	namespacedName := fmt.Sprintf("%s-%s", c.config.EgressGW.Namespace, c.config.EgressGW.Name)
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(namespacedName)
	psp.Spec.AllowedCapabilities = []corev1.Capability{
		corev1.Capability("NET_ADMIN"),
	}
	psp.Spec.AllowPrivilegeEscalation = &boolTrue
	psp.Spec.HostIPC = true
	psp.Spec.HostNetwork = true
	psp.Spec.HostPID = true
	psp.Spec.Privileged = true
	psp.Spec.RunAsUser = policyv1beta1.RunAsUserStrategyOptions{
		Rule: policyv1beta1.RunAsUserStrategyRunAsAny,
	}
	psp.Spec.SELinux = policyv1beta1.SELinuxStrategyOptions{
		Rule: policyv1beta1.SELinuxStrategyRunAsAny,
	}
	psp.Spec.SupplementalGroups = policyv1beta1.SupplementalGroupsStrategyOptions{
		Rule: policyv1beta1.SupplementalGroupsStrategyRunAsAny,
	}
	psp.Spec.FSGroup = policyv1beta1.FSGroupStrategyOptions{
		Rule: policyv1beta1.FSGroupStrategyRunAsAny,
	}
	psp.Spec.Volumes = []policyv1beta1.FSType{
		policyv1beta1.CSI,
		policyv1beta1.Projected,
	}
	return psp
}

func (c *component) egwClusterRole() *rbacv1.ClusterRole {
	namespacedName := fmt.Sprintf("%s-%s", c.config.EgressGW.Namespace, c.config.EgressGW.Name)
	rules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			ResourceNames: []string{namespacedName},
			Verbs:         []string{"use"},
		},
	}
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespacedName,
		},
		Rules: rules,
	}
}

func (c *component) egwClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	namespacedName := fmt.Sprintf("%s-%s", c.config.EgressGW.Namespace, c.config.EgressGW.Name)
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespacedName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     namespacedName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      c.config.EgressGW.Name,
				Namespace: c.config.EgressGW.Namespace,
			},
		},
	}
}

func (c *component) egwServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.config.EgressGW.Name,
			Namespace: c.config.EgressGW.Namespace,
		},
	}
}

func (c *component) getICMPProbe() (string, string, string) {
	probeIPs := ""
	interval := ""
	timeout := ""
	if c.config.EgressGW.Spec.EgressGatewayFailureDetection != nil {
		if c.config.EgressGW.Spec.EgressGatewayFailureDetection.ICMPProbe != nil {
			icmpProbes := c.config.EgressGW.Spec.EgressGatewayFailureDetection.ICMPProbe
			probeIPs = strings.Join(icmpProbes.IPs, ",")
			interval = fmt.Sprintf("%ds", *icmpProbes.IntervalSeconds)
			timeout = fmt.Sprintf("%ds", *icmpProbes.TimeoutSeconds)
		}
	}
	return probeIPs, interval, timeout
}

func (c *component) getHTTPProbe() (string, string, string) {
	probeURLs := ""
	interval := ""
	timeout := ""
	if c.config.EgressGW.Spec.EgressGatewayFailureDetection != nil {
		if c.config.EgressGW.Spec.EgressGatewayFailureDetection.HTTPProbe != nil {
			httpProbes := c.config.EgressGW.Spec.EgressGatewayFailureDetection.HTTPProbe
			probeURLs = strings.Join(httpProbes.URLs, ",")
			interval = fmt.Sprintf("%ds", *httpProbes.IntervalSeconds)
			timeout = fmt.Sprintf("%ds", *httpProbes.TimeoutSeconds)
		}
	}
	return probeURLs, interval, timeout
}

func (c *component) getResources() corev1.ResourceRequirements {
	recommendedQuantity := resource.NewQuantity(1, resource.DecimalSI)
	egw := c.config.EgressGW
	if egw.Spec.AWS != nil && *egw.Spec.AWS.NativeIP == operatorv1.NativeIPEnabled {
		return corev1.ResourceRequirements{
			Limits:   corev1.ResourceList{"projectcalico.org/aws-secondary-ipv4": *recommendedQuantity},
			Requests: corev1.ResourceList{"projectcalico.org/aws-secondary-ipv4": *recommendedQuantity},
		}
	}
	return corev1.ResourceRequirements{}
}

func (c *component) getIPPools() string {
	egw := c.config.EgressGW
	ippools := []string{}
	for _, ippool := range egw.Spec.IPPools {
		if ippool.Name != "" {
			ippools = append(ippools, ippool.Name)
		} else if ippool.CIDR != "" {
			ippools = append(ippools, ippool.CIDR)
		}
	}
	return concatString(ippools)
}

func (c *component) getElasticIPs() string {
	egw := c.config.EgressGW
	if egw.Spec.AWS != nil {
		if len(egw.Spec.AWS.ElasticIPs) > 0 {
			return concatString(egw.Spec.AWS.ElasticIPs)
		}
	}
	return ""
}

func (c *component) getHealthTimeoutDs() string {
	if c.config.EgressGW.Spec.EgressGatewayFailureDetection != nil {
		if c.config.EgressGW.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStoreSeconds != nil {
			egw := c.config.EgressGW
			return fmt.Sprintf("%ds", *egw.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStoreSeconds)
		}
	}
	return ""
}

func (c *component) egwSecurityContextConstraints() *ocsv1.SecurityContextConstraints {
	namespacedName := fmt.Sprintf("%s-%s", c.config.EgressGW.Namespace, c.config.EgressGW.Name)
	return &ocsv1.SecurityContextConstraints{
		TypeMeta:                 metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
		ObjectMeta:               metav1.ObjectMeta{Name: namespacedName},
		AllowHostDirVolumePlugin: true,
		AllowHostIPC:             false,
		AllowHostNetwork:         false,
		AllowHostPID:             false,
		AllowHostPorts:           false,
		AllowPrivilegeEscalation: ptr.BoolToPtr(true),
		AllowPrivilegedContainer: true,
		FSGroup:                  ocsv1.FSGroupStrategyOptions{Type: ocsv1.FSGroupStrategyRunAsAny},
		RunAsUser:                ocsv1.RunAsUserStrategyOptions{Type: ocsv1.RunAsUserStrategyRunAsAny},
		ReadOnlyRootFilesystem:   false,
		SELinuxContext:           ocsv1.SELinuxContextStrategyOptions{Type: ocsv1.SELinuxStrategyMustRunAs},
		SupplementalGroups:       ocsv1.SupplementalGroupsStrategyOptions{Type: ocsv1.SupplementalGroupsStrategyRunAsAny},
		Users: []string{
			fmt.Sprintf("system:serviceaccount:%s:%s", c.config.EgressGW.Namespace, c.config.EgressGW.Name),
		},
		Volumes: []ocsv1.FSType{"*"},
	}
}

func concatString(arr []string) string {
	str, err := json.Marshal(arr)
	if err != nil {
		return ""
	}
	return string(str)
}
