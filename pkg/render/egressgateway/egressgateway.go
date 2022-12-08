// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	EGWPortName             = "health"
	DefaultEGWVxlanPort int = 4790
	DefaultEGWVxlanVNI  int = 4097
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
	OsType       rmeta.OSType
	EgressGW     *operatorv1.EgressGateway

	egwImage          string
	EgressGWVxlanVNI  int
	EgressGWVxlanPort int
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.config.Installation.Registry
	path := c.config.Installation.ImagePath
	prefix := c.config.Installation.ImagePrefix

	if c.config.OsType != c.SupportedOSType() {
		return fmt.Errorf("Egress Gateway is supported only on %s", c.SupportedOSType())
	}

	var err error
	c.config.egwImage, err = components.GetReference(components.ComponentEgressGateway, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return nil
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	return []client.Object{c.egwDeployment()}, nil
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
			Labels:    c.config.EgressGW.Spec.Labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.config.EgressGW.Spec.Replicas,
			Selector: &metav1.LabelSelector{MatchLabels: c.config.EgressGW.Spec.Labels},
			Template: *c.deploymentPodTemplate(),
		},
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
			Labels:      c.config.EgressGW.Spec.Labels,
		},
		Spec: corev1.PodSpec{
			ImagePullSecrets:              ps,
			Affinity:                      c.config.EgressGW.GetAffinity(),
			TopologySpreadConstraints:     c.config.EgressGW.GetTopoConstraints(),
			NodeSelector:                  c.config.EgressGW.GetNodeSelector(),
			TerminationGracePeriodSeconds: c.config.EgressGW.GetTerminationGracePeriod(),
			InitContainers:                []corev1.Container{*c.egwInitContainer()},
			Containers:                    []corev1.Container{*c.egwContainer()},
			Volumes:                       []corev1.Volume{*c.egwVolume()},
		},
	}
}

func (c *component) egwBuildAnnotations() map[string]string {
	annotations := map[string]string{}
	annotations["cni.projectcalico.org/ipv4pools"] = c.config.EgressGW.GetIPPools()
	if c.config.EgressGW.Spec.AWS != nil && len(c.config.EgressGW.Spec.AWS.ElasticIPs) > 0 {
		annotations["cni.projectcalico.org/awsElasticIPs"] = c.config.EgressGW.GetElasticIPs()
	}
	return annotations
}

func (c *component) egwInitContainer() *corev1.Container {
	initContainerPrivileges := true
	return &corev1.Container{
		Name:            "egress-gateway-init",
		Image:           c.config.egwImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/init-gateway.sh"},
		SecurityContext: &corev1.SecurityContext{Privileged: &initContainerPrivileges},
		Env:             c.egwInitEnvVars(),
	}
}

func (c *component) egwContainer() *corev1.Container {
	return &corev1.Container{
		Name:            "egress-gateway",
		Image:           c.config.egwImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Env:             c.egwEnvVars(),
		Resources:       c.egwResources(),
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
				Port: intstr.FromInt(int(c.config.EgressGW.GetHealthPort())),
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
			ContainerPort: c.config.EgressGW.GetHealthPort(),
			Name:          EGWPortName,
			Protocol:      corev1.ProtocolTCP,
		},
	}
}

func (c *component) egwResources() corev1.ResourceRequirements {
	return c.config.EgressGW.GetResources()
}

func (c *component) egwVolume() *corev1.Volume {
	return &corev1.Volume{
		Name:         "policysync",
		VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "csi.tigera.io"}},
	}
}

func (c *component) egwVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		corev1.VolumeMount{Name: "policysync", MountPath: "/var/run"},
	}
}

func (c *component) egwEnvVars() []corev1.EnvVar {
	icmpProbeIPs, icmpInterval, icmpTimeout := c.config.EgressGW.GetICMPProbes()
	httpProbeURLs, httpInterval, httpTimeout := c.config.EgressGW.GetHTTPProbes()
	egressPodIp := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}
	return []corev1.EnvVar{
		{Name: "HEALTH_PORT", Value: fmt.Sprintf("%d", c.config.EgressGW.GetHealthPort())},
		{Name: "HEALTH_TIMEOUT_DATASTORE", Value: c.config.EgressGW.GetHealthTimeoutDs()},
		{Name: "ICMP_PROBE_IPS", Value: icmpProbeIPs},
		{Name: "ICMP_PROBE_INTERVAL", Value: icmpInterval},
		{Name: "ICMP_PROBE_TIMEOUT", Value: icmpTimeout},
		{Name: "HTTP_PROBE_URLS", Value: httpProbeURLs},
		{Name: "HTTP_PROBE_INTERVAL", Value: httpInterval},
		{Name: "HTTP_PROBE_TIMEOUT", Value: httpTimeout},
		{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
		{Name: "EGRESS_VXLAN_VNI", Value: fmt.Sprintf("%d", c.config.EgressGWVxlanVNI)},
		{Name: "LOG_SEVERITY", Value: c.config.EgressGW.GetLogSeverity()},
	}
}

func (c *component) egwInitEnvVars() []corev1.EnvVar {
	egressPodIp := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}
	return []corev1.EnvVar{
		{Name: "EGRESS_VXLAN_VNI", Value: fmt.Sprintf("%d", c.config.EgressGWVxlanVNI)},
		{Name: "EGRESS_VXLAN_PORT", Value: fmt.Sprintf("%d", c.config.EgressGWVxlanPort)},
		{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
	}
}
