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
	//appsv1 "k8s.io/api/apps/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	EGWPortName = "health"
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

	egwImage string
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
	return nil, nil
}

func (c *component) Ready() bool {
	return true
}

/*
func (c *component) egwDeployment() *appsv1.Deployment {

}*/

func (c *component) egwInitContainer() corev1.Container {
	initContainerPrivileges := true
	egressPodIp := &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}
	return corev1.Container{
		Name:            "egress-gateway-init",
		Image:           c.config.egwImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/init-gateway.sh"},
		SecurityContext: &corev1.SecurityContext{Privileged: &initContainerPrivileges},
		Env:             []corev1.EnvVar{{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp}},
	}
}

func (c *component) egwContainer() corev1.Container {
	return corev1.Container{
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
				Host: "localhost",
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

func (c *component) egwVolume() corev1.Volume {
	return corev1.Volume{
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
		{Name: "EGW_LOGSEVERITYSCREEN", Value: c.config.EgressGW.GetLogSeverity()},
		{Name: "EGW_SOCKETPATH", Value: c.config.EgressGW.GetSocketPath()},
		{Name: "EGW_VXLANVNI", Value: fmt.Sprintf("%d", c.config.EgressGW.GetVxlanVni())},
		{Name: "ICMP_PROBE_IPS", Value: icmpProbeIPs},
		{Name: "ICMP_PROBE_INTERVAL", Value: fmt.Sprintf("%d", icmpInterval)},
		{Name: "ICMP_PROBE_TIMEOUT", Value: fmt.Sprintf("%d", icmpTimeout)},
		{Name: "HTTP_PROBE_URLS", Value: httpProbeURLs},
		{Name: "HTTP_PROBE_INTERVAL", Value: fmt.Sprintf("%d", httpInterval)},
		{Name: "HTTP_PROBE_TIMEOUT", Value: fmt.Sprintf("%d", httpTimeout)},
		{Name: "EGRESS_POD_IP", ValueFrom: egressPodIp},
	}
}
