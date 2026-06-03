// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package enterprise

import (
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	client "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
)

const (
	// defaultNodeReporterPort is the port calico/node reports Enterprise internal
	// metrics on when FelixConfiguration does not override prometheusReporterPort.
	defaultNodeReporterPort = 9081

	// defaultFelixMetricsPort is the Felix prometheus metrics port used when
	// FelixConfiguration does not override prometheusMetricsPort.
	defaultFelixMetricsPort = 9091

	installCNIContainerName = "install-cni"
)

func registerNode() {
	extensions.OverrideImage(render.ComponentNameNode, func(in *operatorv1.InstallationSpec) (components.Component, bool) {
		if !in.Variant.IsEnterprise() {
			return components.Component{}, false
		}
		return components.ComponentTigeraNode, true
	})
	extensions.Modify(render.ComponentNameNode, modifyNode)
}

// modifyNode layers Calico Enterprise behavior onto the rendered calico/node
// objects: the extra RBAC rules, the node-metrics Service, and the Enterprise
// daemonset configuration (flow/DNS log env, prometheus reporter, BGP metrics
// readiness check, multi-interface mode, and the calico log volume).
func modifyNode(ctx extensions.RenderContext, objs []client.Object) []client.Object {
	if ctx.Installation == nil || !ctx.Installation.Variant.IsEnterprise() {
		return objs
	}

	if role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, render.CalicoNodeObjectName); ok {
		role.Rules = append(role.Rules, nodeEnterpriseRules()...)
	}

	// The Network resource is only available in Enterprise / Cloud at this time.
	if role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, render.CalicoCNIPluginObjectName); ok {
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"get"},
		})
	}

	if ds, ok := extensions.FindObject[*appsv1.DaemonSet](objs, common.NodeDaemonSetName); ok {
		modifyNodeDaemonSet(ctx, ds)
	}

	return append(objs, nodeMetricsService(ctx))
}

// nodeEnterpriseRules are the additional cluster role rules calico/node needs in
// Calico Enterprise.
func nodeEnterpriseRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{
			// Calico Enterprise needs to be able to read additional resources.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"bfdconfigurations",
				"egressgatewaypolicies",
				"externalnetworks",
				"licensekeys",
				"networks",
				"packetcaptures",
				"remoteclusterconfigurations",
			},
			Verbs: []string{"get", "list", "watch"},
		},
		{
			// Tigera Secure updates status for packet captures.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"packetcaptures",
				"packetcaptures/status",
			},
			Verbs: []string{"update"},
		},
	}
}

// modifyNodeDaemonSet applies the Enterprise-specific daemonset changes that the
// base render leaves out: the Enterprise felix env, multi-interface mode, and the
// BGP metrics readiness check. The calico log volume is mounted by the base
// render for both variants, so it is not handled here.
func modifyNodeDaemonSet(ctx extensions.RenderContext, ds *appsv1.DaemonSet) {
	spec := &ds.Spec.Template.Spec

	multiInterfaceMode := multiInterfaceModeEnv(ctx.Installation)

	for i := range spec.InitContainers {
		if spec.InitContainers[i].Name == installCNIContainerName && multiInterfaceMode != nil {
			spec.InitContainers[i].Env = append(spec.InitContainers[i].Env, *multiInterfaceMode)
		}
	}

	for i := range spec.Containers {
		c := &spec.Containers[i]
		if c.Name != render.CalicoNodeObjectName {
			continue
		}

		c.Env = append(c.Env, nodeEnterpriseEnv(ctx)...)

		// Add the BGP metrics readiness check, but only when the base render kept
		// the bird readiness check (i.e. BGP is in use and we're not on VPP).
		if c.ReadinessProbe != nil && c.ReadinessProbe.Exec != nil && containsString(c.ReadinessProbe.Exec.Command, "--bird-ready") {
			c.ReadinessProbe.Exec.Command = append(c.ReadinessProbe.Exec.Command, "--bgp-metrics-ready")
		}
	}
}

// nodeEnterpriseEnv is the Enterprise felix configuration added to the
// calico/node container.
func nodeEnterpriseEnv(ctx extensions.RenderContext) []corev1.EnvVar {
	env := []corev1.EnvVar{
		{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
		{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: fmt.Sprintf("%d", nodeReporterPort(ctx.FelixConfiguration))},
		{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
		{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
		{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
		{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
		{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
	}

	if mode := multiInterfaceModeEnv(ctx.Installation); mode != nil {
		env = append(env, *mode)
	}

	if ctx.NodePrometheusTLS != nil && ctx.TrustedBundle != nil {
		env = append(env,
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCERTFILE", Value: ctx.NodePrometheusTLS.VolumeMountCertificateFilePath()},
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERKEYFILE", Value: ctx.NodePrometheusTLS.VolumeMountKeyFilePath()},
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCAFILE", Value: ctx.TrustedBundle.MountPath()},
		)
	}

	return env
}

// multiInterfaceModeEnv returns the MULTI_INTERFACE_MODE env var when the
// installation configures it, or nil otherwise.
func multiInterfaceModeEnv(install *operatorv1.InstallationSpec) *corev1.EnvVar {
	if install.CalicoNetwork != nil && install.CalicoNetwork.MultiInterfaceMode != nil {
		return &corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: install.CalicoNetwork.MultiInterfaceMode.Value()}
	}
	return nil
}

// nodeMetricsService builds the enterprise-only calico-node-metrics Service.
func nodeMetricsService(ctx extensions.RenderContext) *corev1.Service {
	reporterPort := nodeReporterPort(ctx.FelixConfiguration)
	felixPort := felixMetricsPort(ctx.FelixConfiguration)
	felixEnabled := ctx.FelixConfiguration != nil && utils.IsFelixPrometheusMetricsEnabled(ctx.FelixConfiguration)

	ports := []corev1.ServicePort{
		{
			Name:       "calico-metrics-port",
			Port:       int32(reporterPort),
			TargetPort: intstr.FromInt(reporterPort),
			Protocol:   corev1.ProtocolTCP,
		},
		{
			Name:       "calico-bgp-metrics-port",
			Port:       render.NodeBGPReporterPort,
			TargetPort: intstr.FromInt(int(render.NodeBGPReporterPort)),
			Protocol:   corev1.ProtocolTCP,
		},
	}
	if felixEnabled {
		ports = append(ports, corev1.ServicePort{
			Name:       "felix-metrics-port",
			Port:       int32(felixPort),
			TargetPort: intstr.FromInt(felixPort),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.CalicoNodeMetricsService,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": render.CalicoNodeObjectName},
		},
		Spec: corev1.ServiceSpec{
			Selector:  map[string]string{"k8s-app": render.CalicoNodeObjectName},
			ClusterIP: "None",
			Ports:     ports,
		},
	}
}

// nodeReporterPort returns the reporter metrics port from the FelixConfiguration,
// falling back to the default. The node-metrics Service and the
// FELIX_PROMETHEUSREPORTERPORT env var both derive from here so they can't drift.
func nodeReporterPort(fc *v3.FelixConfiguration) int {
	if fc != nil && fc.Spec.PrometheusReporterPort != nil {
		return *fc.Spec.PrometheusReporterPort
	}
	return defaultNodeReporterPort
}

// felixMetricsPort returns the Felix prometheus metrics port from the
// FelixConfiguration, falling back to the default.
func felixMetricsPort(fc *v3.FelixConfiguration) int {
	if fc != nil && fc.Spec.PrometheusMetricsPort != nil {
		return *fc.Spec.PrometheusMetricsPort
	}
	return defaultFelixMetricsPort
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
