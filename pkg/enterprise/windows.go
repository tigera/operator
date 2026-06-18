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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// windowsNodeContainers are the calico-node-windows containers that share the
// felix env and node volume mounts, so they receive the same enterprise layering.
var windowsNodeContainers = map[string]bool{"felix": true, "node": true, "confd": true}

func registerWindows(v *extensions.Variant) {
	v.Image(render.ComponentNameWindowsNodeImg, components.ComponentTigeraNodeWindows)
	v.Image(render.ComponentNameWindowsCNIImg, components.ComponentTigeraCNIWindows)
	v.Modify(render.ComponentNameWindows, modifyWindows)
}

// windowsControllerExtension is the Calico Enterprise controller-side hook for the
// windows controller.
type windowsControllerExtension struct{}

// windowsRenderData is the controller-produced data the windows extension hands to
// its modifier through RenderContext.Extension.
type windowsRenderData struct {
	prometheusServerTLS certificatemanagement.KeyPairInterface
}

// windowsData pulls the windows extension's render data back out of the render
// context, returning the zero value when none is set.
func windowsData(rc extensions.RenderContext) windowsRenderData {
	data, _ := rc.Extension.(windowsRenderData)
	return data
}

// Validate rejects windows installation config Calico Enterprise does not support.
func (windowsControllerExtension) Validate(cc extensions.ControllerContext) error {
	return validateReporterPort(cc.FelixConfiguration)
}

// ExtendContext fetches the node prometheus keypair the installation controller
// created and stashes it in the render context for the windows modifier.
func (windowsControllerExtension) ExtendContext(cc extensions.ControllerContext) (extensions.RenderContext, []certificatemanagement.KeyPairInterface, error) {
	rc := cc.RenderContext
	tls, err := cc.CertificateManager.GetKeyPair(
		cc.Client,
		render.NodePrometheusTLSServerSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(render.WindowsNodeMetricsService, common.CalicoNamespace, cc.ClusterDomain),
	)
	if err != nil {
		return rc, nil, fmt.Errorf("error getting node prometheus TLS certificate: %w", err)
	}
	rc.Extension = windowsRenderData{prometheusServerTLS: tls}
	return rc, nil, nil
}

// modifyWindows layers Calico Enterprise behavior onto the rendered
// calico-node-windows objects: the node-metrics Service and the Enterprise
// daemonset configuration (flow/DNS log env, prometheus reporter, trusted DNS
// servers, the calico log volume, and the prometheus reporter keypair mount).
func modifyWindows(rc extensions.RenderContext, objs, del []client.Object) ([]client.Object, []client.Object) {
	if ds, ok := extensions.FindObject[*appsv1.DaemonSet](objs, common.WindowsDaemonSetName); ok {
		modifyWindowsDaemonSet(rc, ds)
	}

	return append(objs, windowsNodeMetricsService(rc)), del
}

func modifyWindowsDaemonSet(rc extensions.RenderContext, ds *appsv1.DaemonSet) {
	dirOrCreate := corev1.HostPathDirectoryOrCreate
	spec := &ds.Spec.Template.Spec

	spec.Volumes = append(spec.Volumes, corev1.Volume{
		Name:         "var-log-calico",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}},
	})

	for i := range spec.Containers {
		c := &spec.Containers[i]
		if !windowsNodeContainers[c.Name] {
			continue
		}

		c.Env = append(c.Env, windowsEnterpriseEnv(rc)...)

		// Enterprise mounts the calico log directory in place of the OSS CNI log
		// directory, so drop the OSS mount before adding the enterprise one.
		c.VolumeMounts = removeVolumeMount(c.VolumeMounts, "cni-log-dir")
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{MountPath: "/var/log/calico", Name: "var-log-calico"})
	}

	mountWindowsPrometheusTLS(rc, ds)
}

// windowsEnterpriseEnv is the Enterprise felix configuration added to the
// calico-node-windows containers.
func windowsEnterpriseEnv(rc extensions.RenderContext) []corev1.EnvVar {
	tls := windowsData(rc).prometheusServerTLS
	env := []corev1.EnvVar{
		{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
		{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: fmt.Sprintf("%d", nodeReporterPort(rc.FelixConfiguration))},
		{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
		{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
		{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
		{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
		{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
		{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
	}

	if tls != nil && rc.TrustedBundle != nil {
		env = append(env,
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCERTFILE", Value: tls.VolumeMountCertificateFilePath()},
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERKEYFILE", Value: tls.VolumeMountKeyFilePath()},
			corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCAFILE", Value: rc.TrustedBundle.MountPath()},
		)
	}

	// Providers without a kube-dns service need a non-default trusted DNS server.
	switch rc.Installation.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		env = append(env, corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"})
	case operatorv1.ProviderRKE2:
		env = append(env, corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:kube-system/rke2-coredns-rke2-coredns"})
	}

	return env
}

// mountWindowsPrometheusTLS mounts the node prometheus reporter keypair onto the
// windows daemonset: the volume, the volume mount on each node container, and
// the pod hash annotation that rolls the pods on cert rotation.
func mountWindowsPrometheusTLS(rc extensions.RenderContext, ds *appsv1.DaemonSet) {
	tls := windowsData(rc).prometheusServerTLS
	if tls == nil {
		return
	}
	spec := &ds.Spec.Template.Spec

	spec.Volumes = append(spec.Volumes, tls.Volume())

	for i := range spec.Containers {
		c := &spec.Containers[i]
		if windowsNodeContainers[c.Name] {
			c.VolumeMounts = append(c.VolumeMounts, tls.VolumeMount(rmeta.OSTypeWindows))
		}
	}

	if ds.Spec.Template.Annotations == nil {
		ds.Spec.Template.Annotations = map[string]string{}
	}
	ds.Spec.Template.Annotations[tls.HashAnnotationKey()] = tls.HashAnnotationValue()
}

// windowsNodeMetricsService builds the enterprise-only calico-node-metrics-windows
// Service.
func windowsNodeMetricsService(rc extensions.RenderContext) *corev1.Service {
	reporterPort := nodeReporterPort(rc.FelixConfiguration)
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.WindowsNodeMetricsService,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": render.WindowsNodeObjectName},
		},
		Spec: corev1.ServiceSpec{
			Selector:  map[string]string{"k8s-app": render.WindowsNodeObjectName},
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
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
			},
		},
	}
}

func removeVolumeMount(mounts []corev1.VolumeMount, name string) []corev1.VolumeMount {
	out := mounts[:0]
	for _, m := range mounts {
		if m.Name != name {
			out = append(out, m)
		}
	}
	return out
}
