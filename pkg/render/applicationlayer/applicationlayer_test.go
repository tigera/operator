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

package applicationlayer_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Tigera Secure Application Layer rendering tests", func() {
	var installation *operatorv1.InstallationSpec

	BeforeEach(func() {
		// Initialize a default installation spec.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
		}
	})

	It("should render with default l7 collector configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: applicationlayer.APLName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: applicationlayer.EnvoyConfigMapName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: applicationlayer.ApplicationLayerDaemonsetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}
		// Should render the correct resources.
		component := applicationlayer.ApplicationLayer(&applicationlayer.Config{
			PullSecrets:  nil,
			Installation: installation,
			OsType:       rmeta.OSTypeLinux,
			LogsEnabled:  true,
		})
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := rtest.GetResource(resources, applicationlayer.ApplicationLayerDaemonsetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

		// Check rendering of daemonset.
		Expect(ds.Spec.Template.Spec.HostNetwork).To(BeTrue())
		Expect(ds.Spec.Template.Spec.HostIPC).To(BeTrue())
		Expect(ds.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirstWithHostNet))
		Expect(len(ds.Spec.Template.Spec.Containers)).To(Equal(2))
		Expect(len(ds.Spec.Template.Spec.Tolerations)).To(Equal(3))

		// Ensure each volume rendered correctly.
		dsVols := ds.Spec.Template.Spec.Volumes
		expectedVolumes := []corev1.Volume{
			{
				Name: applicationlayer.EnvoyLogsVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
			{
				Name: applicationlayer.EnvoyConfigMapName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: applicationlayer.EnvoyConfigMapName},
					},
				},
			},
			{
				Name: applicationlayer.FelixSync,
				VolumeSource: corev1.VolumeSource{
					FlexVolume: &corev1.FlexVolumeSource{
						Driver: "nodeagent/uds",
					},
				},
			},
		}
		Expect(len(ds.Spec.Template.Spec.Volumes)).To(Equal(len(expectedVolumes)))

		for _, expected := range expectedVolumes {
			Expect(dsVols).To(ContainElement(expected))
		}

		// Ensure that tolerations rendered correctly.
		dsTolerations := ds.Spec.Template.Spec.Tolerations
		expectedToleration := rmeta.TolerateAll
		for _, expected := range expectedToleration {
			Expect(dsTolerations).To(ContainElement(expected))
		}

		// Check proxy container rendering.
		proxyContainer := ds.Spec.Template.Spec.Containers[0]

		proxyEnvs := proxyContainer.Env
		expectedProxyEnvs := []corev1.EnvVar{
			{Name: "ENVOY_UID", Value: "0"},
			{Name: "ENVOY_GID", Value: "0"},
		}
		Expect(len(proxyEnvs)).To(Equal(len(expectedProxyEnvs)))

		for _, expected := range expectedProxyEnvs {
			Expect(proxyEnvs).To(ContainElement(expected))
		}

		proxyVolMounts := proxyContainer.VolumeMounts
		expectedProxyVolMounts := []corev1.VolumeMount{
			{Name: applicationlayer.EnvoyConfigMapName, MountPath: "/etc/envoy"},
			{Name: applicationlayer.EnvoyLogsVolumeName, MountPath: "/tmp/"},
		}
		Expect(len(proxyVolMounts)).To(Equal(len(expectedProxyVolMounts)))

		for _, expected := range expectedProxyVolMounts {
			Expect(proxyVolMounts).To(ContainElement(expected))
		}

		collectorContainer := ds.Spec.Template.Spec.Containers[1]

		collectorEnvs := collectorContainer.Env
		expectedCollectorEnvs := []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "Info"},
			{Name: "FELIX_DIAL_TARGET", Value: "/var/run/felix/nodeagent/socket"},
		}
		Expect(len(collectorEnvs)).To(Equal(len(expectedCollectorEnvs)))

		for _, element := range expectedCollectorEnvs {
			Expect(collectorEnvs).To(ContainElement(element))
		}

		collectorVolMounts := collectorContainer.VolumeMounts
		expectedCollectorVolMounts := []corev1.VolumeMount{
			{Name: applicationlayer.EnvoyLogsVolumeName, MountPath: "/tmp/"},
			{Name: applicationlayer.FelixSync, MountPath: "/var/run/felix"},
		}
		Expect(len(collectorVolMounts)).To(Equal(len(expectedCollectorVolMounts)))
		for _, expected := range expectedCollectorVolMounts {
			Expect(collectorVolMounts).To(ContainElement(expected))
		}
	})

	It("should render with custom l7 collector configuration", func() {
		// create component with render the correct resources.
		// Should render the correct resources.
		component := applicationlayer.ApplicationLayer(&applicationlayer.Config{
			PullSecrets:            nil,
			Installation:           installation,
			OsType:                 rmeta.OSTypeLinux,
			LogsEnabled:            true,
			LogIntervalSeconds:     ptr.Int64ToPtr(5),
			LogRequestsPerInterval: ptr.Int64ToPtr(-1),
		})
		resources, _ := component.Objects()

		ds := rtest.GetResource(resources, applicationlayer.ApplicationLayerDaemonsetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

		collectorContainer := ds.Spec.Template.Spec.Containers[1]

		collectorEnvs := collectorContainer.Env
		// ensure that custom env vars ENVOY_LOG_REQUESTS_PER_INTERVAL, ENVOY_LOG_INTERVAL_SECONDS set properly
		expectedCollectorEnvs := []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "Info"},
			{Name: "FELIX_DIAL_TARGET", Value: "/var/run/felix/nodeagent/socket"},
			{Name: "ENVOY_LOG_REQUESTS_PER_INTERVAL", Value: "-1"},
			{Name: "ENVOY_LOG_INTERVAL_SECONDS", Value: "5"},
		}
		Expect(len(collectorEnvs)).To(Equal(len(expectedCollectorEnvs)))
		for _, element := range expectedCollectorEnvs {
			Expect(collectorEnvs).To(ContainElement(element))
		}
	})

})
