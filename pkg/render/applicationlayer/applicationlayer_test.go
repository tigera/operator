// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Tigera Secure Application Layer rendering tests", func() {
	var (
		installation *operatorv1.InstallationSpec
		cfg          *applicationlayer.Config
	)

	BeforeEach(func() {
		// Initialize a default installation spec.
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
		}

		cfg = &applicationlayer.Config{
			PullSecrets:  nil,
			Installation: installation,
			OsType:       rmeta.OSTypeLinux,
			LogsEnabled:  true,
			UsePSP:       true,
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
			{name: "application-layer", ns: "calico-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: "application-layer", ns: "calico-system", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "application-layer", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
		}
		// Should render the correct resources.
		component := applicationlayer.ApplicationLayer(cfg)
		resources, _ := component.Objects()
		Expect(resources).To(HaveLen(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		ds := rtest.GetResource(resources, applicationlayer.ApplicationLayerDaemonsetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

		// Check rendering of daemonset.
		Expect(ds.Spec.Template.Spec.HostNetwork).To(BeTrue())
		Expect(ds.Spec.Template.Spec.HostIPC).To(BeTrue())
		Expect(ds.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirstWithHostNet))
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(2))
		Expect(ds.Spec.Template.Spec.Tolerations).To(HaveLen(3))

		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(2))
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				Add:  []corev1.Capability{"NET_ADMIN", "NET_RAW"},
			},
		))
		Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.Privileged).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(ds.Spec.Template.Spec.Containers[1].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(ds.Spec.Template.Spec.Containers[1].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

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
					CSI: &corev1.CSIVolumeSource{
						Driver: "csi.tigera.io",
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

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component := applicationlayer.ApplicationLayer(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
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

	It("should render with custom l7 envoy configuration", func() {
		// create component with render the correct resources.
		// Should render the correct resources.
		component := applicationlayer.ApplicationLayer(&applicationlayer.Config{
			PullSecrets:            nil,
			Installation:           installation,
			OsType:                 rmeta.OSTypeLinux,
			LogsEnabled:            true,
			LogIntervalSeconds:     ptr.Int64ToPtr(5),
			LogRequestsPerInterval: ptr.Int64ToPtr(-1),
			UseRemoteAddressXFF:    true,
			NumTrustedHopsXFF:      1,
		})
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

		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		envoyConfigMap := rtest.GetResource(resources, applicationlayer.EnvoyConfigMapName, common.CalicoNamespace, "", "v1", "ConfigMap").(*corev1.ConfigMap)
		envoyConfigMapContents := envoyConfigMap.Data[applicationlayer.EnvoyConfigMapKey]
		Expect(envoyConfigMapContents).To(ContainSubstring("xff_num_trusted_hops: 1"))
		Expect(envoyConfigMapContents).To(ContainSubstring("use_remote_address: true"))
	})

	It("should render with default l7 ALP configuration", func() {
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
			ALPEnabled:   true,
		})
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
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
					CSI: &corev1.CSIVolumeSource{
						Driver: "csi.tigera.io",
					},
				},
			},
			{
				Name: applicationlayer.DikastesSyncVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
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
			{Name: applicationlayer.DikastesSyncVolumeName, MountPath: "/var/run/dikastes"},
		}
		Expect(len(proxyVolMounts)).To(Equal(len(expectedProxyVolMounts)))

		for _, expected := range expectedProxyVolMounts {
			Expect(proxyVolMounts).To(ContainElement(expected))
		}

		dikastesContainer := ds.Spec.Template.Spec.Containers[1]

		dikastesEnvs := dikastesContainer.Env
		expectedDikastesEnvs := []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "Info"},
			{Name: "DIKASTES_SUBSCRIPTION_TYPE", Value: "per-host-policies"},
		}
		Expect(len(dikastesEnvs)).To(Equal(len(expectedDikastesEnvs)))

		for _, element := range expectedDikastesEnvs {
			Expect(dikastesEnvs).To(ContainElement(element))
		}

		dikastesVolMounts := dikastesContainer.VolumeMounts
		expectedDikastesVolMounts := []corev1.VolumeMount{
			{Name: applicationlayer.DikastesSyncVolumeName, MountPath: "/var/run/dikastes"},
			{Name: applicationlayer.FelixSync, MountPath: "/var/run/felix"},
		}
		Expect(len(dikastesVolMounts)).To(Equal(len(expectedDikastesVolMounts)))
		for _, expected := range expectedDikastesVolMounts {
			Expect(dikastesVolMounts).To(ContainElement(expected))
		}
	})
})
