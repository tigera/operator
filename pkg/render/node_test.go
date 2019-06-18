// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package render_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/intstr"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

var _ = Describe("Node rendering tests", func() {
	var instance *operator.Installation
	var defaultInstance *operator.Installation

	tolerations := []v1.Toleration{
		{Operator: "Exists", Effect: "PreferNoSchedule"},
		{
			Key:      "somekey",
			Operator: v1.TolerationOpEqual,
			Value:    "somevalue",
			Effect:   v1.TaintEffectNoSchedule,
		},
	}
	nodeVolume := v1.Volume{
		Name: "extravolNode",
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	}
	nodeVolumeMount := v1.VolumeMount{
		Name:      "extravolNode",
		MountPath: "/tmp/calico/testing/node",
	}
	cniVolume := v1.Volume{
		Name: "extravolCNI",
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	}
	cniVolumeMount := v1.VolumeMount{
		Name:      "extravolCNI",
		MountPath: "/tmp/calico/testing/cni",
	}
	// For both node and CNI, override an existing env and add a new one.
	nodeEnv := []v1.EnvVar{
		{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "testing"},
		{Name: "node-env", Value: "node-value"},
	}
	cniEnv := []v1.EnvVar{
		{Name: "CNI_CONF_NAME", Value: "testing"},
		{Name: "cni-env", Value: "cni-value"},
	}
	nodeResources := v1.ResourceRequirements{
		Requests: v1.ResourceList{
			v1.ResourceCPU:    resource.MustParse("1000m"),
			v1.ResourceMemory: resource.MustParse("250Mi"),
		},
		Limits: v1.ResourceList{
			v1.ResourceCPU:    resource.MustParse("1500m"),
			v1.ResourceMemory: resource.MustParse("500Mi"),
		},
	}

	BeforeEach(func() {
		maxUnavailable := intstr.FromInt(2)
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				IPPools: []operator.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Version:   "test",
				Registry:  "test-reg/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
				Datastore: operator.DatastoreConfig{
					Type: operator.Kubernetes,
				},
				Components: operator.ComponentsSpec{
					Node: operator.NodeSpec{
						Image:             "customNodeRegistry/customNodeImage:customNodeVersion",
						MaxUnavailable:    &maxUnavailable,
						ExtraEnv:          nodeEnv,
						ExtraVolumes:      []v1.Volume{nodeVolume},
						ExtraVolumeMounts: []v1.VolumeMount{nodeVolumeMount},
						Tolerations:       tolerations,
						Resources:         nodeResources,
					},
					CNI: operator.CNISpec{
						Image:             "customCNIRegistry/customCNIImage:customCNIVersion",
						ExtraEnv:          cniEnv,
						ExtraVolumes:      []v1.Volume{cniVolume},
						ExtraVolumeMounts: []v1.VolumeMount{cniVolumeMount},
					},
				},
			},
		}

		defaultInstance = &operator.Installation{
			Spec: operator.InstallationSpec{
				IPPools: []operator.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Datastore: operator.DatastoreConfig{
					Type: operator.Kubernetes,
				},
				Version:   "test",
				Registry:  "test-reg/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
			},
		}
	})

	It("should render all resources for a default configuration", func() {
		resources := render.Node(defaultInstance)
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-node", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "cni-config", "calico-system", "", "v1", "ConfigMap")
		ExpectResource(resources[4], "calico-node", "calico-system", "apps", "v1", "DaemonSet")

		// The DaemonSet should have the correct configuration.
		ds := resources[4].(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/calico/node:test"))
		ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")
		ExpectEnv(ds.Spec.Template.Spec.InitContainers[0].Env, "CNI_NET_DIR", "/test/cni/net/dir")
	})

	It("should render all resources for a custom configuration", func() {
		resources := render.Node(instance)
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-node", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "cni-config", "calico-system", "", "v1", "ConfigMap")
		ExpectResource(resources[4], "calico-node", "calico-system", "apps", "v1", "DaemonSet")

		// The DaemonSet should have the correct configuration.
		ds := resources[4].(*apps.DaemonSet)

		// Node image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("customNodeRegistry/customNodeImage:customNodeVersion"))

		// CNI container uses image override.
		Expect(ds.Spec.Template.Spec.InitContainers[0].Image).To(Equal("customCNIRegistry/customCNIImage:customCNIVersion"))

		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,bgp,operator"},
			{Name: "IP", Value: "autodetect"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "FELIX_IPINIPMTU", Value: "1440"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			// Custom env vars.
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "testing"},
			{Name: "node-env", Value: "node-value"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

		expectedCNIEnv := []v1.EnvVar{
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: "/test/cni/net/dir"},
			{
				Name: "CNI_NETWORK_CONFIG",
				ValueFrom: &v1.EnvVarSource{
					ConfigMapKeyRef: &v1.ConfigMapKeySelector{
						Key: "config",
						LocalObjectReference: v1.LocalObjectReference{
							Name: "cni-config",
						},
					},
				},
			},
			// Custom env vars.
			{Name: "CNI_CONF_NAME", Value: "testing"},
			{Name: "cni-env", Value: "cni-value"},
		}
		Expect(ds.Spec.Template.Spec.InitContainers[0].Env).To(ConsistOf(expectedCNIEnv))

		// Verify volumes.
		var fileOrCreate = v1.HostPathFileOrCreate
		expectedVols := []v1.Volume{
			{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/test/cni/bin/dir"}}},
			{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/test/cni/net/dir"}}},
			// Custom volumes
			{Name: "extravolNode", VolumeSource: v1.VolumeSource{EmptyDir: &v1.EmptyDirVolumeSource{}}},
			{Name: "extravolCNI", VolumeSource: v1.VolumeSource{EmptyDir: &v1.EmptyDirVolumeSource{}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []v1.VolumeMount{
			{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
			{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			// Custom volumes
			{MountPath: "/tmp/calico/testing/node", Name: "extravolNode"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []v1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
			// Custom volumes
			{MountPath: "/tmp/calico/testing/cni", Name: "extravolCNI"},
		}
		Expect(ds.Spec.Template.Spec.InitContainers[0].VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify resources.
		Expect(ds.Spec.Template.Spec.Containers[0].Resources).To(Equal(nodeResources))

		// Verify tolerations.
		expectedTolerations := []v1.Toleration{
			{Operator: "Exists", Effect: "NoSchedule"},
			{Operator: "Exists", Effect: "NoExecute"},
			{Operator: "Exists", Key: "CriticalAddonsOnly"},
		}
		expectedTolerations = append(expectedTolerations, tolerations...)
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))

		verifyProbes(ds, false)
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise", func() {
		defaultInstance.Spec.Variant = operator.TigeraSecureEnterprise
		resources := render.Node(defaultInstance)
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-node", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "cni-config", "calico-system", "", "v1", "ConfigMap")
		ExpectResource(resources[4], "calico-node", "calico-system", "apps", "v1", "DaemonSet")

		// The DaemonSet should have the correct configuration.
		ds := resources[4].(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/cnx-node:test"))
		ExpectEnv(ds.Spec.Template.Spec.InitContainers[0].Env, "CNI_NET_DIR", "/test/cni/net/dir")

		expectedNodeEnv := []v1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,bgp,operator"},
			{Name: "IP", Value: "autodetect"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "FELIX_IPINIPMTU", Value: "1440"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			// Tigera-specific envvars
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, false)
	})

	It("should render all resources when OPENSHIFT=true", func() {
		err := os.Setenv("OPENSHIFT", "true")
		Expect(err).To(BeNil())
		defer os.Unsetenv("OPENSHIFT")
		resources := render.Node(defaultInstance)
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-node", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "cni-config", "calico-system", "", "v1", "ConfigMap")
		ExpectResource(resources[4], "calico-node", "calico-system", "apps", "v1", "DaemonSet")

		// The DaemonSet should have the correct configuration.
		ds := resources[4].(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/calico/node:test"))
		ExpectEnv(ds.Spec.Template.Spec.InitContainers[0].Env, "CNI_NET_DIR", "/test/cni/net/dir")

		expectedNodeEnv := []v1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,bgp,operator"},
			{Name: "IP", Value: "autodetect"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "FELIX_IPINIPMTU", Value: "1440"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			// The OpenShift envvar overrides.
			{Name: "FELIX_HEALTHPORT", Value: "9199"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, true)
	})

	It("should render all resources when variant is TigeraSecureEnterprise and OPENSHIFT=true", func() {
		err := os.Setenv("OPENSHIFT", "true")
		Expect(err).To(BeNil())
		defer os.Unsetenv("OPENSHIFT")
		defaultInstance.Spec.Variant = operator.TigeraSecureEnterprise
		resources := render.Node(defaultInstance)
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-node", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "cni-config", "calico-system", "", "v1", "ConfigMap")
		ExpectResource(resources[4], "calico-node", "calico-system", "apps", "v1", "DaemonSet")

		// The DaemonSet should have the correct configuration.
		ds := resources[4].(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("test-reg/tigera/cnx-node:test"))
		ExpectEnv(ds.Spec.Template.Spec.InitContainers[0].Env, "CNI_NET_DIR", "/test/cni/net/dir")

		expectedNodeEnv := []v1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,bgp,operator"},
			{Name: "IP", Value: "autodetect"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "FELIX_IPINIPMTU", Value: "1440"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			// Tigera-specific envvars
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			// The OpenShift envvar overrides.
			{Name: "FELIX_HEALTHPORT", Value: "9199"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, true)
	})
})

// verifyProbes asserts the expected node liveness and readiness probe.
func verifyProbes(ds *apps.DaemonSet, isOpenshift bool) {
	// Verify readiness and liveness probes.
	expectedReadiness := &v1.Probe{Handler: v1.Handler{Exec: &v1.ExecAction{Command: []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}}}}
	expectedLiveness := &v1.Probe{Handler: v1.Handler{
		HTTPGet: &v1.HTTPGetAction{
			Host: "localhost",
			Path: "/liveness",
			Port: intstr.FromInt(9099),
		}}}

	if isOpenshift {
		expectedReadiness.Exec.Command = []string{"/bin/calico-node", "-bird-ready"}
		expectedLiveness.HTTPGet.Port = intstr.FromInt(9199)
	}
	Expect(ds.Spec.Template.Spec.Containers[0].ReadinessProbe).To(Equal(expectedReadiness))
	Expect(ds.Spec.Template.Spec.Containers[0].LivenessProbe).To(Equal(expectedLiveness))
}
