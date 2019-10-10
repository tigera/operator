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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/intstr"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

var (
	openshift    = true
	notOpenshift = false
)

var _ = Describe("Node rendering tests", func() {
	var defaultInstance *operator.Installation

	BeforeEach(func() {
		defaultInstance = &operator.Installation{
			Spec: operator.InstallationSpec{
				IPPools: []operator.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
			},
		}
	})

	It("should render all resources for a default configuration", func() {
		component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico})
		resources := component.Objects()
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		Expect(GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

		cniContainer := GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Node image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("docker.io/calico/node:v3.8.1"))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		// CNI container uses image override.
		Expect(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal("docker.io/calico/cni:v3.8.1"))

		// Verify the Flex volume container image.

		Expect(GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal("docker.io/calico/pod2daemon-flexvol:v3.8.1"))

		optional := true
		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
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
			{
				Name: "NAMESPACE",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.URISAN,
					Optional: &optional,
				},
			}},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

		expectedCNIEnv := []v1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
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
		}
		Expect(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		// Verify volumes.
		var fileOrCreate = v1.HostPathFileOrCreate
		var dirOrCreate = v1.HostPathDirectoryOrCreate
		expectedVols := []v1.Volume{
			{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "policysync", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: v1.VolumeSource{
					ConfigMap: &v1.ConfigMapVolumeSource{
						LocalObjectReference: v1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: v1.VolumeSource{
					Secret: &v1.SecretVolumeSource{
						SecretName: render.FelixTLSSecretName,
					},
				},
			},
			{Name: "flexvol-driver-host", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []v1.VolumeMount{
			{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
			{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "/var/run/nodeagent", Name: "policysync"},
			{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
			{MountPath: "/felix-certs", Name: "felix-certs", ReadOnly: true},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []v1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		expectedTolerations := []v1.Toleration{
			{Operator: "Exists", Effect: "NoSchedule"},
			{Operator: "Exists", Effect: "NoExecute"},
			{Operator: "Exists", Key: "CriticalAddonsOnly"},
		}
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))

		verifyProbes(ds, false)
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise", func() {
		defaultInstance.Spec.Variant = operator.TigeraSecureEnterprise
		component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico})
		resources := component.Objects()
		Expect(len(resources)).To(Equal(6))

		// Should render the correct resources.
		Expect(GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node-metrics", "calico-system", "", "v1", "Service")).ToNot(BeNil())

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("quay.io/tigera/cnx-node:v2.5.0"))
		ExpectEnv(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/etc/cni/net.d")

		optional := true
		expectedNodeEnv := []v1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
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
			{
				Name: "NAMESPACE",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.URISAN,
					Optional: &optional,
				},
			}},
			// Tigera-specific envvars
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, false)
	})

	It("should render all resources when running on openshift", func() {
		component := render.Node(defaultInstance, operator.ProviderOpenShift, render.NetworkConfig{CNI: render.CNICalico})
		resources := component.Objects()
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		Expect(GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("docker.io/calico/node:v3.8.1"))

		ExpectEnv(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/etc/kubernetes/cni/net.d")

		// Verify volumes. In particular, we want to make sure the flexvol-driver-host volume uses the right
		// host path for flexvolume drivers.
		var fileOrCreate = v1.HostPathFileOrCreate
		var dirOrCreate = v1.HostPathDirectoryOrCreate
		expectedVols := []v1.Volume{
			{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/etc/kubernetes/cni/net.d"}}},
			{Name: "policysync", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{Name: "flexvol-driver-host", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/etc/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: v1.VolumeSource{
					ConfigMap: &v1.ConfigMapVolumeSource{
						LocalObjectReference: v1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: v1.VolumeSource{
					Secret: &v1.SecretVolumeSource{
						SecretName: render.FelixTLSSecretName,
					},
				},
			},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		optional := true
		expectedNodeEnv := []v1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
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
			{
				Name: "NAMESPACE",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.URISAN,
					Optional: &optional,
				},
			}},
			// The OpenShift envvar overrides.
			{Name: "FELIX_HEALTHPORT", Value: "9199"},
			{Name: "FELIX_IPTABLESBACKEND", Value: "NFT"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, true)
	})

	It("should render all resources when variant is TigeraSecureEnterprise and running on openshift", func() {
		defaultInstance.Spec.Variant = operator.TigeraSecureEnterprise
		component := render.Node(defaultInstance, operator.ProviderOpenShift, render.NetworkConfig{CNI: render.CNICalico})
		resources := component.Objects()
		Expect(len(resources)).To(Equal(6))

		// Should render the correct resources.
		Expect(GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node-metrics", "calico-system", "", "v1", "Service")).ToNot(BeNil())

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("quay.io/tigera/cnx-node:v2.5.0"))

		ExpectEnv(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/etc/kubernetes/cni/net.d")

		optional := true
		expectedNodeEnv := []v1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
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
			{
				Name: "NAMESPACE",
				ValueFrom: &v1.EnvVarSource{
					FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.URISAN,
					Optional: &optional,
				},
			}},
			// Tigera-specific envvars
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},

			// The OpenShift envvar overrides.
			{Name: "FELIX_HEALTHPORT", Value: "9199"},
			{Name: "FELIX_IPTABLESBACKEND", Value: "NFT"},
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
