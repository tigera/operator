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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/intstr"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	apps "k8s.io/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

var (
	openshift    = true
	notOpenshift = false
)

var _ = Describe("Node rendering tests", func() {
	var defaultInstance *operator.Installation
	var typhaNodeTLS *render.TyphaNodeTLS
	one := intstr.FromInt(1)

	BeforeEach(func() {
		ff := true
		defaultInstance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools:                    []operator.IPPool{{CIDR: "192.168.1.0/16"}},
					NodeAddressAutodetectionV4: &operator.NodeAddressAutodetection{FirstFound: &ff},
				},
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &one,
					},
				},
			},
		}
		typhaNodeTLS = &render.TyphaNodeTLS{
			CAConfigMap: &v1.ConfigMap{},
			TyphaSecret: &v1.Secret{},
			NodeSecret:  &v1.Secret{},
		}
	})

	It("should render all resources for a default configuration", func() {
		defaultInstance.Spec.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
		resources, _ := component.Objects()
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
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s@%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Digest)))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		// CNI container uses image override.
		Expect(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s@%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Digest)))

		// Verify the Flex volume container image.
		Expect(GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s@%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Digest)))

		optional := true
		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "FELIX_IPINIPMTU", Value: "1440"},
			{Name: "FELIX_VXLANMTU", Value: "1410"},
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
			{Name: "FELIX_IPTABLESBACKEND", Value: "auto"},
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
						SecretName: render.NodeTLSSecretName,
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

		component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
		resources, _ := component.Objects()
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
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node@" + components.ComponentTigeraNode.Digest))
		ExpectEnv(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/etc/cni/net.d")

		optional := true
		expectedNodeEnv := []v1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "FELIX_IPINIPMTU", Value: "1440"},
			{Name: "FELIX_VXLANMTU", Value: "1410"},
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
			{Name: "FELIX_IPTABLESBACKEND", Value: "auto"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, false)
	})

	It("should render all resources when running on openshift", func() {
		defaultInstance.Spec.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
		component := render.Node(defaultInstance, operator.ProviderOpenShift, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
		resources, _ := component.Objects()
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
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s@%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Digest)))

		ExpectEnv(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/var/run/multus/cni/net.d")

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
			{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/multus/cni/net.d"}}},
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
						SecretName: render.NodeTLSSecretName,
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
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "FELIX_IPINIPMTU", Value: "1440"},
			{Name: "FELIX_VXLANMTU", Value: "1410"},
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
			{Name: "FELIX_IPTABLESBACKEND", Value: "auto"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, true)
	})

	It("should render all resources when variant is TigeraSecureEnterprise and running on openshift", func() {
		defaultInstance.Spec.Variant = operator.TigeraSecureEnterprise

		component := render.Node(defaultInstance, operator.ProviderOpenShift, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
		resources, _ := component.Objects()
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
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node@" + components.ComponentTigeraNode.Digest))

		ExpectEnv(GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/var/run/multus/cni/net.d")

		optional := true
		expectedNodeEnv := []v1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "FELIX_IPINIPMTU", Value: "1440"},
			{Name: "FELIX_VXLANMTU", Value: "1410"},
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
			{Name: "FELIX_IPTABLESBACKEND", Value: "auto"},
			{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, true)
	})

	It("should render volumes and node volumemounts when bird templates are provided", func() {
		bt := map[string]string{
			"template-1.yaml": "dataforTemplate1 that is not used here",
		}
		component := render.Node(defaultInstance, operator.ProviderOpenShift, render.NetworkConfig{CNI: render.CNICalico}, bt, typhaNodeTLS, false)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(6))

		// Should render the correct resources.
		Expect(GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())
		Expect(GetResource(resources, "bird-templates", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		volumes := ds.Spec.Template.Spec.Volumes
		//Expect(ds.Spec.Template.Spec.Volumes).To(Equal())
		Expect(volumes).To(ContainElement(
			v1.Volume{
				Name: "bird-templates",
				VolumeSource: v1.VolumeSource{
					ConfigMap: &v1.ConfigMapVolumeSource{
						LocalObjectReference: v1.LocalObjectReference{
							Name: "bird-templates",
						},
					},
				},
			}))

		volumeMounts := ds.Spec.Template.Spec.Containers[0].VolumeMounts
		Expect(volumeMounts).To(ContainElement(
			v1.VolumeMount{
				Name:      "bird-templates",
				ReadOnly:  true,
				MountPath: "/etc/calico/confd/templates/template-1.yaml",
				SubPath:   "template-1.yaml",
			}))
	})

	Describe("test IP auto detection", func() {
		It("should support canReach", func() {
			defaultInstance.Spec.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.Spec.CalicoNetwork.NodeAddressAutodetectionV4.CanReach = "1.1.1.1"
			component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(5))

			dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "can-reach=1.1.1.1")
		})

		It("should support interface regex", func() {
			defaultInstance.Spec.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.Spec.CalicoNetwork.NodeAddressAutodetectionV4.Interface = "eth*"
			component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(5))

			dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "interface=eth*")
		})

		It("should support skip-interface regex", func() {
			defaultInstance.Spec.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.Spec.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface = "eth*"
			component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(5))

			dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "skip-interface=eth*")
		})
	})

	It("should include updates needed for the core upgrade", func() {
		component := render.Node(defaultInstance, operator.ProviderOpenShift, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, true)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(5), fmt.Sprintf("resources are %v", resources))

		// Should render the correct resources.
		Expect(GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())

		crbResource := GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		Expect(crbResource).ToNot(BeNil())
		crb := crbResource.(*rbacv1.ClusterRoleBinding)
		Expect(crb.Subjects).To(ContainElement(
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "calico-node",
				Namespace: "kube-system",
			},
		))

		Expect(GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		ns := ds.Spec.Template.Spec.NodeSelector
		Expect(ns).To(HaveKey("projectcalico.org/operator-node-migration"))
		Expect(ns["projectcalico.org/operator-node-migration"]).To(Equal("migrated"))
	})

	DescribeTable("test IP Pool configuration",
		func(pool operator.IPPool, expect map[string]string) {
			// Provider does not matter for IPPool configuration
			defaultInstance.Spec.CalicoNetwork.IPPools = []operator.IPPool{pool}
			component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(5))

			dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			nodeEnvs := ds.Spec.Template.Spec.Containers[0].Env

			for _, envVar := range []string{
				"CALICO_IPV4POOL_CIDR",
				"CALICO_IPV4POOL_IPIP",
				"CALICO_IPV4POOL_VXLAN",
				"CALICO_IPV4POOL_NAT_OUTGOING",
				"CALICO_IPV4POOL_NODE_SELECTOR",
			} {
				v, ok := expect[envVar]
				if ok {
					Expect(nodeEnvs).To(ContainElement(v1.EnvVar{Name: envVar, Value: v}))
				} else {
					found := false
					for _, ev := range nodeEnvs {
						if ev.Name == envVar {
							found = true
							break
						}
					}
					Expect(found).To(BeFalse(), "Expected EnvVars %v to not have %s", nodeEnvs, envVar)
				}
			}
		},

		Entry("Default pool",
			operator.IPPool{
				CIDR: "192.168.0.0/16",
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR": "192.168.0.0/16",
				"CALICO_IPV4POOL_IPIP": "Always",
			}),
		Entry("Pool with nat outgoing disabled",
			operator.IPPool{
				CIDR:        "172.16.0.0/24",
				NATOutgoing: "Disabled",
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":         "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP":         "Always",
				"CALICO_IPV4POOL_NAT_OUTGOING": "false",
			}),
		Entry("Pool with nat outgoing enabled",
			operator.IPPool{
				CIDR:        "172.16.0.0/24",
				NATOutgoing: "Enabled",
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR": "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP": "Always",
				// Enabled is the default so we don't set
				// NAT_OUTGOING if it is enabled.
			}),
		Entry("Pool with CrossSubnet",
			operator.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operator.EncapsulationIPIPCrossSubnet,
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR": "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP": "CrossSubnet",
			}),
		Entry("Pool with VXLAN",
			operator.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operator.EncapsulationVXLAN,
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":  "172.16.0.0/24",
				"CALICO_IPV4POOL_VXLAN": "Always",
			}),
		Entry("Pool with VXLANCrossSubnet",
			operator.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operator.EncapsulationVXLANCrossSubnet,
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":  "172.16.0.0/24",
				"CALICO_IPV4POOL_VXLAN": "CrossSubnet",
			}),
		Entry("Pool with no encapsulation",
			operator.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operator.EncapsulationNone,
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR": "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP": "Never",
			}),
		Entry("Pool with node selector",
			operator.IPPool{
				CIDR:         "172.16.0.0/24",
				NodeSelector: "has(thiskey)",
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":          "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP":          "Always",
				"CALICO_IPV4POOL_NODE_SELECTOR": "has(thiskey)",
			}),
		Entry("Pool with all fields set",
			operator.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operator.EncapsulationIPIP,
				NATOutgoing:   "Disabled",
				NodeSelector:  "has(thiskey)",
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":          "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP":          "Always",
				"CALICO_IPV4POOL_NAT_OUTGOING":  "false",
				"CALICO_IPV4POOL_NODE_SELECTOR": "has(thiskey)",
			}),
	)

	It("should not enable prometheus metrics if NodeMetricsPort is nil", func() {
		defaultInstance.Spec.Variant = operator.TigeraSecureEnterprise
		defaultInstance.Spec.NodeMetricsPort = nil
		component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(6))

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		notExpectedEnvVar := v1.EnvVar{Name: "FELIX_PROMETHEUSMETRICSPORT"}
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(notExpectedEnvVar))

		// It should have the reporter port, though.
		expected := v1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERPORT"}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(expected))
	})

	It("should set FELIX_PROMETHEUSMETRICSPORT with a custom value if NodeMetricsPort is set", func() {
		var nodeMetricsPort int32 = 1234
		defaultInstance.Spec.Variant = operator.TigeraSecureEnterprise
		defaultInstance.Spec.NodeMetricsPort = &nodeMetricsPort
		component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(6))

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Assert on expected env vars.
		expectedEnvVars := []v1.EnvVar{
			{Name: "FELIX_PROMETHEUSMETRICSPORT", Value: "1234"},
			{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
		}
		ds := dsResource.(*apps.DaemonSet)
		for _, v := range expectedEnvVars {
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(v))
		}

		// Assert we set annotations properly.
		Expect(ds.Spec.Template.Annotations["prometheus.io/scrape"]).To(Equal("true"))
		Expect(ds.Spec.Template.Annotations["prometheus.io/port"]).To(Equal("1234"))
	})

	It("should not render a FlexVolume container if FlexVolumePath is set to None", func() {
		defaultInstance.Spec.FlexVolumePath = "None"
		component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(5))

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds).ToNot(BeNil())
		Expect(GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")).To(BeNil())
	})

	It("should render MaxUnavailable if a custom value was set", func() {
		two := intstr.FromInt(2)
		defaultInstance.Spec.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &two
		component := render.Node(defaultInstance, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico}, nil, typhaNodeTLS, false)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(5))

		dsResource := GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds).ToNot(BeNil())

		Expect(ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable).To(Equal(&two))
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
