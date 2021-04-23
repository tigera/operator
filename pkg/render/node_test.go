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
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	apps "k8s.io/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var (
	openshift    = true
	notOpenshift = false
	bgpEnabled   = operator.BGPEnabled
)

var _ = Describe("Node rendering tests", func() {
	var defaultInstance *operator.InstallationSpec
	var typhaNodeTLS *render.TyphaNodeTLS
	var k8sServiceEp k8sapi.ServiceEndpoint
	one := intstr.FromInt(1)
	defaultNumExpectedResources := 6
	const defaultClusterDomain = "svc.cluster.local"
	var defaultMode int32 = 420

	BeforeEach(func() {
		ff := true
		hp := operator.HostPortsEnabled
		miMode := operator.MultiInterfaceModeNone
		defaultInstance = &operator.InstallationSpec{
			CNI: &operator.CNISpec{
				Type: "Calico",
				IPAM: &operator.IPAMSpec{Type: "Calico"},
			},
			CalicoNetwork: &operator.CalicoNetworkSpec{
				BGP:                        &bgpEnabled,
				IPPools:                    []operator.IPPool{{CIDR: "192.168.1.0/16"}},
				NodeAddressAutodetectionV4: &operator.NodeAddressAutodetection{FirstFound: &ff},
				HostPorts:                  &hp,
				MultiInterfaceMode:         &miMode,
			},
			NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &one,
				},
			},
		}
		typhaNodeTLS = &render.TyphaNodeTLS{
			CAConfigMap: &v1.ConfigMap{},
			TyphaSecret: &v1.Secret{},
			NodeSecret:  &v1.Secret{},
		}
		k8sServiceEp = k8sapi.ServiceEndpoint{}
	})

	It("should render all resources for a default configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "true",
          "assign_ipv6" : "false"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Node image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		// CNI container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

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
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

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
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

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
			{Name: "cni-log-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
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
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
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
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: true},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []v1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		verifyProbes(ds, false, false)
	})

	It("should render node correctly for BPF dataplane", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		dpBPF := operator.LinuxDataplaneBPF
		defaultInstance.CalicoNetwork.LinuxDataplane = &dpBPF
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
        "type": "calico-ipam",
        "assign_ipv4": "true",
        "assign_ipv6": "false"
      },
      "container_settings": {
        "allow_ip_forwarding": false
      },
      "policy": {
        "type": "k8s"
      },
      "kubernetes": {
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {
        "bandwidth": true
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}`))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Node image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		// CNI container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

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
			{Name: "FELIX_BPFENABLED", Value: "true"},
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
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

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
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		// Verify volumes.
		var fileOrCreate = v1.HostPathFileOrCreate
		var dirOrCreate = v1.HostPathDirectoryOrCreate
		var dirMustExist = v1.HostPathDirectory
		expectedVols := []v1.Volume{
			{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
			{Name: "bpffs", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
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
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
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
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: true},
			{MountPath: "/sys/fs/bpf", Name: "bpffs"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []v1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		verifyProbes(ds, false, false)
	})

	It("should properly render an explicitly configured MTU", func() {
		mtu := int32(1450)
		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.CalicoNetwork.MTU = &mtu
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Make sure the configmap is populated correctly with the MTU.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 1450,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "true",
          "assign_ipv6" : "false"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))

		// Make sure daemonset has the MTU set as well.
		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*apps.DaemonSet)

		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "FELIX_IPINIPMTU", Value: "1450"},
			{Name: "FELIX_VXLANMTU", Value: "1450"},
			{Name: "FELIX_WIREGUARDMTU", Value: "1450"},
		}
		for _, e := range expectedNodeEnv {
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(e))
		}
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}
		defaultInstance.Variant = operator.TigeraSecureEnterprise

		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 9081)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The DaemonSet should have the correct configuration.
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node:" + components.ComponentTigeraNode.Version))
		rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/etc/cni/net.d")

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
			{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
			{Name: "MULTI_INTERFACE_MODE", Value: operator.MultiInterfaceModeNone.Value()},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, false, true)
	})

	It("should render all resources when using Calico CNI on EKS", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		disabled := operator.BGPDisabled
		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operator.ProviderEKS
		defaultInstance.CalicoNetwork.BGP = &disabled
		defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operator.EncapsulationVXLAN
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "true",
          "assign_ipv6" : "false"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Node image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		// CNI container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		optional := true
		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_VXLAN", Value: "Always"},
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
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

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
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

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
			{Name: "cni-log-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
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
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
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
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: true},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []v1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.

		verifyProbes(ds, false, false)
	})

	It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
		amazonVPCInstalllation := &operator.InstallationSpec{
			KubernetesProvider: operator.ProviderEKS,
			CNI:                &operator.CNISpec{Type: operator.PluginAmazonVPC},
			FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
		}

		component := render.Node(k8sServiceEp, amazonVPCInstalllation, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Should not render CNI configuration.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).To(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)

		// CNI install container should not be present.
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer).To(BeNil())

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		optional := true

		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
			{Name: "IP", Value: "none"},
			{Name: "IP6", Value: "none"},
			{Name: "NO_DEFAULT_POOLS", Value: "true"},
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
			{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
			{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
			{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"},
			{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		// Verify volumes.
		var fileOrCreate = v1.HostPathFileOrCreate
		var dirOrCreate = v1.HostPathDirectoryOrCreate
		expectedVols := []v1.Volume{
			{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
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
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
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

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.
		verifyProbes(ds, false, true)
	})

	DescribeTable("should properly render configuration using non-Calico CNI plugin",
		func(cni operator.CNIPluginType, ipam operator.IPAMPluginType, expectedEnvs []v1.EnvVar) {
			installlation := &operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: cni,
					IPAM: &operator.IPAMSpec{Type: ipam},
				},
				FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
			}

			component := render.Node(k8sServiceEp, installlation, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			// Should render the correct resources.
			Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// Should not render CNI configuration.
			cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
			Expect(cniCmResource).To(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)

			// CNI install container should not be present.
			cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
			Expect(cniContainer).To(BeNil())
			// Validate correct number of init containers.
			Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

			// Verify env
			expectedEnvs = append(expectedEnvs,
				v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
				v1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"},
				v1.EnvVar{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			)
			for _, expected := range expectedEnvs {
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(expected))
			}

			// Verify readiness and liveness probes.
			verifyProbes(ds, false, false)
		},
		Entry("GKE", operator.PluginGKE, operator.IPAMPluginHostLocal, []v1.EnvVar{
			{Name: "FELIX_INTERFACEPREFIX", Value: "gke"},
			{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
			{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"},
			{Name: "FELIX_ROUTETABLERANGE", Value: "10-250"},
		}),
		Entry("AmazonVPC", operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC, []v1.EnvVar{
			{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
			{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
		}),
		Entry("AzureVNET", operator.PluginAzureVNET, operator.IPAMPluginAzureVNET, []v1.EnvVar{
			{Name: "FELIX_INTERFACEPREFIX", Value: "azv"},
		}),
	)
	It("should render all resources when using Calico CNI on EKS", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		disabled := operator.BGPDisabled
		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operator.ProviderEKS
		defaultInstance.CalicoNetwork.BGP = &disabled
		defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operator.EncapsulationVXLAN
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "true",
          "assign_ipv6" : "false"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Node image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		// CNI container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		optional := true
		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_VXLAN", Value: "Always"},
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
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

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
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

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
			{Name: "cni-log-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
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
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
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
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: true},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []v1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.
		verifyProbes(ds, false, false)
	})

	It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
		amazonVPCInstalllation := &operator.InstallationSpec{
			KubernetesProvider: operator.ProviderEKS,
			CNI:                &operator.CNISpec{Type: operator.PluginAmazonVPC},
			FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
		}

		component := render.Node(k8sServiceEp, amazonVPCInstalllation, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(5))

		// Should render the correct resources.
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Should not render CNI configuration.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).To(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)

		// CNI install container should not be present.
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer).To(BeNil())

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		optional := true

		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
			{Name: "IP", Value: "none"},
			{Name: "IP6", Value: "none"},
			{Name: "NO_DEFAULT_POOLS", Value: "true"},
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
			{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
			{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
			{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"},
			{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		// Verify volumes.
		var fileOrCreate = v1.HostPathFileOrCreate
		var dirOrCreate = v1.HostPathDirectoryOrCreate
		expectedVols := []v1.Volume{
			{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
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
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
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

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.
		verifyProbes(ds, false, false)
	})

	It("should render all resources when running on openshift", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operator.ProviderOpenShift
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The DaemonSet should have the correct configuration.
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

		rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/var/run/multus/cni/net.d")

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
			{Name: "cni-log-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
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
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
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
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, true, false)
	})

	It("should render all resources when variant is TigeraSecureEnterprise and running on openshift", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.Variant = operator.TigeraSecureEnterprise
		defaultInstance.KubernetesProvider = operator.ProviderOpenShift
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 9081)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The DaemonSet should have the correct configuration.
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node:" + components.ComponentTigeraNode.Version))

		rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/var/run/multus/cni/net.d")

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
			{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},

			// The OpenShift envvar overrides.
			{Name: "FELIX_HEALTHPORT", Value: "9199"},
			{Name: "MULTI_INTERFACE_MODE", Value: operator.MultiInterfaceModeNone.Value()},
			{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbes(ds, true, true)
	})

	It("should render volumes and node volumemounts when bird templates are provided", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: render.BirdTemplatesConfigMapName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		bt := map[string]string{
			"template-1.yaml": "dataforTemplate1 that is not used here",
		}
		defaultInstance.KubernetesProvider = operator.ProviderOpenShift
		component := render.Node(k8sServiceEp, defaultInstance, bt, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// The DaemonSet should have the correct configuration.
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		volumes := ds.Spec.Template.Spec.Volumes
		// Expect(ds.Spec.Template.Spec.Volumes).To(Equal())
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

	Describe("AKS", func() {
		It("should avoid virtual nodes", func() {
			defaultInstance.KubernetesProvider = operator.ProviderAKS
			component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			Expect(ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms).To(ContainElement(
				v1.NodeSelectorTerm{
					MatchExpressions: []v1.NodeSelectorRequirement{{
						Key:      "type",
						Operator: v1.NodeSelectorOpNotIn,
						Values:   []string{"virtual-kubelet"},
					}},
				},
			))
		})
	})
	Describe("test IP auto detection", func() {
		It("should support canReach", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.CanReach = "1.1.1.1"
			component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "can-reach=1.1.1.1")
		})

		It("should support interface regex", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.Interface = "eth*"
			component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "interface=eth*")
		})

		It("should support skip-interface regex", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface = "eth*"
			component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "skip-interface=eth*")
		})

		It("should support cidr", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.CIDRS = []string{"10.0.1.0/24", "10.0.2.0/24"}
			component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*apps.DaemonSet)
			rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "cidr=10.0.1.0/24,10.0.2.0/24")
		})

	})

	It("should include updates needed for the core upgrade", func() {
		defaultInstance.KubernetesProvider = operator.ProviderOpenShift
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, true, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources-1), fmt.Sprintf("resources are %v", resources))

		// Should render the correct resources.
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())

		crbResource := rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		Expect(crbResource).ToNot(BeNil())
		crb := crbResource.(*rbacv1.ClusterRoleBinding)
		Expect(crb.Subjects).To(ContainElement(
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "calico-node",
				Namespace: "kube-system",
			},
		))

		Expect(rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
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
			defaultInstance.CalicoNetwork.IPPools = []operator.IPPool{pool}
			component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
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
		Entry("Pool with nat outgoing disabled (IPv6)",
			operator.IPPool{
				CIDR:        "fc00::/48",
				NATOutgoing: "Disabled",
			},
			map[string]string{
				"CALICO_IPV6POOL_CIDR": "fc00::/48",
				// Disabled is the default so we don't set
				// NAT_OUTGOING if it is disabled.
			}),
		Entry("Pool with nat outgoing enabled (IPv6)",
			operator.IPPool{
				CIDR:        "fc00::/48",
				NATOutgoing: "Enabled",
			},
			map[string]string{
				"CALICO_IPV6POOL_CIDR":         "fc00::/48",
				"CALICO_IPV6POOL_NAT_OUTGOING": "true",
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
		defaultInstance.Variant = operator.TigeraSecureEnterprise
		defaultInstance.NodeMetricsPort = nil
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
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
		defaultInstance.Variant = operator.TigeraSecureEnterprise
		defaultInstance.NodeMetricsPort = &nodeMetricsPort
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
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
		defaultInstance.FlexVolumePath = "None"
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds).ToNot(BeNil())
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")).To(BeNil())
	})

	It("should render MaxUnavailable if a custom value was set", func() {
		two := intstr.FromInt(2)
		defaultInstance.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &two
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds).ToNot(BeNil())

		Expect(ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable).To(Equal(&two))
	})

	It("should render cni config without portmap when HostPorts disabled", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		hpd := operator.HostPortsDisabled
		defaultInstance.CalicoNetwork.HostPorts = &hpd
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "true",
          "assign_ipv6" : "false"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    }
  ]
}`))

		// The DaemonSet should have the correct configuration.
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*apps.DaemonSet)

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

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
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		Expect(ds.Spec.Template.Spec.Volumes).To(ContainElement(
			v1.Volume{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}}))

		expectedCNIVolumeMounts := []v1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))
	})

	It("should render a proper 'allow_ip_forwarding' container setting in the cni config", func() {
		cif := operator.ContainerIPForwardingEnabled
		defaultInstance.CalicoNetwork.ContainerIPForwarding = &cif
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		// Should render the correct resources.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
          "type": "calico-ipam",
          "assign_ipv4" : "true",
          "assign_ipv6" : "false"
      },
      "container_settings": {
          "allow_ip_forwarding": true
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))
	})

	It("should render cni config with host-local", func() {
		defaultInstance.CNI.IPAM.Type = operator.IPAMPluginHostLocal
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		// Should render the correct resources.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
          "type": "host-local",
          "subnet" : "usePodCidr"
      },
      "container_settings": { "allow_ip_forwarding": false },
      "policy": { "type": "k8s" },
      "kubernetes": { "kubeconfig": "__KUBECONFIG_FILEPATH__" }
    },
    {"type": "bandwidth", "capabilities": {"bandwidth": true}},
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))
	})

	It("should render cni config with k8s endpoint", func() {
		k8sServiceEp.Host = "k8shost"
		k8sServiceEp.Port = "1234"
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		// Should render the correct resources.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
        "type": "calico-ipam",
        "assign_ipv4": "true",
        "assign_ipv6": "false"
      },
      "container_settings": {
        "allow_ip_forwarding": false
      },
      "policy": {
        "type": "k8s"
      },
      "kubernetes": {
        "k8s_api_root": "https://k8shost:1234",
        "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {
        "bandwidth": true
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}`))
	})

	It("should render seccomp profiles", func() {
		seccompProf := "localhost/calico-node-v1"
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, seccompProf, defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*apps.DaemonSet)
		Expect(ds).ToNot(BeNil())

		Expect(ds.Spec.Template.Annotations["container.apparmor.security.beta.kubernetes.io/calico-node"]).To(Equal(seccompProf))
	})

	It("should set TIGERA_*_SECURITY_GROUP variables when AmazonCloudIntegration is defined", func() {
		aci := &operator.AmazonCloudIntegration{
			Spec: operator.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIDs: []string{"sg-nodeid", "sg-masterid"},
				PodSecurityGroupID:   "sg-podsgid",
			},
		}
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, aci, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Assert on expected env vars.
		expectedEnvVars := []v1.EnvVar{
			{Name: "TIGERA_DEFAULT_SECURITY_GROUPS", Value: "sg-nodeid,sg-masterid"},
			{Name: "TIGERA_POD_SECURITY_GROUP", Value: "sg-podsgid"},
		}
		ds := dsResource.(*apps.DaemonSet)
		for _, v := range expectedEnvVars {
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(v))
		}
	})

	It("should render resourcerequirements", func() {
		rr := &v1.ResourceRequirements{
			Requests: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("250m"),
				v1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("500m"),
				v1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		defaultInstance.ComponentResources = []operator.ComponentResource{
			{
				ComponentName:        operator.ComponentNameNode,
				ResourceRequirements: rr,
			},
		}

		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*apps.DaemonSet)

		passed := false
		for _, container := range ds.Spec.Template.Spec.Containers {
			if container.Name == "calico-node" {
				Expect(container.Resources).To(Equal(*rr))
				passed = true
			}
		}
		Expect(passed).To(Equal(true))
	})

	It("should render when configured to use cloude routes with host-local", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		disabled := operator.BGPDisabled
		defaultInstance.CalicoNetwork.BGP = &disabled
		defaultInstance.CNI.Type = operator.PluginCalico
		defaultInstance.CNI.IPAM.Type = operator.IPAMPluginHostLocal
		defaultInstance.CalicoNetwork.IPPools = []operator.IPPool{{
			CIDR:          "192.168.1.0/16",
			Encapsulation: operator.EncapsulationNone,
			NATOutgoing:   operator.NATOutgoingEnabled,
		}}
		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*v1.ConfigMap)
		Expect(cniCm.Data["config"]).To(MatchJSON(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 0,
      "nodename_file_optional": false,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": {
          "type": "host-local",
		  "subnet": "usePodCidr"
      },
      "container_settings": {
          "allow_ip_forwarding": false
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}
  ]
}`))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*apps.DaemonSet)
		rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Node image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		// CNI container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		optional := true
		// Verify env
		expectedNodeEnv := []v1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Never"},
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
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		// Verify readiness and liveness probes.
		verifyProbes(ds, false, false)
	})

	DescribeTable("test node probes",
		func(isOpenshift, isEnterprise bool, bgpOption operator.BGPOption) {
			if isOpenshift {
				defaultInstance.KubernetesProvider = operator.ProviderOpenShift
			}

			if isEnterprise {
				defaultInstance.Variant = operator.TigeraSecureEnterprise
			}

			defaultInstance.CalicoNetwork.BGP = &bgpOption

			component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			ds := dsResource.(*apps.DaemonSet)
			verifyProbes(ds, isOpenshift, isEnterprise)
		},

		Entry("k8s Calico OS no BGP", false, false, operator.BGPDisabled),
		Entry("k8s Calico OS w/ BGP", false, false, operator.BGPEnabled),
		Entry("k8s Enterprise no BGP", false, true, operator.BGPDisabled),
		Entry("k8s Enterprise w/ BGP", false, true, operator.BGPEnabled),
		Entry("OCP Calico OS no BGP", true, false, operator.BGPDisabled),
		Entry("OCP Calico OSS w/ BGP", true, false, operator.BGPEnabled),
		Entry("OCP Enterprise no BGP", true, true, operator.BGPDisabled),
		Entry("OCP Enterprise w/ BGP", true, true, operator.BGPEnabled),
	)

	Context("with k8s overrides set", func() {
		It("should override k8s endpoints", func() {
			k8sServiceEp := k8sapi.ServiceEndpoint{
				Host: "k8shost",
				Port: "1234",
			}
			component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			ds := dsResource.(*apps.DaemonSet)

			// FIXME update gomega to include ContainElements
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
				v1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "k8shost"},
			))
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
				v1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "1234"},
			))

			var cni v1.Container

			for _, c := range ds.Spec.Template.Spec.InitContainers {
				if c.Name == "install-cni" {
					cni = c
					break
				}
			}
			Expect(cni).NotTo(BeNil())

			Expect(cni.Env).To(ContainElement(
				v1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "k8shost"},
			))
			Expect(cni.Env).To(ContainElement(
				v1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "1234"},
			))
		})
	})

	It("should render extra resources when certificate management is enabled", func() {
		defaultInstance.CertificateManagement = &operator.CertificateManagement{CACert: []byte("<ca>"), SignerName: "a.b/c"}
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "calico-node", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: render.CSRClusterRoleName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node:csr-creator", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component := render.Node(k8sServiceEp, defaultInstance, nil, typhaNodeTLS, nil, false, "", defaultClusterDomain, 0)
		resources, _ := component.Objects()

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dep := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
		Expect(dep).ToNot(BeNil())
		deploy, ok := dep.(*appsv1.DaemonSet)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(3))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].Name).To(Equal(render.CSRInitContainerName))
		Expect(deploy.Spec.Template.Spec.InitContainers[1].Name).To(Equal("flexvol-driver"))
		Expect(deploy.Spec.Template.Spec.InitContainers[2].Name).To(Equal("install-cni"))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].Name).To(Equal(render.CSRInitContainerName))
		rtest.ExpectEnv(deploy.Spec.Template.Spec.InitContainers[0].Env, "SIGNER", "a.b/c")
	})
})

// verifyProbes asserts the expected node liveness and readiness probe.
func verifyProbes(ds *apps.DaemonSet, isOpenshift, isEnterprise bool) {
	// Verify readiness and liveness probes.
	expectedReadiness := &v1.Probe{Handler: v1.Handler{Exec: &v1.ExecAction{Command: []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}}}}
	expectedLiveness := &v1.Probe{Handler: v1.Handler{
		HTTPGet: &v1.HTTPGetAction{
			Host: "localhost",
			Path: "/liveness",
			Port: intstr.FromInt(9099),
		}}}

	if isOpenshift {
		expectedLiveness.HTTPGet.Port = intstr.FromInt(9199)
	}

	var found bool
	var bgp bool
	for _, env := range ds.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "CLUSTER_TYPE" {
			if strings.Contains(env.Value, ",bgp") {
				bgp = true
			}
			found = true
			break
		}
	}
	Expect(found).To(BeTrue())

	switch {
	case !bgp:
		expectedReadiness.Exec.Command = []string{"/bin/calico-node", "-felix-ready"}
	case bgp && !isEnterprise:
		expectedReadiness.Exec.Command = []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}
	case bgp && isEnterprise:
		expectedReadiness.Exec.Command = []string{"/bin/calico-node", "-bird-ready", "-felix-ready", "-bgp-metrics-ready"}
	}

	Expect(ds.Spec.Template.Spec.Containers[0].ReadinessProbe).To(Equal(expectedReadiness))
	Expect(ds.Spec.Template.Spec.Containers[0].LivenessProbe).To(Equal(expectedLiveness))
}
