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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var (
	openshift            = true
	notOpenshift         = false
	bgpEnabled           = operatorv1.BGPEnabled
	bgpDisabled          = operatorv1.BGPDisabled
	nonPrivilegedEnabled = operatorv1.NonPrivilegedEnabled
)

var _ = Describe("Node rendering tests", func() {
	var defaultInstance *operatorv1.InstallationSpec
	var typhaNodeTLS *render.TyphaNodeTLS
	var k8sServiceEp k8sapi.ServiceEndpoint
	one := intstr.FromInt(1)
	defaultNumExpectedResources := 8
	const defaultClusterDomain = "svc.cluster.local"
	var defaultMode int32 = 420
	var cfg render.NodeConfiguration

	BeforeEach(func() {
		ff := true
		hp := operatorv1.HostPortsEnabled
		miMode := operatorv1.MultiInterfaceModeNone
		defaultInstance = &operatorv1.InstallationSpec{
			CNI: &operatorv1.CNISpec{
				Type: "Calico",
				IPAM: &operatorv1.IPAMSpec{Type: "Calico"},
			},
			CalicoNetwork: &operatorv1.CalicoNetworkSpec{
				BGP:                        &bgpEnabled,
				IPPools:                    []operatorv1.IPPool{{CIDR: "192.168.1.0/16"}},
				NodeAddressAutodetectionV4: &operatorv1.NodeAddressAutodetection{FirstFound: &ff},
				HostPorts:                  &hp,
				MultiInterfaceMode:         &miMode,
			},
			NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &one,
				},
			},
		}

		// Create a dummy secret to pass as input.
		typhaNodeTLS = &render.TyphaNodeTLS{
			CAConfigMap: &corev1.ConfigMap{},
			TyphaSecret: &corev1.Secret{},
			NodeSecret:  &corev1.Secret{},
		}
		typhaNodeTLS.NodeSecret.Name = "node-certs"
		typhaNodeTLS.NodeSecret.Namespace = "tigera-operator"
		typhaNodeTLS.NodeSecret.Kind = "Secret"
		typhaNodeTLS.NodeSecret.APIVersion = "v1"

		typhaNodeTLS.CAConfigMap.Name = "typha-node-ca"
		typhaNodeTLS.CAConfigMap.Namespace = "tigera-operator"
		typhaNodeTLS.CAConfigMap.Kind = "ConfigMap"
		typhaNodeTLS.CAConfigMap.APIVersion = "v1"

		// Dummy service endpoint for k8s API.
		k8sServiceEp = k8sapi.ServiceEndpoint{}

		// Create a default configuration.
		cfg = render.NodeConfiguration{
			K8sServiceEp:  k8sServiceEp,
			Installation:  defaultInstance,
			TLS:           typhaNodeTLS,
			ClusterDomain: defaultClusterDomain,
		}
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		component := render.Node(&cfg)
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
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		ds := dsResource.(*appsv1.DaemonSet)
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
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
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
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
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

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{
				Name: "CNI_NETWORK_CONFIG",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						Key: "config",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "cni-config",
						},
					},
				},
			},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		// Verify volumes.
		var fileOrCreate = corev1.HostPathFileOrCreate
		var dirOrCreate = corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
			{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
			{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "/var/run/nodeagent", Name: "policysync"},
			{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
			{MountPath: "/felix-certs", Name: "felix-certs", ReadOnly: true},
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		verifyProbesAndLifecycle(ds, false, false)
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		dpBPF := operatorv1.LinuxDataplaneBPF
		defaultInstance.CalicoNetwork.LinuxDataplane = &dpBPF
		component := render.Node(&cfg)
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
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		ds := dsResource.(*appsv1.DaemonSet)
		rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "CALICO_IPV4POOL_CIDR", "192.168.1.0/16")

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Node image override results in correct image.
		calicoNodeImage := fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(calicoNodeImage))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(3))

		// CNI container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		// Verify the mount-bpffs image and command.
		mountBpffs := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "mount-bpffs")
		Expect(mountBpffs.Image).To(Equal(calicoNodeImage))
		Expect(mountBpffs.Command).To(Equal([]string{"calico-node", "-init"}))

		optional := true
		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
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
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
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

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{
				Name: "CNI_NETWORK_CONFIG",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						Key: "config",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "cni-config",
						},
					},
				},
			},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		// Verify volumes.
		var fileOrCreate = corev1.HostPathFileOrCreate
		var dirOrCreate = corev1.HostPathDirectoryOrCreate
		var dirMustExist = corev1.HostPathDirectory
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
			{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
			{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
			{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
			{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "/var/run/nodeagent", Name: "policysync"},
			{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
			{MountPath: "/felix-certs", Name: "felix-certs", ReadOnly: true},
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
			{MountPath: "/sys/fs/bpf", Name: "bpffs"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		verifyProbesAndLifecycle(ds, false, false)
	})

	It("should properly render an explicitly configured MTU", func() {
		mtu := int32(1450)
		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.CalicoNetwork.MTU = &mtu

		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Make sure the configmap is populated correctly with the MTU.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		ds := dsResource.(*appsv1.DaemonSet)

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}
		defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
		cfg.NodeReporterMetricsPort = 9081

		component := render.Node(&cfg)
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
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node:" + components.ComponentTigeraNode.Version))
		rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/etc/cni/net.d")

		optional := true
		expectedNodeEnv := []corev1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,bgp"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
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
			{Name: "MULTI_INTERFACE_MODE", Value: operatorv1.MultiInterfaceModeNone.Value()},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbesAndLifecycle(ds, false, true)
	})

	It("should render all resources with the appropriate permissions when running as non-privileged", func() {
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.NonPrivileged = &nonPrivilegedEnabled
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// The DaemonSet should have the correct security context.
		ds := dsResource.(*appsv1.DaemonSet)
		nodeContainer := rtest.GetContainer(ds.Spec.Template.Spec.Containers, "calico-node")
		Expect(nodeContainer).ToNot(BeNil())
		Expect(nodeContainer.SecurityContext).ToNot(BeNil())
		Expect(nodeContainer.SecurityContext.RunAsUser).ToNot(BeNil())
		Expect(*nodeContainer.SecurityContext.RunAsUser).To(Equal(int64(999)))
		Expect(nodeContainer.SecurityContext.RunAsGroup).ToNot(BeNil())
		Expect(*nodeContainer.SecurityContext.RunAsGroup).To(Equal(int64(0)))
		Expect(*nodeContainer.SecurityContext.Privileged).To(BeFalse())
		Expect(nodeContainer.SecurityContext.Capabilities.Add).To(HaveLen(3))
		Expect(nodeContainer.SecurityContext.Capabilities.Add[0]).To(Equal(corev1.Capability("NET_RAW")))
		Expect(nodeContainer.SecurityContext.Capabilities.Add[1]).To(Equal(corev1.Capability("NET_ADMIN")))
		Expect(nodeContainer.SecurityContext.Capabilities.Add[2]).To(Equal(corev1.Capability("NET_BIND_SERVICE")))

		// hostpath init container should have the correct env and security context.
		hostPathContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "hostpath-init")
		rtest.ExpectEnv(hostPathContainer.Env, "NODE_USER_ID", "999")
		Expect(*hostPathContainer.SecurityContext.RunAsUser).To(Equal(int64(0)))

		// Verify hostpath init container volume mounts.
		expectedHostPathInitVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/var/run", Name: "var-run"},
			{MountPath: "/var/lib", Name: "var-lib"},
			{MountPath: "/var/log", Name: "var-log"},
		}
		Expect(hostPathContainer.VolumeMounts).To(ConsistOf(expectedHostPathInitVolumeMounts))

		// Node image override results in correct image.
		calicoNodeImage := fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(calicoNodeImage))

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(3))

		// CNI container uses image override.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoCNI.Image, components.ComponentCalicoCNI.Version)))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		// Verify the mount-bpffs image and command.
		mountBpffs := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "mount-bpffs")
		Expect(mountBpffs).To(BeNil())

		// Verify volumes.
		var fileOrCreate = corev1.HostPathFileOrCreate
		var dirOrCreate = corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}}},
			{Name: "var-lib", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib"}}},
			{Name: "var-log", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
			{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
			{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
			{MountPath: "/var/run", Name: "var-run"},
			{MountPath: "/var/lib", Name: "var-lib"},
			{MountPath: "/var/log", Name: "var-log"},
			{MountPath: "/var/run/nodeagent", Name: "policysync"},
			{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
			{MountPath: "/felix-certs", Name: "felix-certs", ReadOnly: true},
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
		defaultInstance.CalicoNetwork.BGP = &bgpDisabled
		defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
		component := render.Node(&cfg)
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
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		ds := dsResource.(*appsv1.DaemonSet)
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
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
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
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.URISAN,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{
				Name: "CNI_NETWORK_CONFIG",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						Key: "config",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "cni-config",
						},
					},
				},
			},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		// Verify volumes.
		var fileOrCreate = corev1.HostPathFileOrCreate
		var dirOrCreate = corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
			{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
			{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "/var/run/nodeagent", Name: "policysync"},
			{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
			{MountPath: "/felix-certs", Name: "felix-certs", ReadOnly: true},
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.

		verifyProbesAndLifecycle(ds, false, false)
	})

	It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
		// Override the installation with one configured for AmazonVPC CNI.
		amazonVPCInstalllation := &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderEKS,
			CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
			FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
		}
		cfg.Installation = amazonVPCInstalllation

		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources - 1))

		// Should render the correct resources.
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "node-certs", "calico-system", "", "v1", "Secret")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "typha-node-ca", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())
		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Should not render CNI configuration.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).To(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*appsv1.DaemonSet)

		// CNI install container should not be present.
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer).To(BeNil())

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		optional := true

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
			{Name: "IP", Value: "none"},
			{Name: "IP6", Value: "none"},
			{Name: "NO_DEFAULT_POOLS", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "false"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
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
			{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		// Verify volumes.
		var fileOrCreate = corev1.HostPathFileOrCreate
		var dirOrCreate = corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
			{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
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
		verifyProbesAndLifecycle(ds, false, true)
	})

	DescribeTable("should properly render configuration using non-Calico CNI plugin",
		func(cni operatorv1.CNIPluginType, ipam operatorv1.IPAMPluginType, expectedEnvs []corev1.EnvVar) {
			installlation := &operatorv1.InstallationSpec{
				CNI: &operatorv1.CNISpec{
					Type: cni,
					IPAM: &operatorv1.IPAMSpec{Type: ipam},
				},
				FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
			}
			cfg.Installation = installlation

			component := render.Node(&cfg)
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
			ds := dsResource.(*appsv1.DaemonSet)

			// CNI install container should not be present.
			cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
			Expect(cniContainer).To(BeNil())
			// Validate correct number of init containers.
			Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

			// Verify env
			expectedEnvs = append(expectedEnvs,
				corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
				corev1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"},
				corev1.EnvVar{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			)
			for _, expected := range expectedEnvs {
				Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(expected))
			}

			// Verify readiness and liveness probes.
			verifyProbesAndLifecycle(ds, false, false)
		},
		Entry("GKE", operatorv1.PluginGKE, operatorv1.IPAMPluginHostLocal, []corev1.EnvVar{
			{Name: "FELIX_INTERFACEPREFIX", Value: "gke"},
			{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
			{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"},
		}),
		Entry("AmazonVPC", operatorv1.PluginAmazonVPC, operatorv1.IPAMPluginAmazonVPC, []corev1.EnvVar{
			{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
			{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
		}),
		Entry("AzureVNET", operatorv1.PluginAzureVNET, operatorv1.IPAMPluginAzureVNET, []corev1.EnvVar{
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		disabled := operatorv1.BGPDisabled
		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operatorv1.ProviderEKS
		defaultInstance.CalicoNetwork.BGP = &disabled
		defaultInstance.CalicoNetwork.IPPools[0].Encapsulation = operatorv1.EncapsulationVXLAN
		component := render.Node(&cfg)
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
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		ds := dsResource.(*appsv1.DaemonSet)
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
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
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
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.URISAN,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{
				Name: "CNI_NETWORK_CONFIG",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						Key: "config",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "cni-config",
						},
					},
				},
			},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		// Verify volumes.
		var fileOrCreate = corev1.HostPathFileOrCreate
		var dirOrCreate = corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
			{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
			{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
			{MountPath: "/var/run/calico", Name: "var-run-calico"},
			{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
			{MountPath: "/var/run/nodeagent", Name: "policysync"},
			{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
			{MountPath: "/felix-certs", Name: "felix-certs", ReadOnly: true},
			{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(expectedNodeVolumeMounts))

		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))

		// Verify tolerations.
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		// Verify readiness and liveness probes.
		verifyProbesAndLifecycle(ds, false, false)
	})

	It("should properly render a configuration using the AmazonVPC CNI plugin", func() {
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderEKS,
			CNI:                &operatorv1.CNISpec{Type: operatorv1.PluginAmazonVPC},
			FlexVolumePath:     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
		}

		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources - 1))

		// Should render the correct resources.
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "", "v1", "ServiceAccount")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "node-certs", "calico-system", "", "v1", "Secret")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "typha-node-ca", "calico-system", "", "v1", "ConfigMap")).ToNot(BeNil())
		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Should not render CNI configuration.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).To(BeNil())

		// The DaemonSet should have the correct configuration.
		ds := dsResource.(*appsv1.DaemonSet)

		// CNI install container should not be present.
		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		Expect(cniContainer).To(BeNil())

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(1))

		// Verify the Flex volume container image.
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver").Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentFlexVolume.Image, components.ComponentFlexVolume.Version)))

		optional := true

		// Verify env
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,ecs"},
			{Name: "IP", Value: "none"},
			{Name: "IP6", Value: "none"},
			{Name: "NO_DEFAULT_POOLS", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "false"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
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
			{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(ds.Spec.Template.Spec.Containers[0].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		// Verify volumes.
		var fileOrCreate = corev1.HostPathFileOrCreate
		var dirOrCreate = corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
			{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		// Verify volume mounts.
		expectedNodeVolumeMounts := []corev1.VolumeMount{
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
		verifyProbesAndLifecycle(ds, false, false)
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
		defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
		component := render.Node(&cfg)
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
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("docker.io/%s:%s", components.ComponentCalicoNode.Image, components.ComponentCalicoNode.Version)))

		rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/var/run/multus/cni/net.d")

		// Verify volumes. In particular, we want to make sure the flexvol-driver-host volume uses the right
		// host path for flexvolume drivers.
		var fileOrCreate = corev1.HostPathFileOrCreate
		var dirOrCreate = corev1.HostPathDirectoryOrCreate
		expectedVols := []corev1.Volume{
			{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
			{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
			{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
			{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/cni/bin"}}},
			{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/multus/cni/net.d"}}},
			{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico/cni"}}},
			{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
			{Name: "flexvol-driver-host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds", Type: &dirOrCreate}}},
			{
				Name: "typha-ca",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: render.TyphaCAConfigMapName,
						},
					},
				},
			},
			{
				Name: "felix-certs",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.NodeTLSSecretName,
						DefaultMode: &defaultMode,
					},
				},
			},
		}
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVols))

		optional := true
		expectedNodeEnv := []corev1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
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

		verifyProbesAndLifecycle(ds, true, false)
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "calico-node-metrics", ns: "calico-system", group: "", version: "v1", kind: "Service"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
		defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.NodeReporterMetricsPort = 9081

		component := render.Node(&cfg)
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
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal(components.TigeraRegistry + "tigera/cnx-node:" + components.ComponentTigeraNode.Version))

		rtest.ExpectEnv(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env, "CNI_NET_DIR", "/var/run/multus/cni/net.d")

		optional := true
		expectedNodeEnv := []corev1.EnvVar{
			// Default envvars.
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
			{Name: "CLUSTER_TYPE", Value: "k8s,operator,openshift,bgp"},
			{Name: "IP", Value: "autodetect"},
			{Name: "IP_AUTODETECTION_METHOD", Value: "first-found"},
			{Name: "IP6", Value: "none"},
			{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.1.0/16"},
			{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
			{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"},
			{Name: "FELIX_HEALTHENABLED", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
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
			{Name: "MULTI_INTERFACE_MODE", Value: operatorv1.MultiInterfaceModeNone.Value()},
			{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))
		Expect(len(ds.Spec.Template.Spec.Containers[0].Env)).To(Equal(len(expectedNodeEnv)))

		verifyProbesAndLifecycle(ds, true, true)
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: render.BirdTemplatesConfigMapName, ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		cfg.BirdTemplates = map[string]string{
			"template-1.yaml": "dataforTemplate1 that is not used here",
		}
		defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
		component := render.Node(&cfg)
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
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		volumes := ds.Spec.Template.Spec.Volumes
		// Expect(ds.Spec.Template.Spec.Volumes).To(Equal())
		Expect(volumes).To(ContainElement(
			corev1.Volume{
				Name: "bird-templates",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "bird-templates",
						},
					},
				},
			}))

		volumeMounts := ds.Spec.Template.Spec.Containers[0].VolumeMounts
		Expect(volumeMounts).To(ContainElement(
			corev1.VolumeMount{
				Name:      "bird-templates",
				ReadOnly:  true,
				MountPath: "/etc/calico/confd/templates/template-1.yaml",
				SubPath:   "template-1.yaml",
			}))
	})
	Describe("AKS", func() {
		It("should avoid virtual nodes", func() {
			defaultInstance.KubernetesProvider = operatorv1.ProviderAKS
			component := render.Node(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)
			Expect(ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms).To(ContainElement(
				corev1.NodeSelectorTerm{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key:      "type",
						Operator: corev1.NodeSelectorOpNotIn,
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
			component := render.Node(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)
			rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "can-reach=1.1.1.1")
		})

		It("should support interface regex", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.Interface = "eth*"
			component := render.Node(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)
			rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "interface=eth*")
		})

		It("should support skip-interface regex", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface = "eth*"
			component := render.Node(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)
			rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "skip-interface=eth*")
		})

		It("should support cidr", func() {
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound = nil
			defaultInstance.CalicoNetwork.NodeAddressAutodetectionV4.CIDRS = []string{"10.0.1.0/24", "10.0.2.0/24"}
			component := render.Node(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)
			rtest.ExpectEnv(ds.Spec.Template.Spec.Containers[0].Env, "IP_AUTODETECTION_METHOD", "cidr=10.0.1.0/24,10.0.2.0/24")
		})

	})

	It("should include updates needed for the core upgrade", func() {
		defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.MigrateNamespaces = true
		component := render.Node(&cfg)
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
		ds := dsResource.(*appsv1.DaemonSet)
		ns := ds.Spec.Template.Spec.NodeSelector
		Expect(ns).To(HaveKey("projectcalico.org/operator-node-migration"))
		Expect(ns["projectcalico.org/operator-node-migration"]).To(Equal("migrated"))
	})

	DescribeTable("test IP Pool configuration",
		func(pool operatorv1.IPPool, expect map[string]string) {
			// Provider does not matter for IPPool configuration
			defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{pool}
			component := render.Node(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			// The DaemonSet should have the correct configuration.
			ds := dsResource.(*appsv1.DaemonSet)
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
					Expect(nodeEnvs).To(ContainElement(corev1.EnvVar{Name: envVar, Value: v}))
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
			operatorv1.IPPool{
				CIDR: "192.168.0.0/16",
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR": "192.168.0.0/16",
				"CALICO_IPV4POOL_IPIP": "Always",
			}),
		Entry("Pool with nat outgoing disabled",
			operatorv1.IPPool{
				CIDR:        "172.16.0.0/24",
				NATOutgoing: "Disabled",
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":         "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP":         "Always",
				"CALICO_IPV4POOL_NAT_OUTGOING": "false",
			}),
		Entry("Pool with nat outgoing enabled",
			operatorv1.IPPool{
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
			operatorv1.IPPool{
				CIDR:        "fc00::/48",
				NATOutgoing: "Disabled",
			},
			map[string]string{
				"CALICO_IPV6POOL_CIDR": "fc00::/48",
				// Disabled is the default so we don't set
				// NAT_OUTGOING if it is disabled.
			}),
		Entry("Pool with nat outgoing enabled (IPv6)",
			operatorv1.IPPool{
				CIDR:        "fc00::/48",
				NATOutgoing: "Enabled",
			},
			map[string]string{
				"CALICO_IPV6POOL_CIDR":         "fc00::/48",
				"CALICO_IPV6POOL_NAT_OUTGOING": "true",
			}),
		Entry("Pool with CrossSubnet",
			operatorv1.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operatorv1.EncapsulationIPIPCrossSubnet,
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR": "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP": "CrossSubnet",
			}),
		Entry("Pool with VXLAN",
			operatorv1.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operatorv1.EncapsulationVXLAN,
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":  "172.16.0.0/24",
				"CALICO_IPV4POOL_VXLAN": "Always",
			}),
		Entry("Pool with VXLANCrossSubnet",
			operatorv1.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operatorv1.EncapsulationVXLANCrossSubnet,
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":  "172.16.0.0/24",
				"CALICO_IPV4POOL_VXLAN": "CrossSubnet",
			}),
		Entry("Pool with no encapsulation",
			operatorv1.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operatorv1.EncapsulationNone,
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR": "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP": "Never",
			}),
		Entry("Pool with node selector",
			operatorv1.IPPool{
				CIDR:         "172.16.0.0/24",
				NodeSelector: "has(thiskey)",
			},
			map[string]string{
				"CALICO_IPV4POOL_CIDR":          "172.16.0.0/24",
				"CALICO_IPV4POOL_IPIP":          "Always",
				"CALICO_IPV4POOL_NODE_SELECTOR": "has(thiskey)",
			}),
		Entry("Pool with all fields set",
			operatorv1.IPPool{
				CIDR:          "172.16.0.0/24",
				Encapsulation: operatorv1.EncapsulationIPIP,
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
		defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
		defaultInstance.NodeMetricsPort = nil
		cfg.NodeReporterMetricsPort = 9081

		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		notExpectedEnvVar := corev1.EnvVar{Name: "FELIX_PROMETHEUSMETRICSPORT"}
		ds := dsResource.(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(notExpectedEnvVar))

		// It should have the reporter port, though.
		expected := corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERPORT"}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).ToNot(ContainElement(expected))
	})

	It("should set FELIX_PROMETHEUSMETRICSPORT with a custom value if NodeMetricsPort is set", func() {
		var nodeMetricsPort int32 = 1234
		defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
		defaultInstance.NodeMetricsPort = &nodeMetricsPort
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources + 1))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Assert on expected env vars.
		expectedEnvVars := []corev1.EnvVar{
			{Name: "FELIX_PROMETHEUSMETRICSPORT", Value: "1234"},
			{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
		}
		ds := dsResource.(*appsv1.DaemonSet)
		for _, v := range expectedEnvVars {
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(v))
		}

		// Assert we set annotations properly.
		Expect(ds.Spec.Template.Annotations["prometheus.io/scrape"]).To(Equal("true"))
		Expect(ds.Spec.Template.Annotations["prometheus.io/port"]).To(Equal("1234"))
	})

	It("should not render a FlexVolume container if FlexVolumePath is set to None", func() {
		defaultInstance.FlexVolumePath = "None"
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*appsv1.DaemonSet)
		Expect(ds).ToNot(BeNil())
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")).To(BeNil())
	})

	It("should render MaxUnavailable if a custom value was set", func() {
		two := intstr.FromInt(2)
		defaultInstance.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &two
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*appsv1.DaemonSet)
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		defaultInstance.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		hpd := operatorv1.HostPortsDisabled
		defaultInstance.CalicoNetwork.HostPorts = &hpd
		component := render.Node(&cfg)
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
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		ds := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

		cniContainer := rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
		rtest.ExpectEnv(cniContainer.Env, "CNI_NET_DIR", "/etc/cni/net.d")

		// Validate correct number of init containers.
		Expect(len(ds.Spec.Template.Spec.InitContainers)).To(Equal(2))

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{
				Name: "CNI_NETWORK_CONFIG",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						Key: "config",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "cni-config",
						},
					},
				},
			},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		Expect(ds.Spec.Template.Spec.Volumes).To(ContainElement(
			corev1.Volume{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/cni/net.d"}}}))

		expectedCNIVolumeMounts := []corev1.VolumeMount{
			{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
			{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").VolumeMounts).To(ConsistOf(expectedCNIVolumeMounts))
	})

	It("should render a proper 'allow_ip_forwarding' container setting in the cni config", func() {
		cif := operatorv1.ContainerIPForwardingEnabled
		defaultInstance.CalicoNetwork.ContainerIPForwarding = &cif
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		// Should render the correct resources.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		// Should render the correct resources.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		cfg.K8sServiceEp = k8sServiceEp
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(defaultNumExpectedResources))

		// Should render the correct resources.
		cniCmResource := rtest.GetResource(resources, "cni-config", "calico-system", "", "v1", "ConfigMap")
		Expect(cniCmResource).ToNot(BeNil())
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		cfg.NodeAppArmorProfile = seccompProf
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*appsv1.DaemonSet)
		Expect(ds).ToNot(BeNil())

		Expect(ds.Spec.Template.Annotations["container.apparmor.security.beta.kubernetes.io/calico-node"]).To(Equal(seccompProf))
	})

	It("should set TIGERA_*_SECURITY_GROUP variables when AmazonCloudIntegration is defined", func() {
		cfg.AmazonCloudIntegration = &operatorv1.AmazonCloudIntegration{
			Spec: operatorv1.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIDs: []string{"sg-nodeid", "sg-masterid"},
				PodSecurityGroupID:   "sg-podsgid",
			},
		}
		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())

		// Assert on expected env vars.
		expectedEnvVars := []corev1.EnvVar{
			{Name: "TIGERA_DEFAULT_SECURITY_GROUPS", Value: "sg-nodeid,sg-masterid"},
			{Name: "TIGERA_POD_SECURITY_GROUP", Value: "sg-podsgid"},
		}
		ds := dsResource.(*appsv1.DaemonSet)
		for _, v := range expectedEnvVars {
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(v))
		}
	})

	It("should render resourcerequirements", func() {
		rr := &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		defaultInstance.ComponentResources = []operatorv1.ComponentResource{
			{
				ComponentName:        operatorv1.ComponentNameNode,
				ResourceRequirements: rr,
			},
		}

		component := render.Node(&cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
		Expect(dsResource).ToNot(BeNil())
		ds := dsResource.(*appsv1.DaemonSet)

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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "node-certs", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		disabled := operatorv1.BGPDisabled
		defaultInstance.CalicoNetwork.BGP = &disabled
		defaultInstance.CNI.Type = operatorv1.PluginCalico
		defaultInstance.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal
		defaultInstance.CalicoNetwork.IPPools = []operatorv1.IPPool{{
			CIDR:          "192.168.1.0/16",
			Encapsulation: operatorv1.EncapsulationNone,
			NATOutgoing:   operatorv1.NATOutgoingEnabled,
		}}
		component := render.Node(&cfg)
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
		cniCm := cniCmResource.(*corev1.ConfigMap)
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
		ds := dsResource.(*appsv1.DaemonSet)
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
		expectedNodeEnv := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "WAIT_FOR_DATASTORE", Value: "true"},
			{Name: "CALICO_NETWORKING_BACKEND", Value: "none"},
			{Name: "CALICO_MANAGE_CNI", Value: "true"},
			{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
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
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			{Name: "FELIX_TYPHAK8SNAMESPACE", Value: "calico-system"},
			{Name: "FELIX_TYPHAK8SSERVICENAME", Value: "calico-typha"},
			{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
			{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretCertName)},
			{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", render.TLSSecretKeyName)},
			{Name: "FELIX_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.CommonName,
					Optional: &optional,
				},
			}},
			{Name: "FELIX_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.TyphaTLSSecretName,
					},
					Key:      render.URISAN,
					Optional: &optional,
				},
			}},
		}
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedNodeEnv))

		expectedCNIEnv := []corev1.EnvVar{
			{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
			{Name: "SLEEP", Value: "false"},
			{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
			{
				Name: "CNI_NETWORK_CONFIG",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						Key: "config",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "cni-config",
						},
					},
				},
			},
		}
		Expect(rtest.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni").Env).To(ConsistOf(expectedCNIEnv))

		// Verify readiness and liveness probes.
		verifyProbesAndLifecycle(ds, false, false)
	})

	DescribeTable("test node probes",
		func(isOpenshift, isEnterprise bool, bgpOption operatorv1.BGPOption) {
			if isOpenshift {
				defaultInstance.KubernetesProvider = operatorv1.ProviderOpenShift
			}

			if isEnterprise {
				defaultInstance.Variant = operatorv1.TigeraSecureEnterprise
			}

			defaultInstance.CalicoNetwork.BGP = &bgpOption

			component := render.Node(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			ds := dsResource.(*appsv1.DaemonSet)
			verifyProbesAndLifecycle(ds, isOpenshift, isEnterprise)
		},

		Entry("k8s Calico OS no BGP", false, false, operatorv1.BGPDisabled),
		Entry("k8s Calico OS w/ BGP", false, false, operatorv1.BGPEnabled),
		Entry("k8s Enterprise no BGP", false, true, operatorv1.BGPDisabled),
		Entry("k8s Enterprise w/ BGP", false, true, operatorv1.BGPEnabled),
		Entry("OCP Calico OS no BGP", true, false, operatorv1.BGPDisabled),
		Entry("OCP Calico OSS w/ BGP", true, false, operatorv1.BGPEnabled),
		Entry("OCP Enterprise no BGP", true, true, operatorv1.BGPDisabled),
		Entry("OCP Enterprise w/ BGP", true, true, operatorv1.BGPEnabled),
	)

	Context("with k8s overrides set", func() {
		It("should override k8s endpoints", func() {
			cfg.K8sServiceEp = k8sapi.ServiceEndpoint{
				Host: "k8shost",
				Port: "1234",
			}
			component := render.Node(&cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			Expect(len(resources)).To(Equal(defaultNumExpectedResources))

			dsResource := rtest.GetResource(resources, "calico-node", "calico-system", "apps", "v1", "DaemonSet")
			ds := dsResource.(*appsv1.DaemonSet)

			// FIXME update gomega to include ContainElements
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
				corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "k8shost"},
			))
			Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ContainElement(
				corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "1234"},
			))

			var cni corev1.Container

			for _, c := range ds.Spec.Template.Spec.InitContainers {
				if c.Name == "install-cni" {
					cni = c
					break
				}
			}
			Expect(cni).NotTo(BeNil())

			Expect(cni.Env).To(ContainElement(
				corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "k8shost"},
			))
			Expect(cni.Env).To(ContainElement(
				corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "1234"},
			))
		})
	})

	It("should render extra resources when certificate management is enabled", func() {
		defaultInstance.CertificateManagement = &operatorv1.CertificateManagement{CACert: []byte("<ca>"), SignerName: "a.b/c"}
		cfg.TLS.NodeSecret = nil
		cfg.TLS.TyphaSecret = nil
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
			{name: "typha-node-ca", ns: "calico-system", group: "", version: "v1", kind: "ConfigMap"},
			{name: "cni-config", ns: common.CalicoNamespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: common.NodeDaemonSetName, ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: common.NodeDaemonSetName, ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: render.CSRClusterRoleName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "calico-node:csr-creator", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component := render.Node(&cfg)
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

	It("should handle BGP layout", func() {
		cfg.BGPLayouts = &corev1.ConfigMap{Data: map[string]string{"test": "data"}}
		component := render.Node(&cfg)
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, common.NodeDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
		Expect(dep).ToNot(BeNil())
		deploy, ok := dep.(*appsv1.DaemonSet)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/bgp-layout"))
		Expect(deploy.Spec.Template.Annotations["hash.operator.tigera.io/bgp-layout"]).To(Equal("46aec5c60cd6c6fc95979e247a8370bdb9f23b0f"))
		Expect(deploy.Spec.Template.Spec.Volumes).To(ContainElement(corev1.Volume{
			Name: render.BGPLayoutVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: render.BGPLayoutConfigMapName,
					},
				},
			},
		}))
		Expect(deploy.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name:      render.BGPLayoutVolumeName,
			ReadOnly:  true,
			MountPath: render.BGPLayoutPath,
			SubPath:   render.BGPLayoutConfigMapKey,
		}))
		rtest.ExpectEnv(deploy.Spec.Template.Spec.Containers[0].Env, "CALICO_EARLY_NETWORKING", render.BGPLayoutPath)
	})
})

// verifyProbesAndLifecycle asserts the expected node liveness and readiness probe plus pod lifecycle settings.
func verifyProbesAndLifecycle(ds *appsv1.DaemonSet, isOpenshift, isEnterprise bool) {
	// Verify readiness and liveness probes.
	expectedReadiness := &corev1.Probe{
		Handler:        corev1.Handler{Exec: &corev1.ExecAction{Command: []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}}},
		TimeoutSeconds: 5,
		PeriodSeconds:  10,
	}
	expectedLiveness := &corev1.Probe{Handler: corev1.Handler{
		HTTPGet: &corev1.HTTPGetAction{
			Host: "localhost",
			Path: "/liveness",
			Port: intstr.FromInt(9099),
		}},
		TimeoutSeconds: 10,
	}

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

	expectedLifecycle := &corev1.Lifecycle{
		PreStop: &corev1.Handler{Exec: &corev1.ExecAction{Command: []string{"/bin/calico-node", "-shutdown"}}},
	}
	Expect(ds.Spec.Template.Spec.Containers[0].Lifecycle).To(Equal(expectedLifecycle))

	Expect(int(*ds.Spec.Template.Spec.TerminationGracePeriodSeconds)).To(Equal(5))
}
