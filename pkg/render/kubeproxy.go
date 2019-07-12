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

package render

import (
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var KubeProxyMeta = metav1.ObjectMeta{
	Name:      "kube-proxy",
	Namespace: "kube-system",
}

func KubeProxy(cr *operator.Installation) Component {
	if !cr.Spec.Components.KubeProxy.Required {
		// Only install kube-proxy if configured to do so.
		return nil
	}
	return &kubeproxyComponent{cr: cr}
}

type kubeproxyComponent struct {
	cr *operator.Installation
}

func (c *kubeproxyComponent) GetObjects() []runtime.Object {
	return []runtime.Object{
		kubeProxyServiceAccount(c.cr),
		kubeProxyRoleBinding(c.cr),
		kubeProxyConfigMap(c.cr),
		kubeProxyDaemonset(c.cr),
	}
}

func (c *kubeproxyComponent) GetComponentDeps() []runtime.Object {
	return nil
}

func (c *kubeproxyComponent) Ready(client client.Client) bool {
	return true
}

func kubeProxyServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: KubeProxyMeta,
	}
}

func kubeProxyRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "kube-proxy"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:node-proxier",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "kube-proxy",
				Namespace: "kube-system",
			},
		},
	}
}

func kubeProxyConfigMap(cr *operator.Installation) *v1.ConfigMap {
	var config = `apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
clientConnection:
  acceptContentTypes: ""
  burst: 10
  contentType: application/vnd.kubernetes.protobuf
  kubeconfig: /var/lib/kube-proxy/kubeconfig.conf
  qps: 5
clusterCIDR: <defaultCIDR>
configSyncPeriod: 15m0s
conntrack:
  max: null
  maxPerCore: 32768
  min: 131072
  tcpCloseWaitTimeout: 1h0m0s
  tcpEstablishedTimeout: 24h0m0s
enableProfiling: false
healthzBindAddress: 0.0.0.0:10256
hostnameOverride: ""
iptables:
  masqueradeAll: false
  masqueradeBit: 14
  minSyncPeriod: 0s
  syncPeriod: 30s
ipvs:
  excludeCIDRs: null
  minSyncPeriod: 0s
  scheduler: ""
  syncPeriod: 30s
kind: KubeProxyConfiguration
metricsBindAddress: 127.0.0.1:10249
mode: iptables
nodePortAddresses: null
oomScoreAdj: -999
portRange: ""
resourceContainer: /kube-proxy
udpIdleTimeout: 250ms
`

	var kubeconfig = `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    server: <APIServer>
  name: default
contexts:
- context:
    cluster: default
    namespace: default
    user: default
  name: default
current-context: default
users:
- name: default
  user:
    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
`

	// Populate the config map with values from the custom resource.
	kubeconfig = strings.Replace(kubeconfig, "<APIServer>", cr.Spec.Components.KubeProxy.APIServer, 1)
	config = strings.Replace(config, "<defaultCIDR>", cr.Spec.IPPools[0].CIDR, 1)

	return &v1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: KubeProxyMeta,
		Data: map[string]string{
			"config.conf":     config,
			"kubeconfig.conf": kubeconfig,
		},
	}
}

func kubeProxyDaemonset(cr *operator.Installation) *apps.DaemonSet {
	var terminationGracePeriod int64 = 30
	var trueBool bool = true
	var configMapDefaultMode int32 = 420
	fileOrCreate := v1.HostPathFileOrCreate

	return &apps.DaemonSet{
		TypeMeta:   metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: KubeProxyMeta,
		Spec: apps.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-proxy"}},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"scheduler.alpha.kubernetes.io/critical-pod": "",
					},
					Labels: map[string]string{
						"k8s-app": "kube-proxy",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Command:         []string{"/usr/local/bin/kube-proxy"},
							Args:            []string{"--config=/var/lib/kube-proxy/config.conf"},
							Image:           cr.Spec.Components.KubeProxy.Image,
							ImagePullPolicy: v1.PullAlways,
							Name:            "kube-proxy",
							SecurityContext: &v1.SecurityContext{
								Privileged: &trueBool,
							},
							TerminationMessagePath:   "/dev/termination-log",
							TerminationMessagePolicy: v1.TerminationMessageReadFile,
							VolumeMounts: []v1.VolumeMount{
								{MountPath: "/var/lib/kube-proxy", Name: "kube-proxy"},
								{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
								{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
							},
						},
					},
					DNSPolicy:                     v1.DNSClusterFirst,
					HostNetwork:                   true,
					PriorityClassName:             "system-node-critical",
					RestartPolicy:                 v1.RestartPolicyAlways,
					ServiceAccountName:            "kube-proxy",
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					Tolerations: []v1.Toleration{
						{Operator: "Exists", Effect: "NoSchedule"},
						{Operator: "Exists", Effect: "NoExecute"},
						{Operator: v1.TolerationOpExists, Key: "CriticalAddonsOnly"},
					},
					Volumes: []v1.Volume{
						{
							Name: "kube-proxy",
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									DefaultMode: &configMapDefaultMode,
									LocalObjectReference: v1.LocalObjectReference{
										Name: "kube-proxy",
									},
								},
							},
						},
						{
							Name: "xtables-lock",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/run/xtables.lock",
									Type: &fileOrCreate,
								},
							},
						},
						{
							Name: "lib-modules",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
					},
				},
			},
			UpdateStrategy: apps.DaemonSetUpdateStrategy{
				Type: apps.RollingUpdateDaemonSetStrategyType,
			},
		},
	}
}
