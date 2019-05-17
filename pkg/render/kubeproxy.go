package render

import (
	operatorv1alpha1 "github.com/projectcalico/operator/pkg/apis/operator/v1alpha1"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var kubeProxyMeta = metav1.ObjectMeta{
	Name:      "kube-proxy",
	Namespace: "kube-system",
	Labels:    map[string]string{},
}

func KubeProxy(cr *operatorv1alpha1.Core) []runtime.Object {
	return []runtime.Object{
		kubeProxyServiceAccount(cr),
		kubeProxyRoleBinding(cr),
		kubeProxyConfigMap(cr),
		kubeProxyDaemonset(cr),
	}
}

func kubeProxyServiceAccount(cr *operatorv1alpha1.Core) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: kubeProxyMeta,
	}
}

func kubeProxyRoleBinding(cr *operatorv1alpha1.Core) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: kubeProxyMeta,
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

// kubeProxyConfigMap returns a config map containing the CNI network config to be installed on each node.
func kubeProxyConfigMap(cr *operatorv1alpha1.Core) *v1.ConfigMap {
	var config string = `{
    apiVersion: kubeproxy.config.k8s.io/v1alpha1
    bindAddress: 0.0.0.0
    clientConnection:
      acceptContentTypes: ""
      burst: 10
      contentType: application/vnd.kubernetes.protobuf
      kubeconfig: /var/lib/kube-proxy/kubeconfig.conf
      qps: 5
    clusterCIDR: 192.168.0.0/16
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
  kubeconfig.conf: |-
    apiVersion: v1
    kind: Config
    clusters:
    - cluster:
        certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        server: https://api.casey-ocp.openshift.crc.aws.eng.tigera.net:6443
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
}`
	return &v1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: kubeProxyMeta,
		Data: map[string]string{
			"config.conf": config,
		},
	}
}

func kubeProxyDaemonset(cr *operatorv1alpha1.Core) *apps.DaemonSet {
	var terminationGracePeriod int64 = 30
	var trueBool bool = true
	var configMapDefaultMode int32 = 420
	var defaultString v1.ProcMountType = "Default"
	fileOrCreate := v1.HostPathFileOrCreate

	return &apps.DaemonSet{
		TypeMeta:   metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: kubeProxyMeta,
		Spec: apps.DaemonSetSpec{
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
							Image:           "k8s.gcr.io/kube-proxy:v1.12.7",
							ImagePullPolicy: v1.PullAlways,
							Name:            "kube-proxy",
							Resources:       v1.ResourceRequirements{},
							SecurityContext: &v1.SecurityContext{
								Privileged: &trueBool,
								ProcMount:  &defaultString,
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
					DNSPolicy:                     "ClusterFirst",
					HostNetwork:                   true,
					PriorityClassName:             "system-node-critical",
					RestartPolicy:                 v1.RestartPolicyAlways,
					SchedulerName:                 "default-scheduler",
					SecurityContext:               &v1.PodSecurityContext{},
					ServiceAccountName:            "kube-proxy",
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					Tolerations: []v1.Toleration{
						{Operator: "Exists", Effect: "NoSchedule"},
						{Operator: "Exists", Effect: "NoExecute"},
						// TODO: Not valid?? {Operator: "Exists", Effect: "CriticalAddonsOnly"},
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
				RollingUpdate: &apps.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(1)},
				},
				Type: "DaemonSetUpdateStrategyType",
			},
		},
	}
}
