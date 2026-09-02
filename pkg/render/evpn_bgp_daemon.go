// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package render

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

const (
	// EVPNBGPDaemonName is the name of the calico-bgp DaemonSet.
	EVPNBGPDaemonName = "calico-bgp"
	// EVPNBGPImageName defaults to a well-known repository:tag. Overridable
	// via the Installation registry / imagePath in a real deployment; the
	// demo uses `calico/calico-bgp:evpn-demo` loaded into kind.
	EVPNBGPImageName = "calico/calico-bgp:evpn-demo"
)

// EVPNBGPDaemon returns the DaemonSet spec for calico-bgp. It runs on every
// node with hostNetwork=true, mounts /var/run/calico as a hostPath so the
// UDS is shared with calico-node, and starts calico-bgp on that socket.
func EVPNBGPDaemon(installation *operatorv1.InstallationSpec) *appsv1.DaemonSet {
	dirOrCreate := corev1.HostPathDirectoryOrCreate
	trueVal := true
	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "DaemonSet"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EVPNBGPDaemonName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": EVPNBGPDaemonName},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": EVPNBGPDaemonName},
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k8s-app": EVPNBGPDaemonName}},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					// Tolerate every taint so calico-bgp runs everywhere
					// calico-node runs, including control-plane nodes.
					Tolerations: rmeta.TolerateAll,
					Containers: []corev1.Container{{
						Name:            EVPNBGPDaemonName,
						Image:           EVPNBGPImageName,
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: securitycontext.NewRootContext(true),
						Args: []string{
							"--socket=/var/run/calico/bgp.sock",
							"--log-level=info",
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "var-run-calico",
							MountPath: "/var/run/calico",
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "var-run-calico",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/run/calico",
								Type: &dirOrCreate,
							},
						},
					}},
					AutomountServiceAccountToken: &trueVal,
				},
			},
		},
	}
}
