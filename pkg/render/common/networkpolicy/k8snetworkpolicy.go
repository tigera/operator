// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package networkpolicy

import (
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render/common/selector"
)

func K8sDNSEgressRules(openShift bool) []netv1.NetworkPolicyEgressRule {
	var egressRules []netv1.NetworkPolicyEgressRule
	if openShift {
		egressRules = append(egressRules,
			netv1.NetworkPolicyEgressRule{
				To: []netv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								selector.OpenShiftDNSDaemonsetLabel: "default",
							},
						},
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								selector.CalicoNameLabel: "openshift-dns",
							},
						},
					},
				},
				Ports: []netv1.NetworkPolicyPort{
					NewK8sPolicyPort(corev1.ProtocolUDP, 5353),
				},
			},
		)
	} else {
		egressRules = append(egressRules,
			netv1.NetworkPolicyEgressRule{
				To: []netv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"k8s-app": "kube-dns",
							},
						},
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								selector.CalicoNameLabel: "kube-system",
							},
						},
					},
				},
				Ports: []netv1.NetworkPolicyPort{
					NewK8sPolicyPort(corev1.ProtocolTCP, 53),
					NewK8sPolicyPort(corev1.ProtocolUDP, 53),
				},
			},
		)
	}

	return egressRules
}

func NewK8sPolicyPort(protocol corev1.Protocol, port int32) netv1.NetworkPolicyPort {
	return netv1.NetworkPolicyPort{
		Protocol: ptr.ToPtr(protocol),
		Port:     ptr.ToPtr(intstr.FromInt32(port)),
	}
}
