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

package utils

import (
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/tigera/operator/pkg/ptr"
)

var _ = Describe("BPF Auto Installation Requirements", func() {

	Context("kube-proxy not managed", func() {
		kubeProxyDS := func() *appsv1.DaemonSet {
			return &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      KubeProxyDaemonSetName,
					Namespace: KubeProxyNamespace,
				},
			}
		}
		table.DescribeTable("check whether kube-proxy is not managed",
			func(labels map[string]string, annotations map[string]string, shouldSucceed bool) {
				ds := kubeProxyDS()
				ds.Labels = labels
				ds.Annotations = annotations
				err := validateDaemonSetManaged(ds)
				Expect(err == nil).Should(Equal(shouldSucceed))
			},
			table.Entry("managed by argocd",
				map[string]string{"app.kubernetes.io/managed-by": "argocd"}, nil, false,
			),
			table.Entry("addonmanager mode ReconcileOnce",
				map[string]string{"addonmanager.kubernetes.io/mode": "ReconcileOnce"}, nil, false,
			),
			table.Entry("managed by argocd with tracking-id",
				nil, map[string]string{"argocd.argoproj.io/tracking-id": "fake-git-commit-hash"}, false,
			),
			table.Entry("kube-proxy not managed",
				map[string]string{"app.kubernetes.io/name": "kube-proxy"}, nil, true,
			),
			table.Entry("kube-proxy not managed",
				map[string]string{"app.kubernetes.io/name": "kube-proxy"},
				map[string]string{"kube-proxy.config.k8s.io/proxy-mode": "iptables"},
				true,
			),
		)
	})

	Context("service and endpoint slice IPs consistency", func() {
		svcIpV4 :=
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
					ClusterIP:  "1.2.3.4",
					Ports: []corev1.ServicePort{
						{Name: "https", Port: 443, TargetPort: intstr.FromInt(443)},
					},
				},
			}
		svcIpV6 :=
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol},
					ClusterIPs: []string{"fd00::1"},
					Ports: []corev1.ServicePort{
						{Name: "https", Port: 443, TargetPort: intstr.FromInt(443)},
					},
				},
			}
		svcDualStack :=
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
				Spec: corev1.ServiceSpec{
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
					ClusterIPs: []string{"1.2.3.4", "fd00::1"},
					Ports: []corev1.ServicePort{
						{Name: "https", Port: 443, TargetPort: intstr.FromInt(443)},
					},
				},
			}
		epIpV4 :=
			discoveryv1.EndpointSlice{
				ObjectMeta:  metav1.ObjectMeta{Name: "kubernetes-epv4", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}},
				AddressType: discoveryv1.AddressTypeIPv4,
				Endpoints: []discoveryv1.Endpoint{
					{Addresses: []string{"5.6.7.8", "5.6.7.9", "5.6.7.10"}},
				},
				Ports: []discoveryv1.EndpointPort{{Port: ptr.Int32ToPtr(6443)}},
			}
		epIpV6 :=
			discoveryv1.EndpointSlice{
				ObjectMeta:  metav1.ObjectMeta{Name: "kubernetes-epv6", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}},
				AddressType: discoveryv1.AddressTypeIPv6,
				Endpoints: []discoveryv1.Endpoint{
					{Addresses: []string{"fd00::1"}},
				},
				Ports: []discoveryv1.EndpointPort{{Port: ptr.Int32ToPtr(6443)}},
			}

		table.DescribeTable("test service and endpoint slice IPs consistency",
			func(svc *corev1.Service, endpointSliceList *discoveryv1.EndpointSliceList, shouldSucceed bool) {
				err := validateIpFamilyConsistency(svc, endpointSliceList)
				Expect(err == nil).Should(Equal(shouldSucceed))
			},
			table.Entry("service IPv4 and EP IPv4",
				svcIpV4, &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{epIpV4}}, true,
			),
			table.Entry("service IPv6 and EP IPv6",
				svcIpV6, &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{epIpV6}}, true,
			),
			table.Entry("service dual-stack and EP dual-stack",
				svcDualStack, &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{epIpV4, epIpV6}}, true,
			),
			table.Entry("service IPv4 and EP dual-stack",
				svcIpV4, &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{epIpV4, epIpV6}}, false,
			),
			table.Entry("service IPv6 and EP IPv4",
				svcIpV6, &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{epIpV4}}, false,
			),
			table.Entry("service dual-stack and EP IPv6",
				svcDualStack, &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{epIpV6}}, false,
			),
		)
	})
})
