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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
})
