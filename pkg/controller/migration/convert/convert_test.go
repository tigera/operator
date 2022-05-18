// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Parser", func() {
	var ctx = context.Background()
	var pool *crdv1.IPPool
	var scheme *runtime.Scheme
	BeforeEach(func() {
		scheme = kscheme.Scheme
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		pool = crdv1.NewIPPool()
		pool.Spec = crdv1.IPPoolSpec{
			CIDR:        "192.168.4.0/24",
			IPIPMode:    crdv1.IPIPModeAlways,
			NATOutgoing: true,
		}
	})

	It("should not detect an installation if none exists", func() {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		Expect(NeedsConversion(ctx, c)).To(BeFalse())
	})

	It("should detect an installation if one exists", func() {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig()).Build()
		_, err := Convert(ctx, c)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should detect a valid installation", func() {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig()).Build()
		_, err := Convert(ctx, c)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should error if it detects a canal installation", func() {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&appsv1.DaemonSet{
			ObjectMeta: v1.ObjectMeta{
				Name:      "canal-node",
				Namespace: "kube-system",
			},
		}, pool, emptyFelixConfig()).Build()
		_, err := Convert(ctx, c)
		Expect(err).To(HaveOccurred())
	})

	It("should error for unchecked env vars", func() {
		node := emptyNodeSpec()
		node.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
			Name:  "FOO",
			Value: "bar",
		}}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node, emptyKubeControllerSpec(), pool, emptyFelixConfig()).Build()
		_, err := Convert(ctx, c)
		Expect(err).To(HaveOccurred())
	})

	It("should detect an MTU via substitution", func() {
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{
			{
				Name:  "CNI_MTU",
				Value: "24",
			},
			{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam":{"type":"calico-ipam"}, "mtu": __CNI_MTU__}`,
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ds, emptyKubeControllerSpec(), pool, emptyFelixConfig()).Build()
		cfg, err := Convert(ctx, c)
		Expect(err).ToNot(HaveOccurred())
		Expect(cfg).ToNot(BeNil())
		exp := int32(24)
		Expect(cfg.Spec.CalicoNetwork.MTU).To(Equal(&exp))
	})

	It("should fail on invalid cni", func() {
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
			Name:  "CNI_NETWORK_CONFIG",
			Value: "{",
		}}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ds, emptyKubeControllerSpec(), pool, emptyFelixConfig()).Build()
		_, err := Convert(ctx, c)
		Expect(err).To(HaveOccurred())
	})

	Context("CNI", func() {
		var _ = Describe("CNI", func() {
			It("should load cni from correct fields on calico-node", func() {
				ds := emptyNodeSpec()
				ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{
					{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
							"name": "k8s-pod-network",
							"cniVersion": "0.3.1",
							"plugins": [
							  {
								"type": "calico",
								"log_level": "info",
								"datastore_type": "kubernetes",
								"nodename": "__KUBERNETES_NODE_NAME__",
								"mtu": __CNI_MTU__,
								"ipam": {"type": "calico-ipam"},
								"policy": {
									"type": "k8s"
								},
								"kubernetes": {
									"kubeconfig": "__KUBECONFIG_FILEPATH__"
								}
							  }
							]
						}`,
					},
				}

				cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(emptyKubeControllerSpec()).Build()
				c := components{
					node: CheckedDaemonSet{
						DaemonSet:   *ds,
						checkedVars: map[string]checkedFields{},
					},
					client: cli,
				}

				nc, err := loadCNI(&c)
				Expect(err).ToNot(HaveOccurred())
				Expect(nc.CalicoConfig).ToNot(BeNil())
				Expect(nc.CalicoConfig.IPAM.Type).To(Equal("calico-ipam"), fmt.Sprintf("Got %+v", c.cni.CalicoConfig))
			})
		})
	})
})
