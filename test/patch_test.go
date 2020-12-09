// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package test

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/utils"
)

var _ = Describe("Patch tests with apiserver", func() {
	var c client.Client
	BeforeEach(func() {
		var err error
		err = apis.AddToScheme(scheme.Scheme)
		Expect(err).NotTo(HaveOccurred())
		c, err = client.New(config.GetConfigOrDie(), client.Options{})
		Expect(err).ToNot(HaveOccurred())

		err = cleanInstallationResources(c)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		// Clean up Calico data that might be left behind.
		err := cleanInstallationResources(c)
		Expect(err).ToNot(HaveOccurred())

	})

	Describe("Test patching Installation resource", func() {

		table.DescribeTable("Blah",
			func(og *operator.Installation, update func(*operator.Installation), extraTest func(og, upd, ptchd, getted *operator.Installation)) {
				ctx := context.Background()
				// Create og on apiserver
				err := c.Create(ctx, og)
				Expect(err).ToNot(HaveOccurred())

				// Copy og to updated
				// Make changes to updated
				updated := og.DeepCopy()
				update(updated)

				// Create patch
				p, err := utils.CreatePatch(og, updated)
				Expect(err).ToNot(HaveOccurred())

				patched := og.DeepCopy()
				// Apply patch to apiserver
				err = c.Patch(ctx, patched, p)
				Expect(err).ToNot(HaveOccurred())
				Expect(patched.Spec).To(Equal(updated.Spec))

				test1 := &operator.Installation{}
				// Get updated resource from apiserver
				err = c.Get(ctx, types.NamespacedName{Name: og.Name}, test1)
				Expect(err).ToNot(HaveOccurred())

				// Expect updated to match patched resource
				Expect(updated.Spec).To(Equal(test1.Spec))

				extraTest(og, updated, patched, test1)
			},

			table.Entry("simple patch",
				&operator.Installation{
					TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test1"},
					Spec: operator.InstallationSpec{
						Variant: operator.Calico,
					},
				},
				func(i *operator.Installation) {
					i.Spec.KubernetesProvider = operator.ProviderEKS
				}, func(og, upd, ptchd, getted *operator.Installation) {}),
			table.Entry("sub field update",
				&operator.Installation{
					TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "test1"},
					Spec: operator.InstallationSpec{
						Variant: operator.Calico,
						CalicoNetwork: &operator.CalicoNetworkSpec{
							BGP: operator.BGPOptionPtr(operator.BGPEnabled),
						},
					},
				},
				func(i *operator.Installation) {
					i.Spec.KubernetesProvider = operator.ProviderEKS
					mtu := int32(444)
					i.Spec.CalicoNetwork.MTU = &mtu
				}, func(og, upd, ptchd, getted *operator.Installation) {}),
			table.Entry("IPPool update",
				&operator.Installation{
					ObjectMeta: metav1.ObjectMeta{Name: "test1"},
					Spec: operator.InstallationSpec{
						CalicoNetwork: &operator.CalicoNetworkSpec{
							IPPools: []operator.IPPool{
								{CIDR: "10.0.0.0/24"},
								{CIDR: "ffee::/24"},
							},
						},
					},
				},
				func(i *operator.Installation) {
					i.Spec.CalicoNetwork.IPPools[0].Encapsulation = operator.EncapsulationIPIPCrossSubnet
				}, func(og, upd, ptchd, getted *operator.Installation) {
					pools := getted.Spec.CalicoNetwork.IPPools
					Expect(pools).To(HaveLen(2))
					Expect(pools[0].Encapsulation).To(Equal(operator.EncapsulationIPIPCrossSubnet))
					Expect(pools[1].Encapsulation).To(Equal(operator.EncapsulationType("")))
				},
			),
			table.Entry("Add IPPool",
				&operator.Installation{
					ObjectMeta: metav1.ObjectMeta{Name: "test1"},
					Spec:       operator.InstallationSpec{},
				},
				func(i *operator.Installation) {
					i.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{{
							CIDR:          "10.10.0.0/24",
							Encapsulation: operator.EncapsulationVXLANCrossSubnet,
						}},
					}

				}, func(og, upd, ptchd, getted *operator.Installation) {
					pools := getted.Spec.CalicoNetwork.IPPools
					Expect(pools).To(HaveLen(1))
					Expect(pools[0].CIDR).To(Equal("10.10.0.0/24"))
					Expect(pools[0].Encapsulation).To(Equal(operator.EncapsulationVXLANCrossSubnet))
				},
			),
		)
	})
})

func cleanInstallationResources(c client.Client) error {
	ctx := context.Background()
	instList := &operator.InstallationList{}
	err := c.List(ctx, instList)
	if err != nil {
		return err
	}

	for _, x := range instList.Items {
		err = c.Delete(ctx, &x)
		if err != nil {
			return err
		}
	}
	return nil
}
