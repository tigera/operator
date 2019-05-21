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

package core

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
)

var _ = Describe("Defaulting logic tests", func() {
	It("should properly fill defaults on an empty instance", func() {
		instance := &operatorv1alpha1.Core{}
		fillDefaults(instance)
		Expect(instance.Spec.Version).To(Equal("latest"))
		Expect(instance.Spec.Variant).To(Equal(operatorv1alpha1.Calico))
		Expect(instance.Spec.Registry).To(Equal("docker.io/"))
		Expect(instance.Spec.CNINetDir).To(Equal("/etc/cni/net.d"))
		Expect(instance.Spec.CNIBinDir).To(Equal("/opt/cni/bin"))
		Expect(instance.Spec.KubeProxy.Required).To(BeFalse())
		Expect(instance.Spec.KubeProxy.APIServer).To(Equal(""))
	})

	It("should not override custom configuration", func() {
		instance := &operatorv1alpha1.Core{
			Spec: operatorv1alpha1.CoreSpec{
				Version:   "test",
				Variant:   operatorv1alpha1.TigeraSecureEnterprise,
				Registry:  "test-reg/",
				CNIBinDir: "/test/bin",
				CNINetDir: "/test/net",
				IPPools: []operatorv1alpha1.IPPool{
					{CIDR: "1.2.3.0/24"},
				},
				KubeProxy: operatorv1alpha1.KubeProxySpec{
					Required:  true,
					APIServer: "http://server",
					Image:     "test-image",
				},
			},
		}
		instanceCopy := instance.DeepCopyObject().(*operatorv1alpha1.Core)
		fillDefaults(instanceCopy)
		Expect(instanceCopy).To(Equal(instance))
	})

	It("should correct missing slashes on registry", func() {
		instance := &operatorv1alpha1.Core{
			Spec: operatorv1alpha1.CoreSpec{
				Registry: "test-reg",
			},
		}
		fillDefaults(instance)
		Expect(instance.Spec.Registry).To(Equal("test-reg/"))
	})

})
