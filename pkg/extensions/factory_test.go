// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package extensions_test

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/extensions"
)

var _ = Describe("render context builder", func() {
	AfterEach(func() { extensions.ResetForTest() })

	It("returns the base render context from the default builder", func() {
		install := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}
		rc, err := extensions.BuildRenderContext(extensions.Inputs{
			Installation:  install,
			ClusterDomain: "cluster.local",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.Installation).To(BeIdenticalTo(install))
		Expect(rc.ClusterDomain).To(Equal("cluster.local"))
		Expect(rc.NodePrometheusTLS).To(BeNil())
	})

	It("uses a registered builder in place of the default", func() {
		extensions.RegisterRenderContextBuilder(fakeBuilder(nil))
		rc, err := extensions.BuildRenderContext(extensions.Inputs{})
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.ClusterDomain).To(Equal("from-fake"))
	})

	It("surfaces the builder error", func() {
		extensions.RegisterRenderContextBuilder(fakeBuilder(errors.New("boom")))
		_, err := extensions.BuildRenderContext(extensions.Inputs{})
		Expect(err).To(MatchError("boom"))
	})

	It("restores the default builder on reset", func() {
		extensions.RegisterRenderContextBuilder(fakeBuilder(nil))
		extensions.ResetForTest()
		rc, err := extensions.BuildRenderContext(extensions.Inputs{ClusterDomain: "real"})
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.ClusterDomain).To(Equal("real"))
	})
})

func fakeBuilder(err error) extensions.RenderContextBuilder {
	return func(_ extensions.Inputs) (extensions.RenderContext, error) {
		if err != nil {
			return extensions.RenderContext{}, err
		}
		return extensions.RenderContext{ClusterDomain: "from-fake"}, nil
	}
}
