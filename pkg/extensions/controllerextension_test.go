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
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("controller extension", func() {
	var s *extensions.Set
	BeforeEach(func() {
		s = extensions.NewSet()
	})

	It("returns the base render context when the variant has no extension", func() {
		install := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}
		rc, _, err := s.ExtendContext(extensions.ControllerContext{
			RenderContext: extensions.RenderContext{Installation: install, ClusterDomain: "cluster.local"},
			Controller:    extensions.InstallationController,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.Installation).To(BeIdenticalTo(install))
		Expect(rc.ClusterDomain).To(Equal("cluster.local"))
		Expect(rc.Extension).To(BeNil())
	})

	It("runs the extension registered for the installation variant", func() {
		s.Variant(operatorv1.CalicoEnterprise).Controller(extensions.InstallationController, fakeController{})
		rc, _, err := s.ExtendContext(enterpriseContext())
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.ClusterDomain).To(Equal("from-fake"))
	})

	It("ignores an extension registered for a different variant", func() {
		s.Variant(operatorv1.CalicoEnterprise).Controller(extensions.InstallationController, fakeController{})
		rc, _, err := s.ExtendContext(extensions.ControllerContext{
			RenderContext: extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}, ClusterDomain: "real"},
			Controller:    extensions.InstallationController,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.ClusterDomain).To(Equal("real"))
	})

	It("surfaces the extension error", func() {
		s.Variant(operatorv1.CalicoEnterprise).Controller(extensions.InstallationController, fakeController{err: errors.New("boom")})
		_, _, err := s.ExtendContext(enterpriseContext())
		Expect(err).To(MatchError("boom"))
	})

	It("runs the extension's validation", func() {
		s.Variant(operatorv1.CalicoEnterprise).Controller(extensions.InstallationController, fakeController{validateErr: errors.New("invalid")})
		Expect(s.Validate(enterpriseContext())).To(MatchError("invalid"))
	})

	It("runs the watch hook of an extension that implements Watcher", func() {
		called := false
		s.Variant(operatorv1.CalicoEnterprise).Controller(extensions.InstallationController, watchingController{called: &called})
		Expect(s.SetupWatches(extensions.InstallationController, nil)).NotTo(HaveOccurred())
		Expect(called).To(BeTrue())
	})

	It("returns the base context and no validation error for a nil Set", func() {
		var nilSet *extensions.Set
		cc := enterpriseContext()
		cc.ClusterDomain = "real"
		rc, _, err := nilSet.ExtendContext(cc)
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.ClusterDomain).To(Equal("real"))
		Expect(nilSet.Validate(cc)).NotTo(HaveOccurred())
	})
})

func enterpriseContext() extensions.ControllerContext {
	return extensions.ControllerContext{
		RenderContext: extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}},
		Controller:    extensions.InstallationController,
	}
}

// fakeController is a ControllerExtension whose Validate and ExtendContext return
// configurable results.
type fakeController struct {
	err         error
	validateErr error
}

func (f fakeController) Validate(_ extensions.ControllerContext) error {
	return f.validateErr
}

func (f fakeController) ExtendContext(_ extensions.ControllerContext) (extensions.RenderContext, []certificatemanagement.KeyPairInterface, error) {
	if f.err != nil {
		return extensions.RenderContext{}, nil, f.err
	}
	return extensions.RenderContext{ClusterDomain: "from-fake"}, nil, nil
}

// watchingController is a fakeController that also implements the Watcher
// companion, recording that its watch hook ran.
type watchingController struct {
	fakeController
	called *bool
}

func (w watchingController) Watches(ctrlruntime.Controller) error {
	*w.called = true
	return nil
}
