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
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("controller extension", func() {
	ctx := context.Background()

	var s *extensions.Set
	BeforeEach(func() {
		s = extensions.NewSet()
	})

	It("returns the base render inputs when the variant has no extension", func() {
		install := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}
		eci, _, err := s.ExtendInputs(ctx, controller.Inputs{
			Inputs:     render.Inputs{Installation: install, ClusterDomain: "cluster.local"},
			Controller: controller.Installation,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(eci.Installation).To(BeIdenticalTo(install))
		Expect(eci.ClusterDomain).To(Equal("cluster.local"))
		Expect(eci.Extension).To(BeNil())
	})

	It("runs the extension registered for the installation variant", func() {
		s.Variant(operatorv1.CalicoEnterprise).Controller(controller.Installation, fakeController{})
		eci, _, err := s.ExtendInputs(ctx, enterpriseInputs())
		Expect(err).NotTo(HaveOccurred())
		Expect(eci.ClusterDomain).To(Equal("from-fake"))
	})

	It("ignores an extension registered for a different variant", func() {
		s.Variant(operatorv1.CalicoEnterprise).Controller(controller.Installation, fakeController{})
		eci, _, err := s.ExtendInputs(ctx, controller.Inputs{
			Inputs:     render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}, ClusterDomain: "real"},
			Controller: controller.Installation,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(eci.ClusterDomain).To(Equal("real"))
	})

	It("surfaces the extension error", func() {
		s.Variant(operatorv1.CalicoEnterprise).Controller(controller.Installation, fakeController{err: errors.New("boom")})
		_, _, err := s.ExtendInputs(ctx, enterpriseInputs())
		Expect(err).To(MatchError("boom"))
	})

	It("runs the extension's validation", func() {
		s.Variant(operatorv1.CalicoEnterprise).Controller(controller.Installation, fakeController{validateErr: errors.New("invalid")})
		Expect(s.Validate(ctx, enterpriseInputs())).To(MatchError("invalid"))
	})

	It("runs the watch hook of an extension that implements Watcher", func() {
		called := false
		s.Variant(operatorv1.CalicoEnterprise).Controller(controller.Installation, watchingController{called: &called})
		Expect(s.SetupWatches(controller.Installation, nil)).NotTo(HaveOccurred())
		Expect(called).To(BeTrue())
	})

	It("returns the base context and no validation error for a nil Set", func() {
		var nilSet *extensions.Set
		ci := enterpriseInputs()
		ci.ClusterDomain = "real"
		eci, _, err := nilSet.ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())
		Expect(eci.ClusterDomain).To(Equal("real"))
		Expect(nilSet.Validate(ctx, ci)).NotTo(HaveOccurred())
	})
})

func enterpriseInputs() controller.Inputs {
	return controller.Inputs{
		Inputs:     render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}},
		Controller: controller.Installation,
	}
}

// fakeController is a ControllerExtension whose Validate and ExtendInputs return
// configurable results.
type fakeController struct {
	err         error
	validateErr error
}

func (f fakeController) Validate(_ context.Context, _ controller.Inputs) error {
	return f.validateErr
}

func (f fakeController) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	if f.err != nil {
		return ci, nil, f.err
	}
	ci.ClusterDomain = "from-fake"
	return ci, nil, nil
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
