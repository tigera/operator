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

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("controller extension", func() {
	ctx := context.Background()

	var r *extensions.Registry
	BeforeEach(func() {
		r = extensions.NewRegistry(operatorv1.CalicoEnterprise)
	})

	It("returns the base render inputs when no extension is registered", func() {
		install := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}
		eci, _, err := r.Controller(controller.Installation).ExtendInputs(ctx, controller.Inputs{
			RenderInputs: render.Inputs{Installation: install, ClusterDomain: "cluster.local"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(eci.RenderInputs.Installation).To(BeIdenticalTo(install))
		Expect(eci.RenderInputs.ClusterDomain).To(Equal("cluster.local"))
		Expect(eci.RenderInputs.Extension).To(BeNil())
	})

	It("runs the extension registered for the controller", func() {
		r.RegisterController(controller.Installation, fakeController{})
		eci, _, err := r.Controller(controller.Installation).ExtendInputs(ctx, inputs())
		Expect(err).NotTo(HaveOccurred())
		Expect(eci.RenderInputs.ClusterDomain).To(Equal("from-fake"))
	})

	It("does not run an extension registered for a different controller", func() {
		r.RegisterController(controller.Installation, fakeController{})
		eci, _, err := r.Controller(controller.APIServer).ExtendInputs(ctx, inputs())
		Expect(err).NotTo(HaveOccurred())
		Expect(eci.RenderInputs.ClusterDomain).To(BeEmpty())
	})

	It("surfaces the extension error", func() {
		r.RegisterController(controller.Installation, fakeController{err: errors.New("boom")})
		_, _, err := r.Controller(controller.Installation).ExtendInputs(ctx, inputs())
		Expect(err).To(MatchError("boom"))
	})

	It("reports unsupported configuration distinctly from any other failure", func() {
		r.RegisterController(controller.Installation, fakeController{err: extensions.InvalidConfigf("port %d not supported", 0)})
		_, _, err := r.Controller(controller.Installation).ExtendInputs(ctx, inputs())
		Expect(err).To(MatchError(extensions.ErrInvalidConfig))
		Expect(err.Error()).To(Equal("port 0 not supported"))
	})

	It("does not report an ordinary failure as unsupported configuration", func() {
		r.RegisterController(controller.Installation, fakeController{err: errors.New("boom")})
		_, _, err := r.Controller(controller.Installation).ExtendInputs(ctx, inputs())
		Expect(err).NotTo(MatchError(extensions.ErrInvalidConfig))
	})

	It("runs the watch hook of an extension that implements Watcher", func() {
		called := false
		r.RegisterController(controller.Installation, watchingController{called: &called})
		Expect(r.Watcher(controller.Installation).Watches(nil)).NotTo(HaveOccurred())
		Expect(called).To(BeTrue())
	})

	It("is a no-op watcher when the extension declares no watches", func() {
		r.RegisterController(controller.Installation, fakeController{})
		Expect(r.Watcher(controller.Installation).Watches(nil)).NotTo(HaveOccurred())
	})

	It("runs the defaulting hook of an extension that implements FelixConfigDefaulter", func() {
		r.RegisterController(controller.Installation, defaultingController{})
		updated, err := r.FelixConfigDefaulter(controller.Installation).DefaultFelixConfiguration(nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())
	})

	It("is a no-op defaulter when the extension defaults nothing", func() {
		r.RegisterController(controller.Installation, fakeController{})
		updated, err := r.FelixConfigDefaulter(controller.Installation).DefaultFelixConfiguration(nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse())
	})

	It("hands out no-ops for a nil registry, which is what the core operator runs with", func() {
		var none *extensions.Registry
		ci := inputs()
		ci.RenderInputs.ClusterDomain = "real"

		eci, managed, err := none.Controller(controller.Installation).ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())
		Expect(eci.RenderInputs.ClusterDomain).To(Equal("real"))
		Expect(managed).To(BeEmpty())

		Expect(none.Watcher(controller.Installation).Watches(nil)).NotTo(HaveOccurred())

		updated, err := none.FelixConfigDefaulter(controller.Installation).DefaultFelixConfiguration(nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse())
		Expect(none.Images()).To(BeNil())
	})
})

func inputs() controller.Inputs {
	return controller.Inputs{
		RenderInputs: render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}},
	}
}

// fakeController is a ControllerExtension whose ExtendInputs returns a configurable
// result.
type fakeController struct {
	err error
}

func (f fakeController) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	if f.err != nil {
		return ci, nil, f.err
	}
	ci.RenderInputs.ClusterDomain = "from-fake"
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

// defaultingController is a fakeController that also implements the
// FelixConfigDefaulter companion.
type defaultingController struct {
	fakeController
}

func (defaultingController) DefaultFelixConfiguration(*operatorv1.InstallationSpec, *v3.FelixConfiguration) (bool, error) {
	return true, nil
}
