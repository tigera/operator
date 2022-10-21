// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
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

package render_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("CSI rendering tests", func() {
	var defaultInstance *operatorv1.InstallationSpec
	var cfg render.CSIConfiguration

	BeforeEach(func() {
		defaultInstance = &operatorv1.InstallationSpec{
			KubeletVolumePluginPath: "/var/lib/kubelet",
		}
		cfg = render.CSIConfiguration{
			Installation: defaultInstance,
		}
	})

	It("should render properly with KubeletVolumePluginPath default value", func() {
		expectedCreateObjs := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "csi.tigera.io", ns: "", group: "storage", version: "v1", kind: "CSIDriver"},
			{name: "csi-node-driver", ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}
		comp := render.CSI(&cfg)
		Expect(comp.ResolveImages(nil)).To(BeNil())
		createObjs, delObjs := comp.Objects()

		Expect(len(delObjs)).To(Equal(0))
		Expect(len(createObjs)).To(Equal(len(expectedCreateObjs)))

		for i, expectedRes := range expectedCreateObjs {
			rtest.ExpectResource(createObjs[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should render properly when KubeletVolumePluginPath is set to 'None'", func() {
		cfg.Installation.KubeletVolumePluginPath = "None"
		expectedDelObjs := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "csi.tigera.io", ns: "", group: "storage", version: "v1", kind: "CSIDriver"},
			{name: "csi-node-driver", ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}
		comp := render.CSI(&cfg)
		Expect(comp.ResolveImages(nil)).To(BeNil())
		createObjs, delObjs := comp.Objects()

		Expect(len(createObjs)).To(Equal(0))
		Expect(len(delObjs)).To(Equal(len(expectedDelObjs)))

		for i, expectedRes := range expectedDelObjs {
			rtest.ExpectResource(delObjs[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should propagate imagePullSecrets and registry Installation field changes to DaemonSet", func() {
		privatePullSecret := []corev1.LocalObjectReference{
			{
				Name: "privatePullSecret",
			},
		}
		privateRegistry := "private/registry.io/"
		cfg.Installation.ImagePullSecrets = privatePullSecret
		cfg.Installation.Registry = privateRegistry
		resources, _ := render.CSI(&cfg).Objects()
		ds := rtest.GetResource(resources, render.CSIDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.ImagePullSecrets).To(Equal(privatePullSecret))
		for _, container := range ds.Spec.Template.Spec.Containers {
			Expect(strings.HasPrefix(container.Image, privateRegistry))
		}
	})

	It("should set priority class to system-node-critical", func() {
		resources, _ := render.CSI(&cfg).Objects()
		ds := rtest.GetResource(resources, render.CSIDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal("system-node-critical"))
	})
})
