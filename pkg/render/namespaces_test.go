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

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "github.com/tigera/operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("Namespace rendering tests", func() {
	var installation *v1.InstallationSpec
	BeforeEach(func() {
		installation = &v1.InstallationSpec{Variant: v1.Calico, KubernetesProvider: v1.ProviderNone}
	})

	It("should render a namespace", func() {
		component := render.Namespaces(installation, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(1))
		ExpectResource(resources[0], "calico-system", "", "", "v1", "Namespace")
		meta := resources[0].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("calico-system"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))
	})

	It("should render a namespace for openshift", func() {
		installation.KubernetesProvider = v1.ProviderOpenShift
		component := render.Namespaces(installation, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(1))
		ExpectResource(resources[0], "calico-system", "", "", "v1", "Namespace")
		meta := resources[0].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()["openshift.io/run-level"]).To(Equal("0"))
		Expect(meta.GetAnnotations()["openshift.io/node-selector"]).To(Equal(""))
	})

	It("should render a namespace for tigera-dex on EE", func() {
		installation.Variant = v1.TigeraSecureEnterprise
		component := render.Namespaces(installation, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(2))
		ExpectResource(resources[1], "tigera-dex", "", "", "v1", "Namespace")
		meta := resources[1].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()["name"]).To(Equal("tigera-dex"))
		Expect(meta.GetLabels()).NotTo(ContainElement("openshift.io/run-level"))
		Expect(meta.GetAnnotations()).NotTo(ContainElement("openshift.io/node-selector"))
	})

	It("should render a namespace for tigera-dex for openshift on EE", func() {
		installation.Variant = v1.TigeraSecureEnterprise
		installation.KubernetesProvider = v1.ProviderOpenShift
		component := render.Namespaces(installation, nil)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(2))
		ExpectResource(resources[1], "tigera-dex", "", "", "v1", "Namespace")
		meta := resources[1].(metav1.ObjectMetaAccessor).GetObjectMeta()
		Expect(meta.GetLabels()["openshift.io/run-level"]).To(Equal("0"))
		Expect(meta.GetAnnotations()["openshift.io/node-selector"]).To(Equal(""))
	})
})
