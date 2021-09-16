// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Tigera Secure Application Layer rendering tests", func() {
	var instance *operatorv1.ApplicationLayer
	var installation *operatorv1.InstallationSpec

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1.ApplicationLayer{}
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
		}
	})

	It("should render with a l7 collector configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: render.EnvoyConfigKey, ns: render.CalicoSystemNamespace, group: "apps", version: "v1", kind: "ConfigMap"},
			{name: render.L7LogCollectorDeamonsetName, ns: render.CalicoSystemNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.ApplicationLayer(nil, installation, rmeta.OSTypeLinux, instance)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := rtest.GetResource(resources, render.L7LogCollectorDeamonsetName, render.CalicoSystemNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

		proxyContainer := ds.Spec.Template.Spec.Containers[0]
		proxyEnvs := proxyContainer.Env

		expectedProxyEnvs := []corev1.EnvVar{
			{Name: "ENVOY_UID", Value: "0"},
			{Name: "ENVOY_GID", Value: "0"},
		}
		for _, expected := range expectedProxyEnvs {
			Expect(proxyEnvs).To(ContainElement(expected))
		}

		collectorContainer := ds.Spec.Template.Spec.Containers[1]
		collectorEnvs := collectorContainer.Env

		expectedCollectorEnvs := []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "0"},
			{Name: "FELIX_DIAL_TARGET", Value: "0"},
		}
		for _, element := range expectedCollectorEnvs {
			Expect(collectorEnvs).To(ContainElement(element))
		}

	})

})
