// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package nonclusterhost_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/nonclusterhost"
)

var _ = Describe("NonClusterHost rendering tests", func() {
	var cfg *nonclusterhost.Config

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())

		cfg = &nonclusterhost.Config{
			NonClusterHost: operatorv1.NonClusterHostSpec{
				Endpoint: "https://1.2.3.4:5678",
			},
		}
	})

	It("should render NonClusterHost resources", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-noncluster-host", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-noncluster-host", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-noncluster-host", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-noncluster-host", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component := nonclusterhost.NonClusterHost(cfg)
		toCreate, toDelete := component.Objects()
		Expect(toCreate).To(HaveLen(len(expectedResources)))
		Expect(toDelete).To(BeNil())

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(toCreate[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		secret := rtest.GetResource(toCreate, "tigera-noncluster-host", "calico-system", "", "v1", "Secret").(*corev1.Secret)
		Expect(secret.GetObjectMeta().GetAnnotations()).To(HaveKeyWithValue("kubernetes.io/service-account.name", "tigera-noncluster-host"))
		Expect(secret.Type).To(Equal(corev1.SecretType("kubernetes.io/service-account-token")))
	})
})
