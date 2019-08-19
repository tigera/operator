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
	"bufio"
	"bytes"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var _ = Describe("Rendering tests", func() {
	var instance *operator.Installation
	var client client.Client
	var logBuffer bytes.Buffer
	var logWriter *bufio.Writer
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				IPPools: []operator.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Registry:  "test-reg/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
			},
		}

		client = fake.NewFakeClient()

		logWriter = bufio.NewWriter(&logBuffer)
		render.SetTestLogger(logf.ZapLoggerTo(logWriter, true))
	})
	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			logWriter.Flush()
			fmt.Printf("Logs:\n%s\n", logBuffer.String())
		}
	})

	It("should render all resources for a default configuration", func() {
		// For this scenario, we expect the basic resources
		// created by the controller without any optional ones. These include:
		// - 5 node resources (ServiceAccount, ClusterRole, Binding, ConfigMap, DaemonSet)
		// - 4 kube-controllers resources (ServiceAccount, ClusterRole, Binding, Deployment)
		// - 1 namespace
		// - 1 PriorityClass
		// - 14 custom resource definitions
		c := render.Calico(instance, client, notOpenshift)
		t := render.TigeraSecure(instance, client, notOpenshift)
		components := append(c.Render(), t.Render()...)
		Expect(componentCount(components)).To(Equal(25))
	})

	It("should render all resources when variant is Tigera Secure", func() {
		// For this scenario, we expect the basic resources plus the following 17 resources for Tigera Secure:
		// - 1 additional namespace
		// - 1 APIService
		// - 2 ClusterRole
		// - 3 ClusterRoleBindings
		// - 1 RoleBinding
		// - 1 ConfigMap
		// - 1 Deployment
		// - 1 Service
		// - 1 ServiceAccount
		// - 1 PriorityClass
		// - 2 Secrets
		// - 14 custom resource definitions (calico)
		// - 6 custom resource definitions (tsee)
		// - 27 Compliance
		// - 7 Intrusion Detection
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		c := render.Calico(instance, client, notOpenshift)
		t := render.TigeraSecure(instance, client, notOpenshift)
		components := append(c.Render(), t.Render()...)
		Expect(componentCount(components)).To(Equal(80))
	})
})

func componentCount(components []render.Component) int {
	count := 0
	for _, c := range components {
		count += len(c.Objects())
	}
	return count
}
