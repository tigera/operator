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
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var _ = Describe("Rendering tests", func() {
	var instance *operator.Installation
	var logBuffer bytes.Buffer
	var logWriter *bufio.Writer
	var typhaNodeTLS *render.TyphaNodeTLS
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{IPPools: []operator.IPPool{{CIDR: "192.168.1.0/16"}}},
				Registry:      "test-reg/",
			},
		}

		logWriter = bufio.NewWriter(&logBuffer)
		render.SetTestLogger(logf.ZapLoggerTo(logWriter, true))
		typhaNodeTLS = &render.TyphaNodeTLS{}
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
		// - 4 secrets for Typha comms (2 in operator namespace and 2 in calico namespace)
		// - 2 ConfigMap for Typha comms (1 in operator namespace and 1 in calico namespace)
		// - 6 typha resources (Service, SA, Role, Binding, Deployment, PodDisruptionBudget)
		// - 4 kube-controllers resources (ServiceAccount, ClusterRole, Binding, Deployment)
		// - 1 namespace
		// - 1 PriorityClass
		// - 14 custom resource definitions
		c, err := render.Calico(instance, nil, typhaNodeTLS, nil, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico})
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c.Render())).To(Equal(37))
	})

	It("should render all resources when variant is Tigera Secure", func() {
		// For this scenario, we expect the basic resources plus the following for Tigera Secure:
		// - X Same as default config
		// - 1 Service to expose calico/node metrics.
		// - 1 ns (tigera-prometheus)
		// - 11 TSEE crds
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		c, err := render.Calico(instance, nil, typhaNodeTLS, nil, operator.ProviderNone, render.NetworkConfig{CNI: render.CNICalico})
		Expect(err).To(BeNil(), "Expected Calico to create successfully %s", err)
		Expect(componentCount(c.Render())).To(Equal((37 + 1 + 1 + 14)))
	})
})

func componentCount(components []render.Component) int {
	count := 0
	for _, c := range components {
		count += len(c.Objects())
	}
	return count
}
