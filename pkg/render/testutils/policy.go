// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package testutils

import (
	. "github.com/onsi/gomega"

	"encoding/json"
	"io"
	"os"

	rtest "github.com/tigera/operator/pkg/render/common/test"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

// AllowTigeraScenario represents valid render cases for allow-tigera policies. Render components should test that their
// allow-tigera policies correctly adapt for each relevant potential case. Update if new scenarios arise.
type AllowTigeraScenario struct {
	ManagedCluster bool
	OpenShift      bool
	DPIEnabled     bool
}

type IPMode string

const (
	IPV4      IPMode = "IPV4"
	IPV6      IPMode = "IPV6"
	DualStack IPMode = "Dual-stack"
)

func GetAllowTigeraPolicyFromResources(name types.NamespacedName, resources []client.Object) *v3.NetworkPolicy {
	resource := rtest.GetResource(resources, name.Name, name.Namespace, "projectcalico.org", "v3", "NetworkPolicy")
	if resource == nil {
		return nil
	} else {
		return resource.(*v3.NetworkPolicy)
	}
}

func GetAllowTigeraGlobalPolicyFromResources(name string, resources []client.Object) *v3.GlobalNetworkPolicy {
	resource := rtest.GetGlobalResource(resources, name, "projectcalico.org", "v3", "GlobalNetworkPolicy")
	if resource == nil {
		return nil
	} else {
		return resource.(*v3.GlobalNetworkPolicy)
	}
}

func GetExpectedPolicyFromFile(name string) *v3.NetworkPolicy {
	jsonFile, err := os.Open(name)
	Expect(err).ShouldNot(HaveOccurred())
	defer jsonFile.Close()

	byteValue, err := io.ReadAll(jsonFile)
	Expect(err).ShouldNot(HaveOccurred())

	var policy v3.NetworkPolicy
	err = json.Unmarshal(byteValue, &policy)
	Expect(err).ShouldNot(HaveOccurred())

	return &policy
}

func GetExpectedGlobalPolicyFromFile(name string) *v3.GlobalNetworkPolicy {
	jsonFile, err := os.Open(name)
	Expect(err).ShouldNot(HaveOccurred())
	defer jsonFile.Close()

	byteValue, err := io.ReadAll(jsonFile)
	Expect(err).ShouldNot(HaveOccurred())

	var policy v3.GlobalNetworkPolicy
	err = json.Unmarshal(byteValue, &policy)
	Expect(err).ShouldNot(HaveOccurred())

	return &policy
}

// SelectPolicyByClusterTypeAndProvider simply selects a variant of a policy that varies depending on cluster and provider type.
func SelectPolicyByClusterTypeAndProvider(scenario AllowTigeraScenario,
	unmanagedNoProviderPolicy *v3.NetworkPolicy,
	unmanagedOpenshiftPolicy *v3.NetworkPolicy,
	managedNoProviderPolicy *v3.NetworkPolicy,
	managedOpenshiftPolicy *v3.NetworkPolicy,
) *v3.NetworkPolicy {
	switch scenario {
	case AllowTigeraScenario{ManagedCluster: false, OpenShift: false}:
		return unmanagedNoProviderPolicy
	case AllowTigeraScenario{ManagedCluster: false, OpenShift: true}:
		return unmanagedOpenshiftPolicy
	case AllowTigeraScenario{ManagedCluster: true, OpenShift: false}:
		return managedNoProviderPolicy
	case AllowTigeraScenario{ManagedCluster: true, OpenShift: true}:
		return managedOpenshiftPolicy
	default:
		return nil
	}
}

// SelectPolicyByProvider simply selects a variant of a policy that varies depending on provider type only.
func SelectPolicyByProvider(scenario AllowTigeraScenario, noProviderPolicy *v3.NetworkPolicy, openshiftProviderPolicy *v3.NetworkPolicy) *v3.NetworkPolicy {
	if scenario.OpenShift {
		return openshiftProviderPolicy
	} else {
		return noProviderPolicy
	}
}
