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

package installation

import (
	"github.com/google/cel-go/cel"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The CEL expression from the NodeAddressAutodetection XValidation marker.
// Keep this in sync with the marker in api/v1/installation_types.go.
const autodetectCELRule = `[has(self.firstFound) && self.firstFound == true, has(self.kubernetes), size(self.interface) > 0, size(self.skipInterface) > 0, size(self.canReach) > 0, size(self.cidrs) > 0].filter(x, x).size() <= 1`

var _ = Describe("NodeAddressAutodetection CEL validation", func() {
	var prg cel.Program

	BeforeEach(func() {
		env, err := cel.NewEnv(
			cel.Variable("self", cel.MapType(cel.StringType, cel.DynType)),
		)
		Expect(err).NotTo(HaveOccurred())
		ast, iss := env.Compile(autodetectCELRule)
		Expect(iss.Err()).NotTo(HaveOccurred())
		prg, err = env.Program(ast)
		Expect(err).NotTo(HaveOccurred())
	})

	eval := func(obj map[string]any) bool {
		// String fields default to "" in CRD schemas.
		withDefaults := map[string]any{
			"interface":     "",
			"skipInterface": "",
			"canReach":      "",
			"cidrs":         []any{},
		}
		for k, v := range obj {
			withDefaults[k] = v
		}
		out, _, err := prg.Eval(map[string]any{"self": withDefaults})
		Expect(err).NotTo(HaveOccurred())
		result, ok := out.Value().(bool)
		Expect(ok).To(BeTrue())
		return result
	}

	DescribeTable("should allow single or no methods",
		func(obj map[string]any) { Expect(eval(obj)).To(BeTrue()) },
		Entry("empty", map[string]any{}),
		Entry("firstFound", map[string]any{"firstFound": true}),
		Entry("firstFound false", map[string]any{"firstFound": false}),
		Entry("interface", map[string]any{"interface": "eth0"}),
		Entry("skipInterface", map[string]any{"skipInterface": "docker.*"}),
		Entry("canReach", map[string]any{"canReach": "8.8.8.8"}),
		Entry("cidrs", map[string]any{"cidrs": []any{"10.0.0.0/8"}}),
		Entry("kubernetes", map[string]any{"kubernetes": "NodeInternalIP"}),
		Entry("firstFound false + interface", map[string]any{"firstFound": false, "interface": "eth0"}),
		Entry("empty strings", map[string]any{"interface": "", "canReach": ""}),
		Entry("empty cidrs", map[string]any{"cidrs": []any{}}),
	)

	DescribeTable("should reject multiple methods",
		func(obj map[string]any) { Expect(eval(obj)).To(BeFalse()) },
		Entry("firstFound + interface", map[string]any{"firstFound": true, "interface": "eth0"}),
		Entry("interface + canReach", map[string]any{"interface": "eth0", "canReach": "8.8.8.8"}),
		Entry("kubernetes + cidrs", map[string]any{"kubernetes": "NodeInternalIP", "cidrs": []any{"10.0.0.0/8"}}),
		Entry("three methods", map[string]any{"firstFound": true, "interface": "eth0", "canReach": "8.8.8.8"}),
		Entry("skipInterface + canReach", map[string]any{"skipInterface": "docker.*", "canReach": "8.8.8.8"}),
	)
})
