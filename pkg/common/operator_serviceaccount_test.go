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

package common

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// workaround to set the environment variable before the init() call in operator_servideaccount.go.
var _ struct{} = setEnvBeforeInit()

func setEnvBeforeInit() (x struct{}) {
	os.Setenv("OPERATOR_SERVICEACCOUNT", "tigera-operator-unit-test")
	return
}

var _ = Describe("Operator ServiceAccount name tests", func() {
	It("should read service account name from the environment variable", func() {
		Expect(OperatorServiceAccount()).To(Equal("tigera-operator-unit-test"))
	})
})
