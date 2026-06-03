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

package render_test

import (
	. "github.com/onsi/ginkgo/v2"

	"github.com/tigera/operator/pkg/enterprise"
)

// Register the enterprise extensions once for the whole render suite. This wires
// two things the suite relies on:
//   - the image override, which the Objects()-level render tests pick up through
//     ResolveImages (e.g. the enterprise node image), and
//   - the modifiers, which node_enterprise_test.go applies explicitly to real
//     render output to check they still match it.
//
// The plain Objects()-level tests do not run modifiers - those only run at the
// componentHandler - so registering here does not change their output.
var _ = BeforeSuite(func() {
	enterprise.Register()
})
