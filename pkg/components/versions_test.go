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

package components

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Enterprise version consistency", func() {
	It("should have matching eck-elasticsearch and eck-kibana versions", func() {
		Expect(ComponentEckElasticsearch.Version).To(Equal(ComponentEckKibana.Version),
			"eck-elasticsearch version %q must match eck-kibana version %q — update config/enterprise_versions.yml",
			ComponentEckElasticsearch.Version, ComponentEckKibana.Version)
	})
})
