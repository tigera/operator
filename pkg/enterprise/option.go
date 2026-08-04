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

package enterprise

// Option configures the extension Set built by New.
type Option func(*build)

// build holds what New needs that it can't discover from the cluster.
type build struct {
	cloud bool
}

// WithCloud marks the Set as belonging to a Calico Cloud install.
func WithCloud(cloud bool) Option {
	return func(b *build) {
		b.cloud = cloud
	}
}
