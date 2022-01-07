// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

// Default registries for Calico and Tigera.
const (
	CalicoRegistry = "docker.io/"
	TigeraRegistry = "gcr.io/unique-caldron-775/cnx/"
	// For production InitRegistry should match TigeraRegistry.
	// For the master branch and other testing scenarios we switch TigeraRegistry to
	// point to a testing repo but the init image will be pushed to quay, so having
	// these separate allows pulling the proper test images for the Tigera components
	// and Init image when testing.
	ECKRegistry    = "quay.io/"
	InitRegistry   = "quay.io/"
	K8sGcrRegistry = "gcr.io/"
)
