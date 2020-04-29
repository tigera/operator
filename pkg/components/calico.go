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

import "github.com/tigera/operator/version"

var (

	ComponentCalicoCNI = component{
		Version: "v3.13.1",
		Digest:  "sha256:9b7c143fb84bf79a27cdd285468dcf85b7e1afaae340b0f41ea5fb5b8eb4d4fe",
		Image:   "calico/cni",
	}

	ComponentCalicoKubeControllers = component{
		Version: "v3.13.1",
		Digest:  "sha256:8ecfefc1a9df7ed266e570e8000067575d0ba1b2cb10ec5d9ca8b7adcc96d95f",
		Image:   "calico/kube-controllers",
	}

	ComponentCalicoNode = component{
		Version: "v3.13.1",
		Digest:  "sha256:cbd5bf2ed8cb93595d358b6f23d3937da1620e8a600c93efbb29f689790b882b",
		Image:   "calico/node",
	}

	ComponentCalicoTypha = component{
		Version: "v3.13.1",
		Digest:  "sha256:94242f0d638ea920ec7f4040730422d359447a31e4c6ef4f3269196d85ea2370",
		Image:   "calico/typha",
	}

	ComponentFlexVolume = component{
		Version: "v3.13.1",
		Digest:  "sha256:6d1095d343386940a04a672fbe5c5375d48dd237bcfaaa12f68f1a945edec43d",
		Image:   "calico/pod2daemon-flexvol",
	}

	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator-init",
	}
)
