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
		Version: "v3.13.0",
		Digest:  "sha256:4fc7a1fc57da4fce36fe4383270ad46371a4c1a74dfbf7ceaaf7ff3c1b5bf9a6",
		Image:   "calico/cni",
	}
	
	
	ComponentCalicoKubeControllers = component{
		Version: "v3.13.0",
		Digest:  "sha256:0e25dcd553d1ba741a5452e1314731b9e3e26cd6d698cea11e21aece973b06aa",
		Image:   "calico/kube-controllers",
	}
	
	
	ComponentCalicoNode = component{
		Version: "v3.13.0",
		Digest:  "sha256:a7c4a36eb9e71be6f007013e74b2f795d8f659eb232516df84af6f75c97fb7b1",
		Image:   "calico/node",
	}
	
	
	ComponentCalicoTypha = component{
		Version: "v3.13.0",
		Digest:  "sha256:c3fd855b645b6b92f59aa867ad587a53f9e7bd14ffd9e9987be45bd26f71d2ac",
		Image:   "calico/typha",
	}
	
	
	ComponentFlexVolume = component{
		Version: "v3.13.0",
		Digest:  "sha256:43e36c722733d2e2c7a93d2b297fb2047534d11c58dd776e0cf65f2aecf8a806",
		Image:   "calico/pod2daemon-flexvol",
	}
	
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator-init",
	}
)
