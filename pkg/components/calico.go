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
		Version: "v3.12.0",
		Digest:  "sha256:dc3bc525f1d3b794db1f2a7ceb7d8b84699d13e1431fbc117063f7e2075ff4b5",
		Image:   "calico/cni",
	}
	
	
	ComponentCalicoKubeControllers = component{
		Version: "v3.12.0",
		Digest:  "sha256:edf14a5bcc663d2b0013b1830469626b7aa27206cbc7715ed83c042890ca5837",
		Image:   "calico/kube-controllers",
	}
	
	
	ComponentCalicoNode = component{
		Version: "v3.12.0",
		Digest:  "sha256:3226b047a7034918a05c986347c5fb4d2cce6d0844f325851bfba586271ee617",
		Image:   "calico/node",
	}
	
	
	ComponentCalicoTypha = component{
		Version: "v3.12.0",
		Digest:  "sha256:3baf9aef445a3224160748d6f560426eab798d6c65620020b2466e114bf6805f",
		Image:   "calico/typha",
	}
	
	
	ComponentFlexVolume = component{
		Version: "v3.12.0",
		Digest:  "sha256:2bf967507ad1adb749f3484b5d39e7d7b8700c4a0f836e8093dae5c57a585ccf",
		Image:   "calico/pod2daemon-flexvol",
	}
	
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator-init",
	}
)
