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

var (
	
	ComponentCalicoCNI = component{
		Version: "v3.11.1",
		Digest:  "sha256:0a71a4d0d616c4a38940de5535106e3ac3ed1313eebdb8284e17d284f24aa316",
		Image:   "calico/cni",
	}
	
	
	ComponentCalicoKubeControllers = component{
		Version: "v3.11.1",
		Digest:  "sha256:3c960e6af3c7bf2729334c71977131bb553431a34f05215af3d46d53504f85a0",
		Image:   "calico/kube-controllers",
	}
	
	
	ComponentCalicoNode = component{
		Version: "v3.11.1-with-auto-backend",
		Digest:  "sha256:51709a703c2542a77d2e01434163e2146c503727397bada612ed1dfb627a2844",
		Image:   "calico/node",
	}
	
	
	ComponentCalicoTypha = component{
		Version: "v3.11.1",
		Digest:  "sha256:a69b02b1a8238eb4ece412e03e74faa83ae97ddcbcff83a54ce464be5501c848",
		Image:   "calico/typha",
	}
	
	
	ComponentFlexVolume = component{
		Version: "v3.11.1",
		Digest:  "sha256:86192852a89823c81c1bc8ff5e7c7afb7c9083fa3e1d9ab39736778133533223",
		Image:   "calico/pod2daemon-flexvol",
	}
	
)
