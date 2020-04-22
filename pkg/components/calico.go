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
		Version: "v3.13.3",
		Digest:  "sha256:b32128da90c5cd71de77ffb6dec53d603ee4cd5d2e803ada93bce427310bc1dc",
		Image:   "calico/cni",
	}
	
	
	ComponentCalicoKubeControllers = component{
		Version: "v3.13.3",
		Digest:  "sha256:372afbd3e1a1a8259c85f754be6af41c8213b49d332b775c300c21c57b20c20a",
		Image:   "calico/kube-controllers",
	}
	
	
	ComponentCalicoNode = component{
		Version: "v3.13.3",
		Digest:  "sha256:e97e334f42670dcae613d0220b739b1c214c7d2961db8e6a8d7682013b0cdce2",
		Image:   "calico/node",
	}
	
	
	ComponentCalicoTypha = component{
		Version: "v3.13.3",
		Digest:  "sha256:7b1e3ffb7f130d4cee1e3882f18cfe323ffa391422d5609987189455b7b8bba2",
		Image:   "calico/typha",
	}
	
	
	ComponentFlexVolume = component{
		Version: "v3.13.3",
		Digest:  "sha256:b87afc5d16d70b6be78a5765f157e958b16f8c0d822339e9f7515dbe8711d304",
		Image:   "calico/pod2daemon-flexvol",
	}
	
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator-init",
	}
)
