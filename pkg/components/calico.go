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
		Version: "v3.14.0-0.dev-24-g0cab7f2",
		Digest:  "",
		Image:   "calico/cni",
	}
	
	
	ComponentCalicoKubeControllers = component{
		Version: "v3.14.0-0.dev-30-g947e802",
		Digest:  "",
		Image:   "calico/kube-controllers",
	}
	
	
	ComponentCalicoNode = component{
		Version: "v3.14.0-0.dev-41-g28bcc6a",
		Digest:  "",
		Image:   "calico/node",
	}
	
	
	ComponentCalicoTypha = component{
		Version: "v3.14.0-0.dev-22-g303330a",
		Digest:  "",
		Image:   "calico/typha",
	}
	
	
	ComponentFlexVolume = component{
		Version: "v3.14.0-0.dev-0-g07caa12",
		Digest:  "",
		Image:   "calico/pod2daemon-flexvol",
	}
	
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator-init",
	}
)
