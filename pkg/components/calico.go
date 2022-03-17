// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

// Components defined here are required to be kept in sync with
// config/calico_versions.yml

package components

import "github.com/tigera/operator/version"

var (
	CalicoRelease string = "release-v3.22"

	ComponentCalicoCNI = component{
		Version: "release-v3.22",
		Image:   "calico/cni",
	}

	ComponentCalicoKubeControllers = component{
		Version: "release-v3.22",
		Image:   "calico/kube-controllers",
	}

	ComponentCalicoNode = component{
		Version: "release-v3.22",
		Image:   "calico/node",
	}

	ComponentCalicoTypha = component{
		Version: "release-v3.22",
		Image:   "calico/typha",
	}

	ComponentFlexVolume = component{
		Version: "release-v3.22",
		Image:   "calico/pod2daemon-flexvol",
	}

	ComponentCalicoAPIServer = component{
		Version: "release-v3.22",
		Image:   "calico/apiserver",
	}

	ComponentWindows = component{
		Version: "release-v3.22",
		Image:   "calico/windows-upgrade",
	}
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator",
	}

	CalicoComponents = []component{
		ComponentCalicoCNI,
		ComponentCalicoKubeControllers,
		ComponentCalicoNode,
		ComponentCalicoTypha,
		ComponentFlexVolume,
		ComponentOperatorInit,
		ComponentCalicoAPIServer,
		ComponentWindows,
	}
)
