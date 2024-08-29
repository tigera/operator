// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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
	CalicoRelease string = "v3.26.5"

	ComponentCalicoCNI = component{
		Version: "v3.26.5",
		Image:   "calico/cni",
	}

	ComponentCalicoCNIFIPS = component{
		Version: "v3.26.5-fips",
		Image:   "calico/cni",
	}

	ComponentCalicoKubeControllers = component{
		Version: "v3.26.5",
		Image:   "calico/kube-controllers",
	}

	ComponentCalicoKubeControllersFIPS = component{
		Version: "v3.26.5-fips",
		Image:   "calico/kube-controllers",
	}

	ComponentCalicoNode = component{
		Version: "v3.26.5",
		Image:   "calico/node",
	}

	ComponentCalicoNodeFIPS = component{
		Version: "v3.26.5-fips",
		Image:   "calico/node",
	}

	ComponentCalicoTypha = component{
		Version: "v3.26.5",
		Image:   "calico/typha",
	}

	ComponentCalicoTyphaFIPS = component{
		Version: "v3.26.5-fips",
		Image:   "calico/typha",
	}

	ComponentFlexVolume = component{
		Version: "v3.26.5",
		Image:   "calico/pod2daemon-flexvol",
	}

	ComponentCalicoAPIServer = component{
		Version: "v3.26.5",
		Image:   "calico/apiserver",
	}

	ComponentCalicoAPIServerFIPS = component{
		Version: "v3.26.5-fips",
		Image:   "calico/apiserver",
	}

	ComponentWindowsUpgrade = component{
		Version: "v3.26.5",
		Image:   "calico/windows-upgrade",
	}

	ComponentCalicoCSI = component{
		Version: "v3.26.5",
		Image:   "calico/csi",
	}

	ComponentCalicoCSIFIPS = component{
		Version: "v3.26.5-fips",
		Image:   "calico/csi",
	}

	ComponentCalicoCSIRegistrar = component{
		Version: "v3.26.5",
		Image:   "calico/node-driver-registrar",
	}

	ComponentCalicoCSIRegistrarFIPS = component{
		Version: "v3.26.5-fips",
		Image:   "calico/node-driver-registrar",
	}
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator",
	}

	CalicoImages = []component{
		ComponentCalicoCNI,
		ComponentCalicoCNIFIPS,
		ComponentCalicoKubeControllers,
		ComponentCalicoKubeControllersFIPS,
		ComponentCalicoNode,
		ComponentCalicoNodeFIPS,
		ComponentCalicoTypha,
		ComponentCalicoTyphaFIPS,
		ComponentFlexVolume,
		ComponentOperatorInit,
		ComponentCalicoAPIServer,
		ComponentCalicoAPIServerFIPS,
		ComponentWindowsUpgrade,
		ComponentCalicoCSI,
		ComponentCalicoCSIFIPS,
		ComponentCalicoCSIRegistrar,
		ComponentCalicoCSIRegistrarFIPS,
	}
)
