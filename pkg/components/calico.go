// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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
	CalicoRelease string = "v3.26.1"

	ComponentCalicoCNI = component{
		Version:  "v3.26.1",
		Image:    "calico/cni",
		Registry: "",
	}

	ComponentCalicoCNIFIPS = component{
		Version:  "v3.26.1-fips",
		Image:    "calico/cni",
		Registry: "",
	}

	ComponentCalicoCNIWindows = component{
		Version:  "v3.26.1",
		Image:    "calico/cni-windows",
		Registry: "",
	}

	ComponentCalicoKubeControllers = component{
		Version:  "v3.26.1",
		Image:    "calico/kube-controllers",
		Registry: "",
	}

	ComponentCalicoKubeControllersFIPS = component{
		Version:  "v3.26.1-fips",
		Image:    "calico/kube-controllers",
		Registry: "",
	}

	ComponentCalicoNode = component{
		Version:  "v3.26.1",
		Image:    "calico/node",
		Registry: "",
	}

	ComponentCalicoNodeFIPS = component{
		Version:  "v3.26.1-fips",
		Image:    "calico/node",
		Registry: "",
	}

	ComponentCalicoNodeWindows = component{
		Version:  "v3.26.1",
		Image:    "calico/node-windows",
		Registry: "",
	}

	ComponentCalicoTypha = component{
		Version:  "v3.26.1",
		Image:    "calico/typha",
		Registry: "",
	}

	ComponentCalicoTyphaFIPS = component{
		Version:  "v3.26.1-fips",
		Image:    "calico/typha",
		Registry: "",
	}

	ComponentFlexVolume = component{
		Version:  "v3.26.1",
		Image:    "calico/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentCalicoAPIServer = component{
		Version:  "v3.26.1",
		Image:    "calico/apiserver",
		Registry: "",
	}

	ComponentCalicoAPIServerFIPS = component{
		Version:  "v3.26.1-fips",
		Image:    "calico/apiserver",
		Registry: "",
	}

	ComponentCalicoCSI = component{
		Version:  "v3.26.1",
		Image:    "calico/csi",
		Registry: "",
	}

	ComponentCalicoCSIFIPS = component{
		Version:  "v3.26.1-fips",
		Image:    "calico/csi",
		Registry: "",
	}

	ComponentCalicoCSIRegistrar = component{
		Version:  "v3.26.1",
		Image:    "calico/node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoCSIRegistrarFIPS = component{
		Version:  "v3.26.1-fips",
		Image:    "calico/node-driver-registrar",
		Registry: "",
	}
	ComponentOperatorInit = component{
		Version: version.VERSION,
		Image:   "tigera/operator",
	}

	CalicoImages = []component{
		ComponentCalicoCNI,
		ComponentCalicoCNIFIPS,
		ComponentCalicoCNIWindows,
		ComponentCalicoKubeControllers,
		ComponentCalicoKubeControllersFIPS,
		ComponentCalicoNode,
		ComponentCalicoNodeFIPS,
		ComponentCalicoNodeWindows,
		ComponentCalicoTypha,
		ComponentCalicoTyphaFIPS,
		ComponentFlexVolume,
		ComponentOperatorInit,
		ComponentCalicoAPIServer,
		ComponentCalicoAPIServerFIPS,
		ComponentCalicoCSI,
		ComponentCalicoCSIFIPS,
		ComponentCalicoCSIRegistrar,
		ComponentCalicoCSIRegistrarFIPS,
	}
)
