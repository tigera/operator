// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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
	CalicoRelease string = "master"

	ComponentCalicoCNI = Component{
		Version:  "master",
		Image:    "calico/cni",
		Registry: "",
	}

	ComponentCalicoCNIFIPS = Component{
		Version:  "master-fips",
		Image:    "calico/cni",
		Registry: "",
	}

	ComponentCalicoCNIWindows = Component{
		Version:  "master",
		Image:    "calico/cni-windows",
		Registry: "",
	}

	ComponentCalicoCSRInitContainer = Component{
		Version:  "master",
		Image:    "calico/key-cert-provisioner",
		Registry: "",
	}

	ComponentCalicoKubeControllers = Component{
		Version:  "master",
		Image:    "calico/kube-controllers",
		Registry: "",
	}

	ComponentCalicoKubeControllersFIPS = Component{
		Version:  "master-fips",
		Image:    "calico/kube-controllers",
		Registry: "",
	}

	ComponentCalicoNode = Component{
		Version:  "master",
		Image:    "calico/node",
		Registry: "",
	}

	ComponentCalicoNodeFIPS = Component{
		Version:  "master-fips",
		Image:    "calico/node",
		Registry: "",
	}

	ComponentCalicoNodeWindows = Component{
		Version:  "master",
		Image:    "calico/node-windows",
		Registry: "",
	}

	ComponentCalicoTypha = Component{
		Version:  "master",
		Image:    "calico/typha",
		Registry: "",
	}

	ComponentCalicoTyphaFIPS = Component{
		Version:  "master-fips",
		Image:    "calico/typha",
		Registry: "",
	}

	ComponentCalicoFlexVolume = Component{
		Version:  "master",
		Image:    "calico/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentCalicoAPIServer = Component{
		Version:  "master",
		Image:    "calico/apiserver",
		Registry: "",
	}

	ComponentCalicoAPIServerFIPS = Component{
		Version:  "master-fips",
		Image:    "calico/apiserver",
		Registry: "",
	}

	ComponentCalicoCSI = Component{
		Version:  "master",
		Image:    "calico/csi",
		Registry: "",
	}

	ComponentCalicoCSIFIPS = Component{
		Version:  "master-fips",
		Image:    "calico/csi",
		Registry: "",
	}

	ComponentCalicoCSIRegistrar = Component{
		Version:  "master",
		Image:    "calico/node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoCSIRegistrarFIPS = Component{
		Version:  "master-fips",
		Image:    "calico/node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoGoldmane = Component{
		Version:  "master",
		Image:    "calico/goldmane",
		Registry: "",
	}

	ComponentOperatorInit = Component{
		Version: version.VERSION,
		Image:   "tigera/operator",
	}

	CalicoImages = []Component{
		ComponentCalicoCNI,
		ComponentCalicoCNIFIPS,
		ComponentCalicoCNIWindows,
		ComponentCalicoCSRInitContainer,
		ComponentCalicoKubeControllers,
		ComponentCalicoKubeControllersFIPS,
		ComponentCalicoNode,
		ComponentCalicoNodeFIPS,
		ComponentCalicoNodeWindows,
		ComponentCalicoTypha,
		ComponentCalicoTyphaFIPS,
		ComponentCalicoFlexVolume,
		ComponentCalicoAPIServer,
		ComponentCalicoAPIServerFIPS,
		ComponentCalicoCSI,
		ComponentCalicoCSIFIPS,
		ComponentCalicoCSIRegistrar,
		ComponentCalicoCSIRegistrarFIPS,
		ComponentCalicoGoldmane,
	}
)
