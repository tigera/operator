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
	CalicoRelease string = "master"

	ComponentCalicoCNI = component{
		Version:  "master",
		Image:    "calico/cni",
		Registry: "",
	}

	ComponentCalicoCNIFIPS = component{
		Version:  "master-fips",
		Image:    "calico/cni",
		Registry: "",
	}

	ComponentCalicoCNIWindows = component{
		Version:  "master",
		Image:    "calico/cni-windows",
		Registry: "",
	}

	ComponentCalicoCSRInitContainer = component{
		Version:  "master",
		Image:    "calico/key-cert-provisioner",
		Registry: "",
	}

	ComponentCalicoKubeControllers = component{
		Version:  "master",
		Image:    "calico/kube-controllers",
		Registry: "",
	}

	ComponentCalicoKubeControllersFIPS = component{
		Version:  "master-fips",
		Image:    "calico/kube-controllers",
		Registry: "",
	}

	ComponentCalicoNode = component{
		Version:  "master",
		Image:    "calico/node",
		Registry: "",
	}

	ComponentCalicoNodeFIPS = component{
		Version:  "master-fips",
		Image:    "calico/node",
		Registry: "",
	}

	ComponentCalicoNodeWindows = component{
		Version:  "master",
		Image:    "calico/node-windows",
		Registry: "",
	}

	ComponentCalicoTypha = component{
		Version:  "master",
		Image:    "calico/typha",
		Registry: "",
	}

	ComponentCalicoTyphaFIPS = component{
		Version:  "master-fips",
		Image:    "calico/typha",
		Registry: "",
	}

	ComponentCalicoFlexVolume = component{
		Version:  "master",
		Image:    "calico/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentCalicoAPIServer = component{
		Version:  "master",
		Image:    "calico/apiserver",
		Registry: "",
	}

	ComponentCalicoAPIServerFIPS = component{
		Version:  "master-fips",
		Image:    "calico/apiserver",
		Registry: "",
	}

	ComponentCalicoCSI = component{
		Version:  "master",
		Image:    "calico/csi",
		Registry: "",
	}

	ComponentCalicoCSIFIPS = component{
		Version:  "master-fips",
		Image:    "calico/csi",
		Registry: "",
	}

	ComponentCalicoCSIRegistrar = component{
		Version:  "master",
		Image:    "calico/node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoCSIRegistrarFIPS = component{
		Version:  "master-fips",
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
		ComponentCalicoCSRInitContainer,
		ComponentCalicoKubeControllers,
		ComponentCalicoKubeControllersFIPS,
		ComponentCalicoNode,
		ComponentCalicoNodeFIPS,
		ComponentCalicoNodeWindows,
		ComponentCalicoTypha,
		ComponentCalicoTyphaFIPS,
		ComponentCalicoFlexVolume,
		ComponentOperatorInit,
		ComponentCalicoAPIServer,
		ComponentCalicoAPIServerFIPS,
		ComponentCalicoCSI,
		ComponentCalicoCSIFIPS,
		ComponentCalicoCSIRegistrar,
		ComponentCalicoCSIRegistrarFIPS,
	}
)
