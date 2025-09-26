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

var (
	CalicoRelease string = "master"

	ComponentCalicoCNI = Component{
		Version:   "master",
		ImageName: "cni",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoCNIFIPS = Component{
		Version:   "master-fips",
		ImageName: "cni",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoCNIWindows = Component{
		Version:   "master",
		ImageName: "cni-windows",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoCSRInitContainer = Component{
		Version:   "master",
		ImageName: "key-cert-provisioner",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoKubeControllers = Component{
		Version:   "master",
		ImageName: "kube-controllers",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoKubeControllersFIPS = Component{
		Version:   "master-fips",
		ImageName: "kube-controllers",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoNode = Component{
		Version:   "master",
		ImageName: "node",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoNodeFIPS = Component{
		Version:   "master-fips",
		ImageName: "node",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoNodeWindows = Component{
		Version:   "master",
		ImageName: "node-windows",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoTypha = Component{
		Version:   "master",
		ImageName: "typha",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoTyphaFIPS = Component{
		Version:   "master-fips",
		ImageName: "typha",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoFlexVolume = Component{
		Version:   "master",
		ImageName: "pod2daemon-flexvol",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoAPIServer = Component{
		Version:   "master",
		ImageName: "apiserver",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoAPIServerFIPS = Component{
		Version:   "master-fips",
		ImageName: "apiserver",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoCSI = Component{
		Version:   "master",
		ImageName: "csi",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoCSIFIPS = Component{
		Version:   "master-fips",
		ImageName: "csi",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoCSIRegistrar = Component{
		Version:   "master",
		ImageName: "node-driver-registrar",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoCSIRegistrarFIPS = Component{
		Version:   "master-fips",
		ImageName: "node-driver-registrar",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoGoldmane = Component{
		Version:   "master",
		ImageName: "goldmane",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoWhisker = Component{
		Version:   "master",
		ImageName: "whisker",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoWhiskerBackend = Component{
		Version:   "master",
		ImageName: "whisker-backend",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoEnvoyGateway = Component{
		Version:   "master",
		ImageName: "envoy-gateway",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoEnvoyProxy = Component{
		Version:   "master",
		ImageName: "envoy-proxy",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoEnvoyRatelimit = Component{
		Version:   "master",
		ImageName: "envoy-ratelimit",
		ImagePath: CalicoImagePath,
		Registry:  "",
	}

	ComponentCalicoGuardian = Component{
		Version:   "master",
		ImageName: "guardian",
		ImagePath: CalicoImagePath,
		Registry:  "",
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
		ComponentCalicoWhisker,
		ComponentCalicoWhiskerBackend,
		ComponentCalicoEnvoyGateway,
		ComponentCalicoEnvoyProxy,
		ComponentCalicoEnvoyRatelimit,
		ComponentCalicoGuardian,
	}
)
