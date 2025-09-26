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
		Registry:  "",
	}

	ComponentCalicoCNIFIPS = Component{
		Version:   "master-fips",
		ImageName: "cni",
		Registry:  "",
	}

	ComponentCalicoCNIWindows = Component{
		Version:   "master",
		ImageName: "cni-windows",
		Registry:  "",
	}

	ComponentCalicoCSRInitContainer = Component{
		Version:   "master",
		ImageName: "key-cert-provisioner",
		Registry:  "",
	}

	ComponentCalicoKubeControllers = Component{
		Version:   "master",
		ImageName: "kube-controllers",
		Registry:  "",
	}

	ComponentCalicoKubeControllersFIPS = Component{
		Version:   "master-fips",
		ImageName: "kube-controllers",
		Registry:  "",
	}

	ComponentCalicoNode = Component{
		Version:   "master",
		ImageName: "node",
		Registry:  "",
	}

	ComponentCalicoNodeFIPS = Component{
		Version:   "master-fips",
		ImageName: "node",
		Registry:  "",
	}

	ComponentCalicoNodeWindows = Component{
		Version:   "master",
		ImageName: "node-windows",
		Registry:  "",
	}

	ComponentCalicoTypha = Component{
		Version:   "master",
		ImageName: "typha",
		Registry:  "",
	}

	ComponentCalicoTyphaFIPS = Component{
		Version:   "master-fips",
		ImageName: "typha",
		Registry:  "",
	}

	ComponentCalicoFlexVolume = Component{
		Version:   "master",
		ImageName: "pod2daemon-flexvol",
		Registry:  "",
	}

	ComponentCalicoAPIServer = Component{
		Version:   "master",
		ImageName: "apiserver",
		Registry:  "",
	}

	ComponentCalicoAPIServerFIPS = Component{
		Version:   "master-fips",
		ImageName: "apiserver",
		Registry:  "",
	}

	ComponentCalicoCSI = Component{
		Version:   "master",
		ImageName: "csi",
		Registry:  "",
	}

	ComponentCalicoCSIFIPS = Component{
		Version:   "master-fips",
		ImageName: "csi",
		Registry:  "",
	}

	ComponentCalicoCSIRegistrar = Component{
		Version:   "master",
		ImageName: "node-driver-registrar",
		Registry:  "",
	}

	ComponentCalicoCSIRegistrarFIPS = Component{
		Version:   "master-fips",
		ImageName: "node-driver-registrar",
		Registry:  "",
	}

	ComponentCalicoGoldmane = Component{
		Version:   "master",
		ImageName: "goldmane",
		Registry:  "",
	}

	ComponentCalicoWhisker = Component{
		Version:   "master",
		ImageName: "whisker",
		Registry:  "",
	}

	ComponentCalicoWhiskerBackend = Component{
		Version:   "master",
		ImageName: "whisker-backend",
		Registry:  "",
	}

	ComponentCalicoEnvoyGateway = Component{
		Version:   "master",
		ImageName: "envoy-gateway",
		Registry:  "",
	}

	ComponentCalicoEnvoyProxy = Component{
		Version:   "master",
		ImageName: "envoy-proxy",
		Registry:  "",
	}

	ComponentCalicoEnvoyRatelimit = Component{
		Version:   "master",
		ImageName: "envoy-ratelimit",
		Registry:  "",
	}

	ComponentCalicoGuardian = Component{
		Version:   "master",
		ImageName: "guardian",
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
