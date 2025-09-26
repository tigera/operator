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
		Version:  "master",
		Image:    "cni",
		Registry: "",
	}

	ComponentCalicoCNIFIPS = Component{
		Version:  "master-fips",
		Image:    "cni",
		Registry: "",
	}

	ComponentCalicoCNIWindows = Component{
		Version:  "master",
		Image:    "cni-windows",
		Registry: "",
	}

	ComponentCalicoCSRInitContainer = Component{
		Version:  "master",
		Image:    "key-cert-provisioner",
		Registry: "",
	}

	ComponentCalicoKubeControllers = Component{
		Version:  "master",
		Image:    "kube-controllers",
		Registry: "",
	}

	ComponentCalicoKubeControllersFIPS = Component{
		Version:  "master-fips",
		Image:    "kube-controllers",
		Registry: "",
	}

	ComponentCalicoNode = Component{
		Version:  "master",
		Image:    "node",
		Registry: "",
	}

	ComponentCalicoNodeFIPS = Component{
		Version:  "master-fips",
		Image:    "node",
		Registry: "",
	}

	ComponentCalicoNodeWindows = Component{
		Version:  "master",
		Image:    "node-windows",
		Registry: "",
	}

	ComponentCalicoTypha = Component{
		Version:  "master",
		Image:    "typha",
		Registry: "",
	}

	ComponentCalicoTyphaFIPS = Component{
		Version:  "master-fips",
		Image:    "typha",
		Registry: "",
	}

	ComponentCalicoFlexVolume = Component{
		Version:  "master",
		Image:    "pod2daemon-flexvol",
		Registry: "",
	}

	ComponentCalicoAPIServer = Component{
		Version:  "master",
		Image:    "apiserver",
		Registry: "",
	}

	ComponentCalicoAPIServerFIPS = Component{
		Version:  "master-fips",
		Image:    "apiserver",
		Registry: "",
	}

	ComponentCalicoCSI = Component{
		Version:  "master",
		Image:    "csi",
		Registry: "",
	}

	ComponentCalicoCSIFIPS = Component{
		Version:  "master-fips",
		Image:    "csi",
		Registry: "",
	}

	ComponentCalicoCSIRegistrar = Component{
		Version:  "master",
		Image:    "node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoCSIRegistrarFIPS = Component{
		Version:  "master-fips",
		Image:    "node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoGoldmane = Component{
		Version:  "master",
		Image:    "goldmane",
		Registry: "",
	}

	ComponentCalicoWhisker = Component{
		Version:  "master",
		Image:    "whisker",
		Registry: "",
	}

	ComponentCalicoWhiskerBackend = Component{
		Version:  "master",
		Image:    "whisker-backend",
		Registry: "",
	}

	ComponentCalicoEnvoyGateway = Component{
		Version:  "master",
		Image:    "envoy-gateway",
		Registry: "",
	}

	ComponentCalicoEnvoyProxy = Component{
		Version:  "master",
		Image:    "envoy-proxy",
		Registry: "",
	}

	ComponentCalicoEnvoyRatelimit = Component{
		Version:  "master",
		Image:    "envoy-ratelimit",
		Registry: "",
	}

	ComponentCalicoGuardian = Component{
		Version:  "master",
		Image:    "guardian",
		Registry: "",
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
