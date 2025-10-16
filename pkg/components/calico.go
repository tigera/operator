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
		Image:     "cni",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCNIFIPS = Component{
		Version:   "master-fips",
		Image:     "cni",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCNIWindows = Component{
		Version:   "master",
		Image:     "cni-windows",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCSRInitContainer = Component{
		Version:   "master",
		Image:     "key-cert-provisioner",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoKubeControllers = Component{
		Version:   "master",
		Image:     "kube-controllers",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoKubeControllersFIPS = Component{
		Version:   "master-fips",
		Image:     "kube-controllers",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoNode = Component{
		Version:   "master",
		Image:     "node",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoNodeFIPS = Component{
		Version:   "master-fips",
		Image:     "node",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoNodeWindows = Component{
		Version:   "master",
		Image:     "node-windows",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoTypha = Component{
		Version:   "master",
		Image:     "typha",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoTyphaFIPS = Component{
		Version:   "master-fips",
		Image:     "typha",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoFlexVolume = Component{
		Version:   "master",
		Image:     "pod2daemon-flexvol",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoAPIServer = Component{
		Version:   "master",
		Image:     "apiserver",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoAPIServerFIPS = Component{
		Version:   "master-fips",
		Image:     "apiserver",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCSI = Component{
		Version:   "master",
		Image:     "csi",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCSIFIPS = Component{
		Version:   "master-fips",
		Image:     "csi",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCSIRegistrar = Component{
		Version:   "master",
		Image:     "node-driver-registrar",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoCSIRegistrarFIPS = Component{
		Version:   "master-fips",
		Image:     "node-driver-registrar",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoGoldmane = Component{
		Version:   "master",
		Image:     "goldmane",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoWhisker = Component{
		Version:   "master",
		Image:     "whisker",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoWhiskerBackend = Component{
		Version:   "master",
		Image:     "whisker-backend",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyGateway = Component{
		Version:   "master",
		Image:     "envoy-gateway",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyProxy = Component{
		Version:   "master",
		Image:     "envoy-proxy",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoEnvoyRatelimit = Component{
		Version:   "master",
		Image:     "envoy-ratelimit",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
	}

	ComponentCalicoGuardian = Component{
		Version:   "master",
		Image:     "guardian",
		Registry:  "",
		imagePath: "",
		variant:   calicoVariant,
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
