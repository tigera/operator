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
	CalicoRelease string = "master"

	ComponentCalicoCNI = component{
		Version:  "os-flowlog",
		Image:    "tigera/cni",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoCNIFIPS = component{
		Version:  "os-flowlog-fips",
		Image:    "tigera/cni",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoKubeControllers = component{
		Version:  "os-flowlog",
		Image:    "tigera/kube-controllers",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoKubeControllersFIPS = component{
		Version:  "os-flowlog-fips",
		Image:    "tigera/kube-controllers",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoNode = component{
		Version:  "os-flowlog",
		Image:    "tigera/node",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoNodeFIPS = component{
		Version:  "os-flowlog-fips",
		Image:    "tigera/node",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoTypha = component{
		Version:  "os-flowlog",
		Image:    "tigera/typha",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoTyphaFIPS = component{
		Version:  "os-flowlog-fips",
		Image:    "tigera/typha",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentFlexVolume = component{
		Version:  "master",
		Image:    "calico/pod2daemon-flexvol",
		Registry: "",
	}

	ComponentCalicoAPIServer = component{
		Version:  "os-flowlog-amd64",
		Image:    "tigera/apiserver",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoAPIServerFIPS = component{
		Version:  "os-flowlog-amd64-fips",
		Image:    "tigera/apiserver",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentWindowsUpgrade = component{
		Version:  "master",
		Image:    "calico/windows-upgrade",
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

	ComponentCalicoFluentd = component{
		Version:  "os-flowlog",
		Image:    "tigera/fluentd",
		Registry: "gcr.io/unique-caldron-775/cnx/",
	}

	ComponentCalicoCSIRegistrarFIPS = component{
		Version:  "master-fips",
		Image:    "calico/node-driver-registrar",
		Registry: "",
	}

	ComponentCalicoGuardian = component{
		Version:  "os-flowlog",
		Image:    "tigera/guardian",
		Registry: "",
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
		ComponentCalicoFluentd,
		ComponentCalicoCSIRegistrarFIPS,
		ComponentCalicoGuardian,
	}
)
