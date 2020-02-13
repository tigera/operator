// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.11.1-with-auto-backend"
	DigestCalicoNode             = "sha256:d5dd82cf57a48b5297869bc69a57c0eca9d2ea4f7879f19fe1aa2520a8f37cf3"
	VersionCalicoCNI             = "v3.11.1"
	DigestCalicoCNI              = "sha256:dd5246a4630ea53a0563c4c9fc1d70a724a0efab423ed72063f373547f945666"
	VersionCalicoTypha           = "v3.11.1"
	DigestCalicoTypha            = "sha256:7c86403b89ce0da577da2562a5524afebb641dc869ea813ba48a5e011f5a61d2"
	VersionCalicoKubeControllers = "v3.11.1"
	DigestCalicoKubeControllers  = "sha256:3b0f6ceb8f359841f83f69713d7da1c169d73d4e78630a5b8738b742e54a9168"
	VersionFlexVolume            = "v3.11.1"
	DigestFlexVolume             = "sha256:2aa6baaaf352c25f3c9120dd79941e1ce6985bb23abd1d28b7c3bcd0f6ffadea"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.7.0-0.dev-188-gc5255d3"
	DigestTigeraNode             = "sha256:f3baafcfe0f5148917caa732dba491cc1ca254b12b7979e20f2b6a6f53f75f5c"
	VersionTigeraTypha           = "v2.7.0-0.dev-74-g67bc0b1"
	DigestTigeraTypha            = "sha256:4f58430a9533225fc23764c22c0ea0ceb166c751d75314db683be1c296c676c1"
	VersionTigeraKubeControllers = "v2.7.0-0.dev-109-gfa8b79c"
	DigestTigeraKubeControllers  = "sha256:0d3ab190236acad4431f11d9e7c930ff59e6889794c2e21c4543a697dd5938fb"

	// API server images.
	VersionAPIServer   = "v2.7.0-0.dev-32-gb094281f"
	DigestAPIServer    = "sha256:2d554bcf81aa3a6c5dcd5c0881cb75a302a6e017459c862466a03fe3b1b65aeb"
	VersionQueryServer = "v2.7.0-0.dev-26-g232a725"
	DigestQueryServer  = "sha256:3627a12ca28542119aee38d04294f34a06af0ad9d2a3f1c92f0b6105aa88b8ec"

	// Logging
	VersionFluentd = "v2.7.0-0.dev-4-gb1486b3"
	DigestFluentd  = "sha256:8848601ff34233b4d38d18fc0412c8cc2caf4760ce8cfe51c9c4472069de4089"

	// Compliance images.
	VersionComplianceController  = "v2.7.0-0.dev-38-g23b93c3"
	DigestComplianceController   = "sha256:3fa8ee484872ad1d038278e43a88be7e715377db03052e128bac420cf56f8cd4"
	VersionComplianceReporter    = "v2.7.0-0.dev-38-g23b93c3"
	DigestComplianceReporter     = "sha256:cc13da725771cb7e26fbab269090a97bbb2dd9978bc6cb03af33fca11d4f005e"
	VersionComplianceServer      = "v2.7.0-0.dev-38-g23b93c3"
	DigestComplianceServer       = "sha256:8eb1854922500c517cc2fffb64c8eeb3a270a70c0f54e2f49feecefe67c614d0"
	VersionComplianceSnapshotter = "v2.7.0-0.dev-38-g23b93c3"
	DigestComplianceSnapshotter  = "sha256:6e648c8e3172e3cf6b53d8dc50a14e2b30bbcd8b7fe9dd5e87aa186bdd68624c"
	VersionComplianceBenchmarker = "v2.7.0-0.dev-38-g23b93c3"
	DigestComplianceBenchmarker  = "sha256:2c0576d36882206ccda6ecbc1902babc16361c73fc725b7a63069ed0ba4c0370"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.7.0-0.dev-27-gd7ce71b"
	DigestIntrusionDetectionController    = "sha256:365f44da69573b308d09e3704be670b850fc8be190abd030f541195bb017cde0"
	VersionIntrusionDetectionJobInstaller = "v2.7.0-0.dev-27-gd7ce71b"
	DigestIntrusionDetectionJobInstaller  = "sha256:b5b088acca40262ffdbb7d099e33f7fc25e7422a3b2a43cbb67fb43f8eff1a8e"

	// Manager images.
	VersionManager        = "v2.7.0-0.dev-234-g952d0a82"
	DigestManager         = "sha256:96db6db901c9fd80fc5c1b9da20c4858837930192dacb5c43b40998fb0878a50"
	VersionManagerProxy   = "v2.7.0-0.dev-34-g4eac4a3"
	DigestManagerProxy    = "sha256:514f8fbe9b71ac3ffa783336f2d6ddccbb8edbfa09398b66433685325f85119f"
	VersionManagerEsProxy = "v2.7.0-0.dev-43-g422fefb"
	DigestManagerEsProxy  = "sha256:ac4e0f12afdb15a1bb5d80367d2ff2bb0b8ec8e4e1ec3c136835120cd9e4c6b1"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	DigestECKOperator       = "sha256:4110b88c5c69a5fa209eda572204b91c69454ae2a51c24fcc963f25ad12413d0"
	VersionECKElasticsearch = "7.3.2"
	DigestECKElasticsearch  = "sha256:5883982a7f565c99aa3b084cffa299e2e1c013f099502d75d53406234afe05dc"
	VersionECKKibana        = "7.3.2"
	DigestECKKibana         = "sha256:01ccd6ed750eaf8fb2e7a99f54c25b88a64a2f30ea82b9c3524ffa57a87d24b1"
	VersionEsCurator        = "v2.6.0-0.dev-25-gb04da05"
	DigestEsCurator         = "sha256:409cb7cbd2ee9bab71df20afc64876adf7c6fdd092f351736e873a199f09b135"

	VersionKibana = "7.3"
	DigestKibana  = "sha256:421ca7ace6cc72ec67dcb44ee294b5175386430c80349890ad8ca025c03e5aa2"

	// Multicluster tunnel image.
	VersionGuardian = "v2.7.0-0.dev-34-g4eac4a3"
	DigestGuardian  = "sha256:081672818e114add80593ee0f78be5c5c6b5f74e294037f5beabd2e75fff3916"
)
