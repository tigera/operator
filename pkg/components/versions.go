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

// This file is auto generated so if you are changing or updating it
// then you should instead consider updating hack/gen-versions/main.go,
// config/os_versions.yaml, or config/ee_versions.yaml.

package components

// This section contains images used when installing open-source Calico.
const (
	VersionCalicoNode            = "v3.12.2"
	VersionCalicoCNI             = "release-v3.12"
	VersionCalicoTypha           = "v3.12.2"
	VersionCalicoKubeControllers = "v3.12.2"
	VersionFlexVolume            = "v3.12.2"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "release-v2.7"
	VersionTigeraTypha           = "release-v2.7"
	VersionTigeraKubeControllers = "release-v2.7"

	// API server images.
	VersionAPIServer   = "release-v2.7"
	VersionQueryServer = "release-v2.7"

	// Logging
	VersionFluentd = "release-v2.7"

	// Compliance images.
	VersionComplianceController  = "release-v2.7"
	VersionComplianceReporter    = "release-v2.7"
	VersionComplianceServer      = "release-v2.7"
	VersionComplianceSnapshotter = "release-v2.7"
	VersionComplianceBenchmarker = "release-v2.7"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "release-v2.7"
	VersionIntrusionDetectionJobInstaller = "release-v2.7"

	// Manager images.
	VersionManager        = "release-v2.7"
	VersionManagerProxy   = "release-v2.7"
	VersionManagerEsProxy = "release-v2.7"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "release-v2.7"

	VersionKibana        = "release-v2.7"
	VersionElasticsearch = "release-v2.7"

	// Multicluster tunnel image.
	VersionGuardian = "release-v2.7"
)
