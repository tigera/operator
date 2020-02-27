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
	VersionCalicoNode            = "v3.12.0"
	VersionCalicoCNI             = "v3.12.0"
	VersionCalicoTypha           = "v3.12.0"
	VersionCalicoKubeControllers = "v3.12.0"
	VersionFlexVolume            = "v3.12.0"
)

// This section contains images used when installing Tigera Secure.
const (
	// Overrides for Calico.
	VersionTigeraNode            = "v2.6.1"
	VersionTigeraTypha           = "v2.6.1"
	VersionTigeraKubeControllers = "v2.6.1"

	// API server images.
	VersionAPIServer   = "v2.6.1"
	VersionQueryServer = "v2.6.1"

	// Logging
	VersionFluentd = "v2.6.1"

	// Compliance images.
	VersionComplianceController  = "v2.6.1"
	VersionComplianceReporter    = "v2.6.1"
	VersionComplianceServer      = "v2.6.1"
	VersionComplianceSnapshotter = "v2.6.1"
	VersionComplianceBenchmarker = "v2.6.1"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.6.1"
	VersionIntrusionDetectionJobInstaller = "v2.6.1"

	// Manager images.
	VersionManager        = "v2.6.1"
	VersionManagerProxy   = "v2.6.1"
	VersionManagerEsProxy = "v2.6.1"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.6.1"

	VersionKibana = "v2.6.1"
)
