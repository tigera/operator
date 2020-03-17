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
	VersionTigeraNode            = "v2.7.3"
	VersionTigeraTypha           = "v2.7.3"
	VersionTigeraKubeControllers = "v2.7.3"

	// API server images.
	VersionAPIServer   = "v2.7.3"
	VersionQueryServer = "v2.7.3"

	// Logging
	VersionFluentd = "v2.7.3"

	// Compliance images.
	VersionComplianceController  = "v2.7.3"
	VersionComplianceReporter    = "v2.7.3"
	VersionComplianceServer      = "v2.7.3"
	VersionComplianceSnapshotter = "v2.7.3"
	VersionComplianceBenchmarker = "v2.7.3"

	// Intrusion detection images.
	VersionIntrusionDetectionController   = "v2.7.3"
	VersionIntrusionDetectionJobInstaller = "v2.7.3"

	// Manager images.
	VersionManager        = "v2.7.3"
	VersionManagerProxy   = "v2.7.3"
	VersionManagerEsProxy = "v2.7.3"

	// ECK Elasticsearch images
	VersionECKOperator      = "0.9.0"
	VersionECKElasticsearch = "7.3.2"
	VersionECKKibana        = "7.3.2"
	VersionEsCurator        = "v2.7.3"

	VersionKibana = "v2.7.3"

	// Multicluster tunnel image.
	VersionGuardian = "v2.7.3"
)
