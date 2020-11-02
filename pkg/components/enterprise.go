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

var (
	ComponentAPIServer = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentEckElasticsearch = component{
		Version: "7.6.2",
		Image:   "tigera/elasticsearch",
	}

	ComponentEckKibana = component{
		Version: "7.6.2",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.2.1",
		Image:   "eck/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/fluentd",
	}

	ComponentGuardian = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/cnx-manager",
	}

	ComponentDex = component{
		Version: "v2.25.0",
		Image:   "dexidp/dex",
	}

	ComponentManagerProxy = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/cni",
	}

	ComponentCloudControllers = component{
		Version: "release-calient-v3.4",
		Image:   "tigera/cloud-controllers",
	}
)
