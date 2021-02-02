// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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
	EnterpriseRelease string = "2021-02-01-v3-5-perquisitionnaient"

	ComponentAPIServer = component{
		Version: "v3.5.0-calient-0.dev-53-g45c3165d121a",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v3.5.0-calient-0.dev-132-gf9e20b5a8ccc",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v3.5.0-calient-0.dev-132-gf9e20b5a8ccc",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v3.5.0-calient-0.dev-132-gf9e20b5a8ccc",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v3.5.0-calient-0.dev-132-gf9e20b5a8ccc",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v3.5.0-calient-0.dev-132-gf9e20b5a8ccc",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentEckElasticsearch = component{
		Version: "7.10.1",
		Image:   "tigera/elasticsearch",
	}

	ComponentEckKibana = component{
		Version: "7.10.1",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "v3.5.0-0-g4e6405a4b5f8",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "release-calient-v3.5",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.2.1",
		Image:   "eck/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "v3.5.0-0-g1a6ce55966f6",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v3.5.0-calient-0.dev-220-g1b649e73cbc4",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "v3.5.0-0-g6a56ca90c28e",
		Image:   "tigera/fluentd",
	}

	ComponentFluentdWindows = component{
		Version: "v3.5.0-0-g6a56ca90c28e",
		Image:   "tigera/fluentd-windows",
	}

	ComponentGuardian = component{
		Version: "v3.5.0-0-gc70e6b5943ae",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v3.5.0-0-g4e6405a4b5f8",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "v3.5.0-calient-0.dev-15-g68a12737e58e",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v3.6.0-calient-0.dev-40-g2522a3dcb488",
		Image:   "tigera/cnx-manager",
	}

	ComponentDex = component{
		Version: "release-calient-v3.5",
		Image:   "tigera/dex",
	}

	ComponentManagerProxy = component{
		Version: "v3.5.0-0-gc70e6b5943ae",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "v3.5.0-0-g1e356142b309",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "v3.5.0-0-gad47751fbfc4",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v3.5.0-0-g34ed36b0f55f",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v3.5.0-0-gc92affaf94a8",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "v3.5.0-0-g80abfd7bc3b4",
		Image:   "tigera/cni",
	}

	ComponentCloudControllers = component{
		Version: "v3.5.0-0-gda7f1b8d0ecf",
		Image:   "tigera/cloud-controllers",
	}

	EnterpriseComponents = []component{
		ComponentAPIServer,
		ComponentComplianceBenchmarker,
		ComponentComplianceController,
		ComponentComplianceReporter,
		ComponentComplianceServer,
		ComponentComplianceSnapshotter,
		ComponentEckElasticsearch,
		ComponentEckKibana,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentEsCurator,
		ComponentEsProxy,
		ComponentFluentd,
		ComponentFluentdWindows,
		ComponentGuardian,
		ComponentIntrusionDetectionController,
		ComponentKibana,
		ComponentManager,
		ComponentDex,
		ComponentManagerProxy,
		ComponentQueryServer,
		ComponentTigeraKubeControllers,
		ComponentTigeraNode,
		ComponentTigeraTypha,
		ComponentTigeraCNI,
		ComponentCloudControllers,
	}
)
