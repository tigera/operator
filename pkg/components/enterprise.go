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
		Version: "v3.0.0-0.dev-32-g771e07c7",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentEckKibana = component{
		Version: "7.6.2",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "v3.0.0-0.dev-15-g466c351",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "7.6.2",
		Image:   "elasticsearch/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.0.1",
		Image:   "eck/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "v3.0.0-0.dev-10-gf2e83fb",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v3.0.0-0.dev-29-gfe7b046",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "v3.0.0-0.dev-12-g63e0f79",
		Image:   "tigera/fluentd",
	}

	ComponentGuardian = component{
		Version: "v3.0.0-0.dev-8-g4197ee4",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v3.0.0-0.dev-15-g466c351",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "v3.1.0.calient-0.dev-3-g3c84c12",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v3.0.0-0.dev-138-g711599c3",
		Image:   "tigera/cnx-manager",
	}

	ComponentManagerProxy = component{
		Version: "v3.0.0-0.dev-9-ge9b5d1c",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "v3.0.0-0.dev-27-gd8468ea",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "v3.0.0-0.dev-70-gae8763c",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v3.0.0-0.dev-82-gd804d79",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v3.0.0-0.dev-52-g8aa41da",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "v3.0.0-0.dev-53-gb3668d9",
		Image:   "tigera/cni",
	}
)
