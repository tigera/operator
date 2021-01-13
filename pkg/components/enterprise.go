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
		Version: "master",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "master",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "master",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "master",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "master",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "master",
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
		Version: "master",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "master",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.2.1",
		Image:   "eck/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "master",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "master",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "master",
		Image:   "tigera/fluentd",
	}

	ComponentFluentdWindows = component{
		Version: "master",
		Image:   "tigera/fluentd-windows",
	}

	ComponentGuardian = component{
		Version: "master",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "master",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "master",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "master",
		Image:   "tigera/cnx-manager",
	}

	ComponentDex = component{
		Version: "master",
		Image:   "tigera/dex",
	}

	ComponentManagerProxy = component{
		Version: "master",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "master",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "master",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "master",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "master",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "master",
		Image:   "tigera/cni",
	}

	ComponentCloudControllers = component{
		Version: "master",
		Image:   "tigera/cloud-controllers",
	}
)
