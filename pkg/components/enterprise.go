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
		Version: "v3.0.0",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v3.0.0",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v3.0.0",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v3.0.0",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v3.0.0",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v3.0.0",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentEckKibana = component{
		Version: "7.3.2",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "v3.0.0",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "7.3.2",
		Image:   "elasticsearch/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.0.1",
		Image:   "eck/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "v3.0.0",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v3.0.0",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "v3.0.0",
		Image:   "tigera/fluentd",
	}

	ComponentGuardian = component{
		Version: "v3.0.0",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v3.0.0",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "v3.0.0",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v3.0.0",
		Image:   "tigera/cnx-manager",
	}

	ComponentManagerProxy = component{
		Version: "v3.0.0",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "v3.0.0",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "v3.0.0",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v3.0.0",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v3.0.0",
		Image:   "tigera/typha",
	}

    ComponentTigeraCNI = component{
		Version: "v3.0.0",
		Image:   "tigera/cni",
    }

    ComponentCloudControllers = component{
		Version: "v3.1.0.calient-0.dev-14-gbd93096",
		Image:   "tigera/cloud-controllers",
    }
)
