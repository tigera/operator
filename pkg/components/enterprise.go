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
	EnterpriseRelease string = "v3.5.1"

	ComponentAPIServer = component{
		Version: "v3.5.1",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v3.5.1",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v3.5.1",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v3.5.1",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v3.5.1",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v3.5.1",
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
		Version: "v3.5.1",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "v3.5.1",
		Image:   "tigera/elasticsearch",
	}

	ComponentElasticsearchOperator = component{
		Version: "1.2.1",
		Image:   "eck/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "v3.5.1",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v3.5.1",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "v3.5.1",
		Image:   "tigera/fluentd",
	}

	ComponentFluentdWindows = component{
		Version: "v3.5.1",
		Image:   "tigera/fluentd-windows",
	}

	ComponentGuardian = component{
		Version: "v3.5.1",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v3.5.1",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "v3.5.1",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v3.5.1",
		Image:   "tigera/cnx-manager",
	}

	ComponentDex = component{
		Version: "v3.5.1",
		Image:   "tigera/dex",
	}

	ComponentManagerProxy = component{
		Version: "v3.5.1",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "v3.5.1",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "v3.5.1",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v3.5.1",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v3.5.1",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "v3.5.1",
		Image:   "tigera/cni",
	}

	ComponentCloudControllers = component{
		Version: "v3.5.1",
		Image:   "tigera/cloud-controllers",
	}

	ComponentCSRInitContainer = component{
		Version: "v3.5.1",
		Image:   "tigera/key-cert-provisioner",
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
		ComponentCSRInitContainer,
	}
)
