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
		Version: "v2.8.2",
		Digest:  "sha256:d163a2e95668fed7cc2f5fcecc7e0be72f0c3e269bed38f9f0848f2be56da34b",
		Image:   "tigera/cnx-apiserver",
	}
	
	
	ComponentComplianceBenchmarker = component{
		Version: "v2.8.2",
		Digest:  "sha256:e860832d9b864613a66ab84076a9a78ff4a3dc7c1456d0b04314b8eb7c04998f",
		Image:   "tigera/compliance-benchmarker",
	}
	
	
	ComponentComplianceController = component{
		Version: "v2.8.2",
		Digest:  "sha256:f848b457e19972fccf33d2574239c04995c8df49c60c6eea3c6105f1878a7cd2",
		Image:   "tigera/compliance-controller",
	}
	
	
	ComponentComplianceReporter = component{
		Version: "v2.8.2",
		Digest:  "sha256:261dd8891f08d249f2a1c44a51a881eb689806092ce96c3ff6393281dc447056",
		Image:   "tigera/compliance-reporter",
	}
	
	
	ComponentComplianceServer = component{
		Version: "v2.8.2",
		Digest:  "sha256:9d00968c30d14d91e234d9a7ee142b748ce8e5cd23e17879e58fac97f6318300",
		Image:   "tigera/compliance-server",
	}
	
	
	ComponentComplianceSnapshotter = component{
		Version: "v2.8.2",
		Digest:  "sha256:c26e7c343ae582cf8cc809453ecdabc3d1093e2dd500d815b39e5cf6b804c050",
		Image:   "tigera/compliance-snapshotter",
	}
	
	
	ComponentEckKibana = component{
		Version: "7.3.2",
		Digest:  "sha256:fbd81abc89aab14b99b463b32310052e4ea563870cd0eadb1dd1153e54769ed3",
		Image:   "tigera/kibana",
	}
	
	
	ComponentElasticTseeInstaller = component{
		Version: "v2.8.2",
		Digest:  "sha256:02903cd625b2582b47ee0c44a53d574ec47acd8a82de570fec33e754a2c031ab",
		Image:   "tigera/intrusion-detection-job-installer",
	}
	
	
	ComponentElasticsearch = component{
		Version: "7.3.2",
		Digest:  "sha256:9dd701842833e902c0ba2b5682e0b7b3cd32f08e94a637d87ebdcb730e0a101a",
		Image:   "elasticsearch/elasticsearch",
	}
	
	
	ComponentElasticsearchOperator = component{
		Version: "1.0.1",
		Digest:  "sha256:fa4fbf738f8f81c39d1a4a0172209f1641ed0115488f16c91dcc4a9a16f42531",
		Image:   "eck/eck-operator",
	}
	
	
	ComponentEsCurator = component{
		Version: "v2.8.2",
		Digest:  "sha256:315eccdde5ffefb8debc546693a1dfc8fbf2388c52d38457866065a12ba442fd",
		Image:   "tigera/es-curator",
	}
	
	
	ComponentEsProxy = component{
		Version: "v2.8.2",
		Digest:  "sha256:97dbeb3ede1f6d92cd9b6ad6de9d2470601704ebe15ca822463f7ae35cf3b9aa",
		Image:   "tigera/es-proxy",
	}
	
	
	ComponentFluentd = component{
		Version: "v2.8.2",
		Digest:  "sha256:01bcbebe345aa02185d372a8d7cb5c1eb7ac901fcb4e78714f3f6e4741add174",
		Image:   "tigera/fluentd",
	}
	
	
	ComponentGuardian = component{
		Version: "v2.8.2",
		Digest:  "sha256:7218db91a23d30a44680926376055dd66ce900669ec2cabb94d49f777b3b6733",
		Image:   "tigera/guardian",
	}
	
	
	ComponentIntrusionDetectionController = component{
		Version: "v2.8.2",
		Digest:  "sha256:81dd214aa72481091fa49cf76aff988324fdce6586a07bced58cd04644f523dc",
		Image:   "tigera/intrusion-detection-controller",
	}
	
	
	ComponentKibana = component{
		Version: "v2.8.2",
		Digest:  "sha256:dd12a78e986cbee001e04e81f05af101cdfd2aa0c1ebd69375cbc368ea011c7a",
		Image:   "tigera/kibana",
	}
	
	
	ComponentManager = component{
		Version: "v2.8.2",
		Digest:  "sha256:8532e25ed52304e289d4c211bd706a60014bfd160d1cb473520e83055c00aaf7",
		Image:   "tigera/cnx-manager",
	}
	
	
	ComponentManagerProxy = component{
		Version: "v2.8.2",
		Digest:  "sha256:1e807476253b62d5efb0c0787fc388c5dc64c98f5f0213f3e857ff9fede4ef73",
		Image:   "tigera/voltron",
	}
	
	
	ComponentQueryServer = component{
		Version: "v2.8.2",
		Digest:  "sha256:11a8b42c0493c216d22a578dabfb1af6cfb8af1ada5d8941c03e18681739720e",
		Image:   "tigera/cnx-queryserver",
	}
	
	
	ComponentTigeraKubeControllers = component{
		Version: "v2.8.2",
		Digest:  "sha256:182083654aaca5f8a9ba8d9069b97b16c175d53966f2d0054455f34e8539006f",
		Image:   "tigera/kube-controllers",
	}
	
	
	ComponentTigeraNode = component{
		Version: "v2.8.2",
		Digest:  "sha256:a24868e127ca9e5709da2ef1c421584304ce2a11ec72f88d002bd2159761a6ae",
		Image:   "tigera/cnx-node",
	}
	
	
	ComponentTigeraTypha = component{
		Version: "v2.8.2",
		Digest:  "sha256:e84229b83c23ea6b88326c02503d9cbe432262cbf96591067fda30d6a15345e9",
		Image:   "tigera/typha",
	}
	
)
