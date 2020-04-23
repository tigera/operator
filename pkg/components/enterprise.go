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
		Version: "v2.8.1",
		Digest:  "sha256:eca762f19d62e7f6838bc8435315de78806b2bdeaa71c99b6854909309818eb6",
		Image:   "tigera/cnx-apiserver",
	}
	
	
	ComponentComplianceBenchmarker = component{
		Version: "v2.8.1",
		Digest:  "sha256:de9511268472ff0320c83535585a8a37d9dbc0ad4cb0ef01de1c991fb4bcbda6",
		Image:   "tigera/compliance-benchmarker",
	}
	
	
	ComponentComplianceController = component{
		Version: "v2.8.1",
		Digest:  "sha256:72c0ea595003760a3bece0bad41447f255e8dc7edde33a53b06f65f20e5cec5f",
		Image:   "tigera/compliance-controller",
	}
	
	
	ComponentComplianceReporter = component{
		Version: "v2.8.1",
		Digest:  "sha256:3fd160aa33ec01fceff71df17e592a1d5c53ee933b8acd58dc8a343375788984",
		Image:   "tigera/compliance-reporter",
	}
	
	
	ComponentComplianceServer = component{
		Version: "v2.8.1",
		Digest:  "sha256:a9fbd49fe61f9cc29d99c15dbc6ccc982aabd490d787099d715023f156e6a539",
		Image:   "tigera/compliance-server",
	}
	
	
	ComponentComplianceSnapshotter = component{
		Version: "v2.8.1",
		Digest:  "sha256:3f4e97eed6dcca935fee8b0c82f9a62023c64339a5be98f71a89796fd1c141ae",
		Image:   "tigera/compliance-snapshotter",
	}
	
	
	ComponentEckKibana = component{
		Version: "7.3.2",
		Digest:  "sha256:fbd81abc89aab14b99b463b32310052e4ea563870cd0eadb1dd1153e54769ed3",
		Image:   "tigera/kibana",
	}
	
	
	ComponentElasticTseeInstaller = component{
		Version: "v2.8.1",
		Digest:  "sha256:9f1fcb38df9acae1e3abdd03fe3135e51233797f26949c45e173679e898aa197",
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
		Version: "v2.8.1",
		Digest:  "sha256:67dc2844395b1cc00083a09a9cfd80650394bc249b4c396fabc63aeb86f7d0b8",
		Image:   "tigera/es-curator",
	}
	
	
	ComponentEsProxy = component{
		Version: "v2.8.1",
		Digest:  "sha256:5346e397642daae2f70713c460e4c903708a10ee1089645896cd9f987c026416",
		Image:   "tigera/es-proxy",
	}
	
	
	ComponentFluentd = component{
		Version: "v2.8.1",
		Digest:  "sha256:dc8072c92157a0e18d0ee2b3b593006e53d6e476e9e8312cd06d360e7b80331e",
		Image:   "tigera/fluentd",
	}
	
	
	ComponentGuardian = component{
		Version: "v2.8.1",
		Digest:  "sha256:2d6e2885d5852ca0647c5a28e51b70642618510362de6e73fe3cce689c1bd69e",
		Image:   "tigera/guardian",
	}
	
	
	ComponentIntrusionDetectionController = component{
		Version: "v2.8.1",
		Digest:  "sha256:da382087e030ea7edcb2949dad0b5c0a4a7ba049382d144b78c2f100521f667b",
		Image:   "tigera/intrusion-detection-controller",
	}
	
	
	ComponentKibana = component{
		Version: "v2.8.1",
		Digest:  "sha256:f2b8750e296009b5eecabec13d04b8aff7050e902a1837bc7eefada869015db2",
		Image:   "tigera/kibana",
	}
	
	
	ComponentManager = component{
		Version: "v2.8.1",
		Digest:  "sha256:a137be96fff82d443fc06ae241841140ba58d2a00cf00c3f64dbbedd15548492",
		Image:   "tigera/cnx-manager",
	}
	
	
	ComponentManagerProxy = component{
		Version: "v2.8.1",
		Digest:  "sha256:99b52056d00e25ed0261a6c2aa0dac4fcbc38d2c51cec657c73519c8a050fdfb",
		Image:   "tigera/voltron",
	}
	
	
	ComponentQueryServer = component{
		Version: "v2.8.1",
		Digest:  "sha256:0edcd65947bf94963d8e224dbe0377db0eeb0f7e231b61fade9e13a61b7fc6ad",
		Image:   "tigera/cnx-queryserver",
	}
	
	
	ComponentTigeraKubeControllers = component{
		Version: "v2.8.1",
		Digest:  "sha256:0c71e9bb9676e295d1340623294547526a7ec426f1ba4fd4ef596ff4e7d4d97c",
		Image:   "tigera/kube-controllers",
	}
	
	
	ComponentTigeraNode = component{
		Version: "v2.8.1",
		Digest:  "sha256:dc86bb1af6d7f0fd24d8dfcd9a5eead125917adb1ac66bf15fc7cb4765881b46",
		Image:   "tigera/cnx-node",
	}
	
	
	ComponentTigeraTypha = component{
		Version: "v2.8.1",
		Digest:  "sha256:81a3a11f84cc71113835e16a2db688a6fab9e8e04d64e784bc36e3064c404bdf",
		Image:   "tigera/typha",
	}
	
)
