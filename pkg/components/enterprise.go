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
		Version: "v2.7.0-0.dev-32-gb094281f",
		Digest:  "sha256:86e5debfc69e370dc78f8e4024adc7ce94f8827f792716d3289e8d87fa8e98ce",
		Image:   "tigera/cnx-apiserver",
	}
	
	
	ComponentComplianceBenchmarker = component{
		Version: "v2.7.0-0.dev-38-g23b93c3",
		Digest:  "sha256:98048f1972e1b0caefc82892a12146e392f4302bf4a4e3768ed9cfbfd9e2799c",
		Image:   "tigera/compliance-benchmarker",
	}
	
	
	ComponentComplianceController = component{
		Version: "v2.7.0-0.dev-38-g23b93c3",
		Digest:  "sha256:97259c22599d350d92d80daffcfc44bad8eff7010d97f6dfd37eff7cf980a080",
		Image:   "tigera/compliance-controller",
	}
	
	
	ComponentComplianceReporter = component{
		Version: "v2.7.0-0.dev-38-g23b93c3",
		Digest:  "sha256:8f592854c9ff8032cb76d07b627dbc3c05bae4267c2f317bd827b8d7bcba7fcd",
		Image:   "tigera/compliance-reporter",
	}
	
	
	ComponentComplianceServer = component{
		Version: "v2.7.0-0.dev-38-g23b93c3",
		Digest:  "sha256:61a92fa99afdd5f534a4de2230dcc46c1a0203056062e18e3f9168af55d2ab99",
		Image:   "tigera/compliance-server",
	}
	
	
	ComponentComplianceSnapshotter = component{
		Version: "v2.7.0-0.dev-38-g23b93c3",
		Digest:  "sha256:7fb58645b8db247b44df7438ec0220fcf2c0b081df754aef0d0abfbfe7dbe776",
		Image:   "tigera/compliance-snapshotter",
	}
	
	
	ComponentEckKibana = component{
		Version: "7.3.2",
		Digest:  "sha256:fbd81abc89aab14b99b463b32310052e4ea563870cd0eadb1dd1153e54769ed3",
		Image:   "tigera/kibana",
	}
	
	
	ComponentElasticTseeInstaller = component{
		Version: "v2.7.0-0.dev-38-gbf021d6",
		Digest:  "sha256:3fded7f9999c7b4547044da41c857e30e061b0680942efdd007dbd5214ab574b",
		Image:   "tigera/intrusion-detection-job-installer",
	}
	
	
	ComponentElasticsearch = component{
		Version: "7.3.2",
		Digest:  "sha256:9dd701842833e902c0ba2b5682e0b7b3cd32f08e94a637d87ebdcb730e0a101a",
		Image:   "elasticsearch/elasticsearch",
	}
	
	
	ComponentElasticsearchOperator = component{
		Version: "0.9.0",
		Digest:  "sha256:9f134a7647371fc4e627c592496ff1ef1c3d50d6206fa6fb3571aacdb6ade574",
		Image:   "eck/eck-operator",
	}
	
	
	ComponentEsCurator = component{
		Version: "v2.6.0-0.dev-25-gb04da05",
		Digest:  "sha256:0106b8f8683a0bdf8d7dfc8a2210c2effc664ce2a7570e0f23508fc00b82657f",
		Image:   "tigera/es-curator",
	}
	
	
	ComponentEsProxy = component{
		Version: "v2.7.0-0.dev-43-g422fefb",
		Digest:  "sha256:561a30afb86d770437ba896c727ed6f6453967d8503bd086cf6e7b098f774f62",
		Image:   "tigera/es-proxy",
	}
	
	
	ComponentFluentd = component{
		Version: "v2.7.0-0.dev-4-gb1486b3",
		Digest:  "sha256:fced08b2ab80f967e69864299905bec19b482e2a55b3483f43f201f28f32553d",
		Image:   "tigera/fluentd",
	}
	
	
	ComponentGuardian = component{
		Version: "v2.7.0-0.dev-34-g4eac4a3",
		Digest:  "sha256:0d24ba5d2006b880575b5e8bcb58ab7c805c5b1c0497a70d4604eddf1c96b78b",
		Image:   "tigera/guardian",
	}
	
	
	ComponentIntrusionDetectionController = component{
		Version: "v2.7.0-0.dev-38-gbf021d6",
		Digest:  "sha256:d91bc2a82527c14306e50c4682cf3ff681914c067547df5c500cb5760f5413d6",
		Image:   "tigera/intrusion-detection-controller",
	}
	
	
	ComponentKibana = component{
		Version: "7.3",
		Digest:  "sha256:4c8e458fa0327c477c9aabd3672cc294e4497173faa61c475c76c47748677bf0",
		Image:   "tigera/kibana",
	}
	
	
	ComponentManager = component{
		Version: "v2.7.0-0.dev-234-g952d0a82",
		Digest:  "sha256:9ed1dcc9fd85a895c9d621fe7e9fb5bc90e7737f84a48afa88804278331b7f8f",
		Image:   "tigera/cnx-manager",
	}
	
	
	ComponentManagerProxy = component{
		Version: "v2.7.0-0.dev-34-g4eac4a3",
		Digest:  "sha256:d0af3c73e78b069f0035dc3c37b2059c0f282ec7a50514ab1aa089babcbde6ae",
		Image:   "tigera/voltron",
	}
	
	
	ComponentQueryServer = component{
		Version: "v2.7.0-0.dev-26-g232a725",
		Digest:  "sha256:40459e70f0417be61034de3917ab981f03ee270989e460c0e2dd87d56eb133f0",
		Image:   "tigera/cnx-queryserver",
	}
	
	
	ComponentTigeraKubeControllers = component{
		Version: "v2.7.0-0.dev-128-g3f4d4f5",
		Digest:  "sha256:6d52b51da6d48bf627aeeb865d0c18f6b0051c012ee9d168b8cb6446c28086dc",
		Image:   "tigera/kube-controllers",
	}
	
	
	ComponentTigeraNode = component{
		Version: "v2.7.0-0.dev-188-gc5255d3",
		Digest:  "sha256:324c51fbee91a3252556e2a90342a2a2e60121bd60679e94a722c2cd755a4b9a",
		Image:   "tigera/cnx-node",
	}
	
	
	ComponentTigeraTypha = component{
		Version: "v2.7.0-0.dev-74-g67bc0b1",
		Digest:  "sha256:a071de352b530363774297f1abb820ed01c6aaa84f5f92a6b3ab33670b65253d",
		Image:   "tigera/typha",
	}
	
)
