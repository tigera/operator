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
		Digest:  "sha256:ef64f6b93c55f7034abf9d8b72065f9af75f65551ea3d67f0180516c3e2a4c53",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:fbfea99cecc2e30640e5a426a9d3247d8a1427e76de02d7cf351f4ce0e027cb5",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:1c79338d8c8091fb700755b7865b3dd0c5563146a571918ee7e208f6064d4173",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:2d021540ba3ceeff9dac2dc058002647b6dd1990eb3c291bb48dc3679b01e7ba",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:ccefdd535b389d99a290adca0f052ebcc8d022caefe80dde24e0a1640738b65b",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:fca37f49d00ae0bdef3f916aa7a5b74eea031e2adc73b23506f23ccddca5664d",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentEckKibana = component{
		Version: "7.3.2",
		Digest:  "sha256:fbd81abc89aab14b99b463b32310052e4ea563870cd0eadb1dd1153e54769ed3",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "v3.0.0-0.dev-15-g466c351",
		Digest:  "sha256:2d8902ef6f201d974204b98f83e48d999e1315075e70bbd46b1ccf117d96de37",
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
		Version: "v3.0.0-0.dev-10-gf2e83fb",
		Digest:  "sha256:3ccc22571348038bf35489e8f146ba609e731f0119f53845c169d9517e5141df",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v3.0.0-0.dev-29-gfe7b046",
		Digest:  "sha256:a23cec3dfbbcbcc28ec8f2352cd9383d91b8d4222ef5b066b24fb4d6172365f0",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "v3.0.0-0.dev-12-g63e0f79",
		Digest:  "sha256:895b97a80bd2ee0e445b4acc3aa8a988ed801e0cb8c0f036c81f8e4e7b063e3a",
		Image:   "tigera/fluentd",
	}

	ComponentGuardian = component{
		Version: "v3.0.0-0.dev-8-g4197ee4",
		Digest:  "sha256:25ded97128058945d334cd26fbd1126f846d8f7702eb7118be365f6fc28dcadb",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v3.0.0-0.dev-15-g466c351",
		Digest:  "sha256:56282d9a1de02ae5443d35439010694283503b9f1eacd4ba676abb6640a1d241",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "v3.0.0-0.dev-0-gddc3967",
		Digest:  "sha256:68a568f58b2ee83e054971fc8121bf83001678a039ff9d27a3dd31266d5f9c94",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v3.0.0-0.dev-138-g711599c3",
		Digest:  "sha256:b44284d80be95e38954e5143d44e1d58c73e892ba1495d5472e396160ada4f8d",
		Image:   "tigera/cnx-manager",
	}

	ComponentManagerProxy = component{
		Version: "v3.0.0-0.dev-8-g4197ee4",
		Digest:  "sha256:67161a27da6da8238651fb735d4bbb1b27250fb1274c994b646df7bfc723b86b",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "v3.0.0-0.dev-27-gd8468ea",
		Digest:  "sha256:a6cb00b54268b021654ff4d1b216991a184881025ae5f06b09583dcd0d7751b2",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "v3.0.0-0.dev-70-gae8763c",
		Digest:  "sha256:56be38018ed124fd459a2f537ee0e921e87efcfcb140c0d1083591140d30a851",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v3.0.0-0.dev-82-gd804d79",
		Digest:  "sha256:7a758c4c0323b57d34b0d7c1388ebc3dff87f870eff3facc6da8f0b60c74b2ef",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v3.0.0-0.dev-52-g8aa41da",
		Digest:  "sha256:685c544ae9fc607a2d1706493a46ae06669a9d207e480d492def270305f37a1c",
		Image:   "tigera/typha",
	}

	ComponentTigeraCNI = component{
		Version: "v3.0.0-0.dev-53-gb3668d9",
		Digest:  "sha256:717d24e4111ed42dd158ca9d622b43f4e80de3385b336cd254507166a9681694",
		Image:   "tigera/cni",
	}
)
