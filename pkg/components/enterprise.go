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
		Digest:  "sha256:0d5493e9051367637ee19fa269a7d38a7f632386ecc747daf4c51d54c5d9e69b",
		Image:   "tigera/cnx-apiserver",
	}
	
	ComponentComplianceBenchmarker = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:2f5baffd22321094faeb27e1390009efc693075b0e3964301deaad45ea7f1729",
		Image:   "tigera/compliance-benchmarker",
	}
	
	ComponentComplianceController = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:6837d7c525ba0c8d7c14ff1f143160b683489536e3265f9a490071ec2ddec268",
		Image:   "tigera/compliance-controller",
	}
	
	ComponentComplianceReporter = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:375b697376dfaaa835600adaa0ad858a83aeaa88d2270a5e1acdb1988c4c4bda",
		Image:   "tigera/compliance-reporter",
	}
	
	ComponentComplianceServer = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:c9719426d9b191ceb18f256f9b54e1310d099b1144f53d1d679861b23c0e9f6a",
		Image:   "tigera/compliance-server",
	}
	
	ComponentComplianceSnapshotter = component{
		Version: "v3.0.0-0.dev-23-gd7abd7d",
		Digest:  "sha256:15df2aa0adb2b2987dca8abd0af685fd3f5af78e60a9d269c139e819c5990288",
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
		Digest:  "sha256:1bc33476d2befbd1ab1ca8af21f01d951d7afd33c800ab2f9a4d165a47e53163",
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
		Version: "v3.0.0-0.dev-69-gb7d1f80",
		Digest:  "sha256:70c05c587815a2982fa290abad6d279b845db81cb88a1bf8e1a947bf5e5bb916",
		Image:   "tigera/kube-controllers",
	}
	
	ComponentTigeraNode = component{
		Version: "v3.0.0-0.dev-80-g032b7f3",
		Digest:  "sha256:6272729e8e1c4b625eca37e58bb8e1eb2a715388e133b38142553160bc357257",
		Image:   "tigera/cnx-node",
	}
	
	ComponentTigeraTypha = component{
		Version: "v3.0.0-0.dev-52-g8aa41da",
		Digest:  "sha256:81fe44b7253f50dc7ede0475802898d0f953bf4a64619fd933b9dc10edab1d31",
		Image:   "tigera/typha",
	}
	
    ComponentTigeraCNI = component{
        Version: "v3.0.0-0.dev-53-gb3668d9",
        Digest:  "sha256:90790ac19b1848438cae12ae116a5138f7e7cc1c15766ab41cfd62e515e03854",
        Image:   "tigera/cni",
    }
)
