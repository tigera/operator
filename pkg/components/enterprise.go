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
		Version: "v3.0.0-0.dev-29-g11260416",
		Digest:  "sha256:b8a1e376eb52e8add42d93fc975ff3550136afa436c3a414f89f588b1393ecea",
		Image:   "tigera/cnx-apiserver",
	}
	
	
	ComponentComplianceBenchmarker = component{
		Version: "v2.7.0-0.dev-81-g41d5d65",
		Digest:  "sha256:f1c984f73cc7ae56e243257ee8214bfcbe4a8cafe214c2887e97e5a7bf869b08",
		Image:   "tigera/compliance-benchmarker",
	}
	
	
	ComponentComplianceController = component{
		Version: "v2.7.0-0.dev-81-g41d5d65",
		Digest:  "sha256:b461196a24c6a3ea4528886c1ff39a91441aa0a04238b2e86ec9e0f2b4407b0f",
		Image:   "tigera/compliance-controller",
	}
	
	
	ComponentComplianceReporter = component{
		Version: "v2.7.0-0.dev-81-g41d5d65",
		Digest:  "sha256:26edc7485345a894cb72f16692515bb857b7ea0c32eb890a2a016c245c195a85",
		Image:   "tigera/compliance-reporter",
	}
	
	
	ComponentComplianceServer = component{
		Version: "v2.7.0-0.dev-81-g41d5d65",
		Digest:  "sha256:30b82e739fc2e392a814c07827a58f9cd7f8807b3b334ce1aeda575a13ce1036",
		Image:   "tigera/compliance-server",
	}
	
	
	ComponentComplianceSnapshotter = component{
		Version: "v2.7.0-0.dev-81-g41d5d65",
		Digest:  "sha256:b5750d37bb454ea6cbeb90843b136d3f880060534fea36314fc748e3e4deb9cd",
		Image:   "tigera/compliance-snapshotter",
	}
	
	
	ComponentEckKibana = component{
		Version: "7.3.2",
		Digest:  "sha256:fbd81abc89aab14b99b463b32310052e4ea563870cd0eadb1dd1153e54769ed3",
		Image:   "tigera/kibana",
	}
	
	
	ComponentElasticTseeInstaller = component{
		Version: "v2.7.0-0.dev-63-g8591567",
		Digest:  "sha256:4aa2ba8382ba7a87a2a8a8ef88ca82e175f7aa4df2d047471c7fbb26e7710ac0",
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
		Version: "v2.8.0-0.dev-0-gd026b79",
		Digest:  "sha256:f11b66e91b82d0ec2c6191d59738644e4cceea122c682956ff93445cf5344c5c",
		Image:   "tigera/es-curator",
	}
	
	
	ComponentEsProxy = component{
		Version: "v2.7.0-0.dev-111-g3d1305c",
		Digest:  "sha256:aa5b425a27de2d1ee97c210b62ddb6f6397e5001dd5ad26ce88144fa15adc1bd",
		Image:   "tigera/es-proxy",
	}
	
	
	ComponentFluentd = component{
		Version: "v3.0.0-0.dev-1-ge3d709f",
		Digest:  "sha256:84208c8d0946b23d28148f61a70f924b1a13738c9f0949656937acdd0b5d3cf6",
		Image:   "tigera/fluentd",
	}
	
	
	ComponentGuardian = component{
		Version: "v2.7.0-0.dev-61-g73e2b02",
		Digest:  "sha256:707e77225e8b92a040c03a730cbcaa39c3109bf9387d30e253c4dbb10de7c42f",
		Image:   "tigera/guardian",
	}
	
	
	ComponentIntrusionDetectionController = component{
		Version: "v2.7.0-0.dev-63-g8591567",
		Digest:  "sha256:774a77e54ae42ed96aad05d910acaa7ee6872001ceca0eef3bb3e5305bf89b34",
		Image:   "tigera/intrusion-detection-controller",
	}
	
	
	ComponentKibana = component{
		Version: "v2.7.3-0-g99fc114",
		Digest:  "sha256:ffc7704120c22f3d48d1495d205901795f16a51219fc79a01068dcbcde8cf33f",
		Image:   "tigera/kibana",
	}
	
	
	ComponentManager = component{
		Version: "v2.7.0-0.dev-598-g5f43270b",
		Digest:  "sha256:24fbd97411f81cd530ee749c42916d15698744b7664f3e9f7e12768c995a9008",
		Image:   "tigera/cnx-manager",
	}
	
	
	ComponentManagerProxy = component{
		Version: "v2.7.0-0.dev-61-g73e2b02",
		Digest:  "sha256:723b584f03e8b81e98bcd6002a9c599b3d31342edffe07a4c28bb01fae9a0ffb",
		Image:   "tigera/voltron",
	}
	
	
	ComponentQueryServer = component{
		Version: "v2.7.0-0.dev-74-g6ce4ce4",
		Digest:  "sha256:06faecae3036ac48ec7e049ff596acea413f3da8523ad319d564e318cf04d1ca",
		Image:   "tigera/cnx-queryserver",
	}
	
	
	ComponentTigeraKubeControllers = component{
		Version: "v2.7.0-0.dev-176-g68be5b8",
		Digest:  "sha256:8f7400037804f3ae80168df50e6479ffba4998662f089984f3a5a92fe8b775a8",
		Image:   "tigera/kube-controllers",
	}
	
	
	ComponentTigeraNode = component{
		Version: "v3.0.0-0.dev-79-gccc948e",
		Digest:  "sha256:00901a322278c0a7abdd07bf3665e4779e9327d1103e0cdd9fe1066d104254ca",
		Image:   "tigera/cnx-node",
	}
	
	
	ComponentTigeraTypha = component{
		Version: "v3.0.0-0.dev-23-g664fa65",
		Digest:  "sha256:596fa5fe7f80d1af871f705ff586e71761bbc0b12ae7522169a179ce24543271",
		Image:   "tigera/typha",
	}
	
	
    ComponentTigeraCNI = component{
        Version: "v3.0.0-0.dev-39-g3f96541",
        Digest:  "sha256:b3cc46ace05218b55a07b9351fe206e1a4398ab227c36bdde6ca84a076100cb9",
        Image:   "tigera/cni",
    }
    
)
