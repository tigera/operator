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
		Version: "v2.8.0",
		Digest:  "sha256:eab0e7f6e6580026ffa60b661773f821d0990c2cd736c3bc61746b80713888d2",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v2.8.0",
		Digest:  "sha256:197621e7facdfcb648d973ea3436858c9b98a93f5032f7c1b004a8182aa4b3f2",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v2.8.0",
		Digest:  "sha256:6c47b63ee518ae88cadc44ae1ecc2b4405c2a3307d9e833d15f4317faa890282",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v2.8.0",
		Digest:  "sha256:328d0023e902308a0c7df9111067121ab105090e639e8931214506e8437f7f6e",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v2.8.0",
		Digest:  "sha256:5973accd459a083cfabc09d6b857378f9b47c07b17b7619341b2724bc2833804",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v2.8.0",
		Digest:  "sha256:316f78256732061d8cf7d389f32e25ac190c3def19ed714d7b6d20c742bf6318",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentEckKibana = component{
		Version: "7.3.2",
		Digest:  "sha256:fbd81abc89aab14b99b463b32310052e4ea563870cd0eadb1dd1153e54769ed3",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "v2.8.0",
		Digest:  "sha256:2509c3a597fba10aea2f847c5e48d224f1a66413c897f07208bef99968f0541d",
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
		Version: "v2.8.0",
		Digest:  "sha256:620672d054a15e3195bf6b8caf2a2811aaabf2f1c485648f2ecc1f752c533974",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v2.8.0",
		Digest:  "sha256:1c2838ddbca6290bce9631f489a3dfa98ea6321333fe745af2623512777c2edc",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "v2.8.0",
		Digest:  "sha256:18bc903059709436bfc00ae9977dcfcf00aa74e2f319f0dfe565dd2e5ebaa1c8",
		Image:   "tigera/fluentd",
	}

	ComponentGuardian = component{
		Version: "v2.8.0",
		Digest:  "sha256:7bb05ffce01fad8dc9078125ece06dc3180df732a853c775b3ac3602bcfe7a42",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v2.8.0",
		Digest:  "sha256:87289932cfc98a08776d98723225ca53fe244be86bd7d41c92c8fb756d9c5106",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "v2.8.0",
		Digest:  "sha256:73962523ddfc55dfd3f4a2b2d87183e96e13d890a74883cd05a1242ac53b627f",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v2.8.0",
		Digest:  "sha256:5fd4510f1889ff3a352973315203404d1630c41a3a48ab11c085599d0cde8edf",
		Image:   "tigera/cnx-manager",
	}

	ComponentManagerProxy = component{
		Version: "v2.8.0",
		Digest:  "sha256:1978746fcf77d0f682d4c78f309d5a81b58fe8dc6376d4df6d1dd7c0fb06d2f7",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "v2.8.0",
		Digest:  "sha256:6041c7c991330701fd236a4198c5f0dc75b16092b5e2c087bff6874da273fb22",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "v2.8.0",
		Digest:  "sha256:3594da436ea2ac34397756d259fb52707dafab36180d7c060015b72e3304ba0c",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v2.8.0",
		Digest:  "sha256:1482a15e15dacbaefc241a2bd3dbde1a5b7adebc23397599955f3725bb735f17",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v2.8.0",
		Digest:  "sha256:8b07fe09db3a33ba85ca7473cccf838da2ce20832647fb04021baa2293f58fa8",
		Image:   "tigera/typha",
	}
)
