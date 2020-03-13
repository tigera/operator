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
		Version: "v2.7.0",
		Digest:  "sha256:33755103ca321c07e07e1b1302428c3a6d29bc40f0b71519be879a0a689868fd",
		Image:   "tigera/cnx-apiserver",
	}

	ComponentComplianceBenchmarker = component{
		Version: "v2.7.0",
		Digest:  "sha256:59886e14f8af2a9335df1666e65f6801a4b30f076872f3dad6cef14dd35e1838",
		Image:   "tigera/compliance-benchmarker",
	}

	ComponentComplianceController = component{
		Version: "v2.7.0",
		Digest:  "sha256:a18b73d69c6edef6c0c87e0b85dfd4f8977293f24d899c6c369be914106b1b93",
		Image:   "tigera/compliance-controller",
	}

	ComponentComplianceReporter = component{
		Version: "v2.7.0",
		Digest:  "sha256:030112b0dbd9d66fd557f6c118e8001ff8569661bcc6503ed29891281e0e0695",
		Image:   "tigera/compliance-reporter",
	}

	ComponentComplianceServer = component{
		Version: "v2.7.0",
		Digest:  "sha256:421c4ffe4b04bf91d4ae4840d65c3d42aa7edfa3e0fa6a222a7cb8297cc05465",
		Image:   "tigera/compliance-server",
	}

	ComponentComplianceSnapshotter = component{
		Version: "v2.7.0",
		Digest:  "sha256:b2a7ad0c8df9a7f51a9bf8865bdc357682309fa3ab0247092915304115c5be86",
		Image:   "tigera/compliance-snapshotter",
	}

	ComponentEckKibana = component{
		Version: "7.3.2",
		Digest:  "sha256:fbd81abc89aab14b99b463b32310052e4ea563870cd0eadb1dd1153e54769ed3",
		Image:   "tigera/kibana",
	}

	ComponentElasticTseeInstaller = component{
		Version: "v2.7.0-0.dev-38-gbf021d6",
		Digest:  "sha256:db5d3ee0a5c659337efaa1e48bd8716b913ace1e745a73de59cfad5d79cfaba3",
		Image:   "tigera/intrusion-detection-job-installer",
	}

	ComponentElasticsearch = component{
		Version: "7.3.2",
		Digest:  "sha256:9dd701842833e902c0ba2b5682e0b7b3cd32f08e94a637d87ebdcb730e0a101a",
		Image:   "elasticsearch/elasticsearch",
	}
	//	Version: "7.6.0",
	//	Digest:  "sha256:fb37d2e15d897b32bef18fed6050279f68a76d8c4ea54c75e37ecdbe7ca10b4b",
	//	Image:   "elasticsearch/elasticsearch",

	ComponentElasticsearchOperator = component{
		Version: "1.0.1",
		Digest:  "sha256:fa4fbf738f8f81c39d1a4a0172209f1641ed0115488f16c91dcc4a9a16f42531",
		Image:   "eck/eck-operator",
	}

	ComponentEsCurator = component{
		Version: "v2.7.0",
		Digest:  "sha256:34a8486c7e0d646b17c788adb4bafd41d567a85be5c75f4bfe1d650ebc85d475",
		Image:   "tigera/es-curator",
	}

	ComponentEsProxy = component{
		Version: "v2.7.0",
		Digest:  "sha256:9da0f6f55431b9d6737bd915083cf51e09fe537b2072681e8b88a0cee5695259",
		Image:   "tigera/es-proxy",
	}

	ComponentFluentd = component{
		Version: "v2.7.0",
		Digest:  "sha256:b3921b735d220e10808362925e04500a19b1edc15a2c0108e5104a8317f51c52",
		Image:   "tigera/fluentd",
	}

	ComponentGuardian = component{
		Version: "v2.7.0-0.dev-50-g2b3fa78",
		Digest:  "sha256:22928d9b9711004c65699eb6daff547ce92cd6bd31feb680faff58d0a2a06d24",
		Image:   "tigera/guardian",
	}

	ComponentIntrusionDetectionController = component{
		Version: "v2.7.0-0.dev-38-gbf021d6",
		Digest:  "sha256:11047f506a1db4d5295c1bd94afbdd2682c81cda9b9fccaafca4730f813bd4ee",
		Image:   "tigera/intrusion-detection-controller",
	}

	ComponentKibana = component{
		Version: "7.3",
		Digest:  "sha256:4c8e458fa0327c477c9aabd3672cc294e4497173faa61c475c76c47748677bf0",
		Image:   "tigera/kibana",
	}

	ComponentManager = component{
		Version: "v2.7.0",
		Digest:  "sha256:439666b2f313341330ccece00cceff97b0c9cd77b4d834470060c519e51fccfc",
		Image:   "tigera/cnx-manager",
	}

	ComponentManagerProxy = component{
		Version: "v2.7.0-0.dev-50-g2b3fa78",
		Digest:  "sha256:6ba6db0df465c06f64d1b241ed3b6e9bfa7a108a37851d45d13943d0bdbb6cff",
		Image:   "tigera/voltron",
	}

	ComponentQueryServer = component{
		Version: "v2.7.0",
		Digest:  "sha256:3603e45257693d8112fee4244ed5ceeb09c6dd34df07eb5ddb1b2e882eb209ae",
		Image:   "tigera/cnx-queryserver",
	}

	ComponentTigeraKubeControllers = component{
		Version: "eck101",
		Digest:  "sha256:61a632958236520f6640be83c69f1f7b1d0f38dd282b1ea0171d9530cf6847a9",
		Image:   "tigera/kube-controllers",
	}

	ComponentTigeraNode = component{
		Version: "v2.7.0",
		Digest:  "sha256:205c5e15543ef4c0f166a77326a061f5d99a1e20f6c9e4a0a8227b620333d280",
		Image:   "tigera/cnx-node",
	}

	ComponentTigeraTypha = component{
		Version: "v2.7.0",
		Digest:  "sha256:262d9e73ac8842eeaa6219a1c1453295cd55124b5ded5ade2cc765b03a1006e7",
		Image:   "tigera/typha",
	}
)
