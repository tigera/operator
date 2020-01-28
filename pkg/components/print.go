package components

import (
	"fmt"
)

func Print(digest bool) {
	for _, c := range []component{
		ComponentCalicoNode,
		ComponentAPIServer,
		ComponentCalicoCNI,
		ComponentCalicoKubeControllers,
		ComponentCalicoNode,
		ComponentCalicoTypha,
		ComponentComplianceBenchmarker,
		ComponentComplianceController,
		ComponentComplianceReporter,
		ComponentComplianceServer,
		ComponentComplianceSnapshotter,
		ComponentEckKibana,
		ComponentElasticTseeInstaller,
		ComponentElasticsearch,
		ComponentElasticsearchOperator,
		ComponentEsCurator,
		ComponentEsProxy,
		ComponentFlexVolume,
		ComponentFluentd,
		ComponentGuardian,
		ComponentIntrusionDetectionController,
		ComponentKibana,
		ComponentManager,
		ComponentManagerProxy,
		ComponentQueryServer,
		ComponentTigeraKubeControllers,
		ComponentTigeraNode,
		ComponentTigeraTypha,
	} {
		fmt.Println(GetReference(c, "", digest))
	}
}
