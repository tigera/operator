package render

import (
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/k8sapi"
)

func PrometheusService(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operator.InstallationSpec,
	bt map[string]string,
	tnTLS *TyphaNodeTLS,
	aci *operator.AmazonCloudIntegration,
	migrate bool,
	nodeAppArmorProfile string,
	clusterDomain string,
	nodeReporterMetricsPort int,
	bgpLayoutHash string,
) Component {
	return &nodeComponent{
		k8sServiceEp:            k8sServiceEp,
		cr:                      cr,
		birdTemplates:           bt,
		typhaNodeTLS:            tnTLS,
		amazonCloudInt:          aci,
		migrationNeeded:         migrate,
		nodeAppArmorProfile:     nodeAppArmorProfile,
		clusterDomain:           clusterDomain,
		nodeReporterMetricsPort: nodeReporterMetricsPort,
		bgpLayoutHash:           bgpLayoutHash,
	}
}
