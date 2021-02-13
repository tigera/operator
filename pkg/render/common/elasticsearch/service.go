package elasticsearch

import (
	"fmt"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	httpsFQDNEndpoint = "https://tigera-secure-es-http.tigera-elasticsearch.svc.%s:9200"
	httpsEndpoint     = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
)

func HTTPSEndpoint(osType rmeta.OSType, clusterDomain string) string {
	// If this is for Windows, use the clusterDomain to get the FQDN version of
	// the ES https endpoint.
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(httpsFQDNEndpoint, clusterDomain)
	}
	return httpsEndpoint
}
