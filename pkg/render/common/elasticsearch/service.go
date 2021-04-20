package elasticsearch

import (
	"fmt"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	httpsEndpoint     = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
	httpsFQDNEndpoint = "https://tigera-secure-es-http.tigera-elasticsearch.svc.%s:9200"
)

// HTTPSEndpoint returns the endpoint for the Elasticsearch service. For
// Windows, the FQDN endpoint is returned.
func HTTPSEndpoint(osType rmeta.OSType, clusterDomain string) string {
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(httpsFQDNEndpoint, clusterDomain)
	}
	return httpsEndpoint
}
