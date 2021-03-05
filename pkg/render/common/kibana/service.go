package kibana

import (
	"fmt"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	httpsEndpoint     = "https://tigera-secure-kb-http.tigera-kibana.svc:5601"
	httpsFQDNEndpoint = "https://tigera-secure-kb-http.tigera-kibana.svc.%s:5601"
)

// HTTPSEndpoint returns the full endpoint for the Kibana service. For
// Windows, the FQDN endpoint is returned.
func HTTPSEndpoint(osType rmeta.OSType, clusterDomain string) string {
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(httpsFQDNEndpoint, clusterDomain)
	}
	return httpsEndpoint
}
