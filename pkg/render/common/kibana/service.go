package kibana

import (
	"fmt"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	httpsEndpoint     = "https://tigera-secure-kb-http.tigera-kibana.svc:5601"
	httpsFQDNEndpoint = "https://tigera-secure-kb-http.tigera-kibana.svc.%s:5601"
)

func HTTPSEndpoint(osType rmeta.OSType, clusterDomain string) string {
	// If this is for Windows, use the clusterDomain to get the FQDN version of
	// the Kibana https endpoint.
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(httpsFQDNEndpoint, clusterDomain)
	}
	return httpsEndpoint
}
