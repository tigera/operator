// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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

package elasticsearch

import (
	"fmt"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	httpsEndpoint       = "https://tigera-secure-es-gateway-http.tigera-elasticsearch.svc:9200"
	linseedEndpoint     = "https://tigera-linseed.tigera-elasticsearch.svc"
	httpsFQDNEndpoint   = "https://tigera-secure-es-gateway-http.tigera-elasticsearch.svc.%s:9200"
	linseedFQDNEndpoint = "https://tigera-linseed.tigera-elasticsearch.svc.%s"
)

// HTTPSEndpoint returns the endpoint for the Elasticsearch service. For
// Windows, the FQDN endpoint is returned.
func HTTPSEndpoint(osType rmeta.OSType, clusterDomain string) string {
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(httpsFQDNEndpoint, clusterDomain)
	}
	return httpsEndpoint
}

func LinseedEndpoint(osType rmeta.OSType, clusterDomain string) string {
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(linseedFQDNEndpoint, clusterDomain)
	}
	return linseedEndpoint
}
