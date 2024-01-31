// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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
	httpsEndpoint       = "https://tigera-secure-es-gateway-http.%s.svc:9200"
	linseedEndpoint     = "https://tigera-linseed.%s.svc"
	httpsFQDNEndpoint   = "https://tigera-secure-es-gateway-http.%s.svc.%s:9200"
	linseedFQDNEndpoint = "https://tigera-linseed.%s.svc.%s"
)

func LinseedEndpoint(osType rmeta.OSType, clusterDomain, namespace string) string {
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(linseedFQDNEndpoint, namespace, clusterDomain)
	}
	return fmt.Sprintf(linseedEndpoint, namespace)
}

// GatewayEndpoint returns the endpoint for the Elasticsearch service. For
// Windows, the FQDN endpoint is returned.
func GatewayEndpoint(osType rmeta.OSType, clusterDomain, namespace string) string {
	if osType == rmeta.OSTypeWindows {
		return fmt.Sprintf(httpsFQDNEndpoint, namespace, clusterDomain)
	}
	return fmt.Sprintf(httpsEndpoint, namespace)
}

// Deprecated - does not support multi-tenancy. Use GatewayEndpoint instead.
func HTTPSEndpoint(osType rmeta.OSType, clusterDomain string) string {
	return GatewayEndpoint(osType, clusterDomain, "tigera-elasticsearch")
}

// ECKElasticEndpoint returns the URL of the Elasticsearch provisioned by the ECK operator. This
// endpoint is only valid when using internal elasticsearch.
func ECKElasticEndpoint() string {
	return "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
}
