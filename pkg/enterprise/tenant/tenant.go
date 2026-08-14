// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package tenant

import (
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
)

// These are re-exported by pkg/render, which cannot own them without importing
// this package back.
const (
	ElasticsearchNamespace = "tigera-elasticsearch"
	ManagerServiceName     = "calico-manager"
	ManagerNamespace       = common.CalicoNamespace
	ManagerPort            = 9443
)

// LinseedNamespace is the namespace Linseed runs in. Multi-tenant management
// clusters use the tenant namespace, everything else tigera-elasticsearch.
func LinseedNamespace(tenant *operatorv1.Tenant) string {
	if tenant.MultiTenant() {
		return tenant.Namespace
	}
	return ElasticsearchNamespace
}

// ManagerService is the URL of the Calico manager service. Multi-tenant
// management clusters use the tenant namespace, everything else calico-system.
func ManagerService(tenant *operatorv1.Tenant) string {
	if tenant.MultiTenant() {
		return fmt.Sprintf("https://%s.%s.svc:%d", ManagerServiceName, tenant.Namespace, ManagerPort)
	}
	return fmt.Sprintf("https://%s.%s.svc:%d", ManagerServiceName, ManagerNamespace, ManagerPort)
}
