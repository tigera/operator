// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package render

import (
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// LinseedNamespace determine the namespace in which Linseed is running.
// For management and standalone clusters, this is always the tigera-elasticsearch
// namespace. For multi-tenant management clusters, this is the tenant namespace
func LinseedNamespace(tenant *operatorv1.Tenant) string {
	if tenant.MultiTenant() {
		return tenant.Namespace
	}
	return ElasticsearchNamespace
}

// ManagerService determine the name of the tigera manager service.
// For management and standalone clusters, this is always the tigera-manager.tigera-manager
// namespace. For multi-tenant management clusters, this is a service that resides within the
// tenant namespace
func ManagerService(tenant *operatorv1.Tenant) string {
	if tenant.MultiTenant() {
		return fmt.Sprintf("https://tigera-manager.%s.svc:9443", tenant.Namespace)
	}
	return fmt.Sprintf("https://tigera-manager.%s.svc:9443", ManagerNamespace)
}
