// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Package rbacmanagement reads the admin-owned gate that switches the RBAC
// management UI on for a cluster.
package rbacmanagement

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

// ConfigMapName is the admin-owned switch for the RBAC management UI, read by the
// operator, ui-apis and rbacsync. Keep in sync with ui-apis rbacmanagement/gate.
const (
	ConfigMapName = "rbac-ui-config"
	ConfigMapKey  = "rbac-ui-enabled"
)

// Enabled reports whether the RBAC management UI is switched on for this cluster.
// A missing ConfigMap, missing key or unparsable value reads as disabled.
func Enabled(cm *corev1.ConfigMap) bool {
	if cm == nil {
		return false
	}
	enabled, err := strconv.ParseBool(cm.Data[ConfigMapKey])
	return err == nil && enabled
}
