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

// Package wafmanagement reads the admin-owned gate that switches the WAF
// management UI on for a cluster.
package wafmanagement

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

const (
	// ConfigMapName is the admin-owned switch for the WAF management UI. Unlike the
	// RBAC gate, only the operator reads it: it is projected onto the ui-apis
	// container as WAF_UI_ENABLED, so a toggle rolls the manager Deployment.
	ConfigMapName = "waf-ui-config"
	ConfigMapKey  = "waf-ui-enabled"
)

// Enabled reports whether the WAF management UI is switched on for this cluster.
// A missing ConfigMap, missing key or unparsable value reads as disabled.
func Enabled(cm *corev1.ConfigMap) bool {
	if cm == nil {
		return false
	}
	enabled, err := strconv.ParseBool(cm.Data[ConfigMapKey])
	return err == nil && enabled
}
