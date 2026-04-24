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

package components

import (
	operatorv1 "github.com/tigera/operator/api/v1"
)

// CalicoBinaryPath is the absolute path to the combined "calico" binary inside the calico/calico image.
// Components deployed from the combined image invoke this binary via Command / probe exec.
const CalicoBinaryPath = "/usr/bin/calico"

// UsesCombinedCalicoImage reports whether the given installation should deploy the combined
// calico/calico image in place of per-component images. Today this is all Calico OSS installs,
// including FIPS mode. Enterprise support for the combined image is planned as a follow-up.
func UsesCombinedCalicoImage(installation *operatorv1.InstallationSpec) bool {
	if installation == nil {
		return false
	}
	return !installation.Variant.IsEnterprise()
}

// CombinedCalicoImage returns the combined calico/calico Component for the given installation
// along with a boolean indicating whether it should be used. When the boolean is false, the
// returned Component is meaningless and callers should deploy per-component images instead.
// The FIPS-tagged variant is selected automatically when FIPS mode is enabled.
func CombinedCalicoImage(installation *operatorv1.InstallationSpec) (Component, bool) {
	if !UsesCombinedCalicoImage(installation) {
		return Component{}, false
	}
	if operatorv1.IsFIPSModeEnabled(installation.FIPSMode) {
		return ComponentCalicoFIPS, true
	}
	return ComponentCalico, true
}
