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

package probes

import (
	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// ApplyOverride applies user-provided probe timing overrides to a probe.
// The probe handler is not modified — only timing parameters are overridden.
// If override is nil, the probe is returned unchanged.
func ApplyOverride(probe *corev1.Probe, override *operatorv1.ProbeOverride) *corev1.Probe {
	if probe == nil || override == nil {
		return probe
	}
	if override.PeriodSeconds != nil {
		probe.PeriodSeconds = *override.PeriodSeconds
	}
	if override.TimeoutSeconds != nil {
		probe.TimeoutSeconds = *override.TimeoutSeconds
	}
	if override.FailureThreshold != nil {
		probe.FailureThreshold = *override.FailureThreshold
	}
	if override.InitialDelaySeconds != nil {
		probe.InitialDelaySeconds = *override.InitialDelaySeconds
	}
	return probe
}
