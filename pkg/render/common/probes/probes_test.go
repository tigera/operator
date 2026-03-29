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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
)

func TestApplyOverride_NilOverride(t *testing.T) {
	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/readiness", Port: intstr.FromInt(8080)},
		},
		PeriodSeconds: 30,
	}
	result := ApplyOverride(probe, nil)
	if result.PeriodSeconds != 30 {
		t.Errorf("expected PeriodSeconds=30, got %d", result.PeriodSeconds)
	}
}

func TestApplyOverride_NilProbe(t *testing.T) {
	override := &operatorv1.ProbeOverride{PeriodSeconds: ptr.Int32ToPtr(10)}
	result := ApplyOverride(nil, override)
	if result != nil {
		t.Error("expected nil probe to remain nil")
	}
}

func TestApplyOverride_AllFields(t *testing.T) {
	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/readiness", Port: intstr.FromInt(8080)},
		},
		PeriodSeconds:       30,
		TimeoutSeconds:      5,
		FailureThreshold:    3,
		InitialDelaySeconds: 0,
	}
	override := &operatorv1.ProbeOverride{
		PeriodSeconds:       ptr.Int32ToPtr(10),
		TimeoutSeconds:      ptr.Int32ToPtr(2),
		FailureThreshold:    ptr.Int32ToPtr(5),
		InitialDelaySeconds: ptr.Int32ToPtr(15),
	}
	result := ApplyOverride(probe, override)

	if result.PeriodSeconds != 10 {
		t.Errorf("PeriodSeconds: expected 10, got %d", result.PeriodSeconds)
	}
	if result.TimeoutSeconds != 2 {
		t.Errorf("TimeoutSeconds: expected 2, got %d", result.TimeoutSeconds)
	}
	if result.FailureThreshold != 5 {
		t.Errorf("FailureThreshold: expected 5, got %d", result.FailureThreshold)
	}
	if result.InitialDelaySeconds != 15 {
		t.Errorf("InitialDelaySeconds: expected 15, got %d", result.InitialDelaySeconds)
	}
	if result.HTTPGet == nil || result.HTTPGet.Path != "/readiness" {
		t.Error("probe handler was modified")
	}
}

func TestApplyOverride_PartialFields(t *testing.T) {
	probe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{Command: []string{"calico", "health"}},
		},
		PeriodSeconds:    30,
		TimeoutSeconds:   5,
		FailureThreshold: 3,
	}
	override := &operatorv1.ProbeOverride{
		PeriodSeconds: ptr.Int32ToPtr(10),
	}
	result := ApplyOverride(probe, override)

	if result.PeriodSeconds != 10 {
		t.Errorf("PeriodSeconds: expected 10, got %d", result.PeriodSeconds)
	}
	if result.TimeoutSeconds != 5 {
		t.Errorf("TimeoutSeconds should be unchanged: expected 5, got %d", result.TimeoutSeconds)
	}
	if result.FailureThreshold != 3 {
		t.Errorf("FailureThreshold should be unchanged: expected 3, got %d", result.FailureThreshold)
	}
}
