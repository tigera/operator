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

package v1

import "testing"

func TestRBACManagementEnabled(t *testing.T) {
	state := func(s RBACUIStatusType) *RBACUIStatusType { return &s }

	for _, tc := range []struct {
		name string
		m    *Manager
		want bool
	}{
		// Nil paths: RBACManagementEnabled is called as managerCR.RBACManagementEnabled()
		// where managerCR is nil when no Manager CR exists, so a nil receiver (and each
		// nil field below) must return false rather than panic.
		{name: "nil Manager", m: nil, want: false},
		{name: "nil RBACUI", m: &Manager{}, want: false},
		{name: "nil State", m: &Manager{Spec: ManagerSpec{RBACUI: &RBACUI{}}}, want: false},

		{name: "State Enabled", m: &Manager{Spec: ManagerSpec{RBACUI: &RBACUI{State: state(RBACUIEnabled)}}}, want: true},
		{name: "State Disabled", m: &Manager{Spec: ManagerSpec{RBACUI: &RBACUI{State: state(RBACUIDisabled)}}}, want: false},
		// Any value other than Enabled is off (the Enum marker rejects this at the
		// apiserver, but the helper must not treat a non-empty value as enabled).
		{name: "State unrecognized value", m: &Manager{Spec: ManagerSpec{RBACUI: &RBACUI{State: state("SomethingElse")}}}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RBACManagementEnabled panicked on %s: %v", tc.name, r)
				}
			}()
			if got := tc.m.RBACManagementEnabled(); got != tc.want {
				t.Errorf("RBACManagementEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWAFManagementEnabled(t *testing.T) {
	state := func(s WAFUIStatusType) *WAFUIStatusType { return &s }

	for _, tc := range []struct {
		name string
		m    *Manager
		want bool
	}{
		// Nil paths: WAFManagementEnabled is called as managerCR.WAFManagementEnabled()
		// where managerCR is nil when no Manager CR exists, so a nil receiver (and each
		// nil field below) must return false rather than panic.
		{name: "nil Manager", m: nil, want: false},
		{name: "nil WAFUI", m: &Manager{}, want: false},
		{name: "nil State", m: &Manager{Spec: ManagerSpec{WAFUI: &WAFUI{}}}, want: false},

		{name: "State Enabled", m: &Manager{Spec: ManagerSpec{WAFUI: &WAFUI{State: state(WAFUIEnabled)}}}, want: true},
		{name: "State Disabled", m: &Manager{Spec: ManagerSpec{WAFUI: &WAFUI{State: state(WAFUIDisabled)}}}, want: false},
		// Any value other than Enabled is off (the Enum marker rejects this at the
		// apiserver, but the helper must not treat a non-empty value as enabled).
		{name: "State unrecognized value", m: &Manager{Spec: ManagerSpec{WAFUI: &WAFUI{State: state("SomethingElse")}}}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("WAFManagementEnabled panicked on %s: %v", tc.name, r)
				}
			}()
			if got := tc.m.WAFManagementEnabled(); got != tc.want {
				t.Errorf("WAFManagementEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
