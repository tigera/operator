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

package apis

import "testing"

func TestDecideV3CRDs(t *testing.T) {
	cases := []struct {
		name                            string
		v1present, v3present, mapServed bool
		want                            bool
	}{
		{"v1 present stays v1", true, false, true, false},
		{"both present stays v1", true, true, true, false},
		{"v3 only stays v3", false, true, false, true},
		{"greenfield capable goes v3", false, false, true, true},
		{"greenfield not capable stays v1", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideV3CRDs(tc.v1present, tc.v3present, tc.mapServed)
			if got != tc.want {
				t.Errorf("decideV3CRDs(v1=%t,v3=%t,map=%t) = %t, want %t",
					tc.v1present, tc.v3present, tc.mapServed, got, tc.want)
			}
		})
	}
}
