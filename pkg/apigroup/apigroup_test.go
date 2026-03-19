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

package apigroup

import (
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

func TestSetAndGet(t *testing.T) {
	tests := []struct {
		name        string
		set         APIGroup
		wantGet     APIGroup
		wantEnvVars []corev1.EnvVar
	}{
		{
			name:        "default state is Unknown with nil env vars",
			set:         Unknown,
			wantGet:     Unknown,
			wantEnvVars: nil,
		},
		{
			name:    "V3 returns CALICO_API_GROUP env var",
			set:     V3,
			wantGet: V3,
			wantEnvVars: []corev1.EnvVar{
				{Name: "CALICO_API_GROUP", Value: "projectcalico.org/v3"},
			},
		},
		{
			name:        "V1 returns nil env vars",
			set:         V1,
			wantGet:     V1,
			wantEnvVars: nil,
		},
		{
			name:        "setting back to Unknown clears env vars",
			set:         Unknown,
			wantGet:     Unknown,
			wantEnvVars: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			Set(tt.set)
			g.Expect(Get()).To(Equal(tt.wantGet))
			g.Expect(EnvVars()).To(Equal(tt.wantEnvVars))
		})
	}
}
