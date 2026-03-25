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

package datastoremigration

import (
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newFakeClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		DatastoreMigrationGVR: "DatastoreMigrationList",
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, objects...)
}

func migrationCR(name, phase string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "migration.projectcalico.org",
		Version: "v1beta1",
		Kind:    "DatastoreMigration",
	})
	obj.SetName(name)
	if phase != "" {
		obj.Object["status"] = map[string]any{"phase": phase}
	}
	return obj
}

func TestGetPhaseAndExists(t *testing.T) {
	tests := []struct {
		name      string
		objects   []runtime.Object
		nilClient bool
		wantPhase string
		wantExist bool
	}{
		{
			name:      "nil client",
			nilClient: true,
			wantPhase: "",
			wantExist: false,
		},
		{
			name:      "no CRs",
			wantPhase: "",
			wantExist: false,
		},
		{
			name:      "CR with no status",
			objects:   []runtime.Object{migrationCR("default", "")},
			wantPhase: "",
			wantExist: true,
		},
		{
			name:      "CR in Migrating phase",
			objects:   []runtime.Object{migrationCR("default", PhaseMigrating)},
			wantPhase: PhaseMigrating,
			wantExist: true,
		},
		{
			name:      "CR in Converged phase",
			objects:   []runtime.Object{migrationCR("default", PhaseConverged)},
			wantPhase: PhaseConverged,
			wantExist: true,
		},
		{
			name:      "CR in Complete phase",
			objects:   []runtime.Object{migrationCR("default", PhaseComplete)},
			wantPhase: PhaseComplete,
			wantExist: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			if tt.nilClient {
				phase, err := GetPhase(nil)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(phase).To(Equal(tt.wantPhase))
				exists, err := Exists(nil)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(Equal(tt.wantExist))
				return
			}

			dc := newFakeClient(tt.objects...)
			phase, err := GetPhase(dc)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(phase).To(Equal(tt.wantPhase))
			exists, err := Exists(dc)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(exists).To(Equal(tt.wantExist))
		})
	}
}
