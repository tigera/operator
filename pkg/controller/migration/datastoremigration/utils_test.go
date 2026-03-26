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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeClient(t *testing.T, objects ...*DatastoreMigration) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}
	b := fake.NewClientBuilder().WithScheme(scheme)
	for _, obj := range objects {
		b = b.WithObjects(obj)
	}
	return b.Build()
}

func migrationCR(name, phase string) *DatastoreMigration {
	obj := &DatastoreMigration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "DatastoreMigration",
			APIVersion: "migration.projectcalico.org/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	if phase != "" {
		obj.Status.Phase = phase
	}
	return obj
}

func TestGetPhaseAndExists(t *testing.T) {
	tests := []struct {
		name      string
		objects   []*DatastoreMigration
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
			objects:   []*DatastoreMigration{migrationCR("default", "")},
			wantPhase: "",
			wantExist: true,
		},
		{
			name:      "CR in Migrating phase",
			objects:   []*DatastoreMigration{migrationCR("default", PhaseMigrating)},
			wantPhase: PhaseMigrating,
			wantExist: true,
		},
		{
			name:      "CR in Converged phase",
			objects:   []*DatastoreMigration{migrationCR("default", PhaseConverged)},
			wantPhase: PhaseConverged,
			wantExist: true,
		},
		{
			name:      "CR in Complete phase",
			objects:   []*DatastoreMigration{migrationCR("default", PhaseComplete)},
			wantPhase: PhaseComplete,
			wantExist: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			if tt.nilClient {
				g.Expect(GetPhase(nil)).To(Equal(tt.wantPhase))
				g.Expect(Exists(nil)).To(Equal(tt.wantExist))
				return
			}

			c := newFakeClient(t, tt.objects...)
			g.Expect(GetPhase(c)).To(Equal(tt.wantPhase))
			g.Expect(Exists(c)).To(Equal(tt.wantExist))
		})
	}
}
