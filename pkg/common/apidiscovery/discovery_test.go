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

package apidiscovery

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeMapper returns the registered versions for the given GroupKind. Other RESTMapper methods
// are not implemented because Discovery only uses RESTMappings.
type fakeMapper struct {
	meta.RESTMapper
	served map[schema.GroupKind][]string
	calls  int
}

func (f *fakeMapper) RESTMappings(gk schema.GroupKind, _ ...string) ([]*meta.RESTMapping, error) {
	f.calls++
	versions, ok := f.served[gk]
	if !ok {
		return nil, &meta.NoKindMatchError{GroupKind: gk}
	}
	out := make([]*meta.RESTMapping, 0, len(versions))
	for _, v := range versions {
		out = append(out, &meta.RESTMapping{GroupVersionKind: gk.WithVersion(v)})
	}
	return out, nil
}

func TestDiscoveryRecordsPreferredVersion(t *testing.T) {
	mapper := &fakeMapper{served: map[schema.GroupKind][]string{
		{Group: "admissionregistration.k8s.io", Kind: "MutatingAdmissionPolicy"}: {"v1", "v1beta1"},
		{Group: "certificates.k8s.io", Kind: "CertificateSigningRequest"}:        {"v1"},
	}}
	tracked := []schema.GroupKind{
		{Group: "admissionregistration.k8s.io", Kind: "MutatingAdmissionPolicy"},
		{Group: "certificates.k8s.io", Kind: "CertificateSigningRequest"},
		{Group: "made.up.example.com", Kind: "Nope"},
	}

	d := New(mapper, tracked)

	if got := d.ServedVersion("admissionregistration.k8s.io", "MutatingAdmissionPolicy"); got != "v1" {
		t.Errorf("MutatingAdmissionPolicy: got %q, want v1", got)
	}
	if got := d.ServedVersion("certificates.k8s.io", "CertificateSigningRequest"); got != "v1" {
		t.Errorf("CertificateSigningRequest: got %q, want v1", got)
	}
	if got := d.ServedVersion("made.up.example.com", "Nope"); got != "" {
		t.Errorf("Nope: got %q, want empty", got)
	}
	if got := d.ServedVersion("never.registered.com", "Other"); got != "" {
		t.Errorf("untracked GroupKind: got %q, want empty", got)
	}
}

func TestDiscoveryNoCallsAfterConstruction(t *testing.T) {
	mapper := &fakeMapper{served: map[schema.GroupKind][]string{
		{Group: "g", Kind: "K"}: {"v1"},
	}}
	d := New(mapper, []schema.GroupKind{{Group: "g", Kind: "K"}})
	calls := mapper.calls

	for i := 0; i < 100; i++ {
		_ = d.ServedVersion("g", "K")
		_ = d.ServedVersion("nope", "Other")
	}
	if mapper.calls != calls {
		t.Errorf("expected zero additional mapper calls after construction, got %d (was %d)", mapper.calls, calls)
	}
}

func TestNilDiscoverySafe(t *testing.T) {
	var d *Discovery
	if got := d.ServedVersion("g", "K"); got != "" {
		t.Errorf("nil Discovery: got %q, want empty", got)
	}
}
