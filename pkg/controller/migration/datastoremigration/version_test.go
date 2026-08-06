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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes/fake"
)

// discoveryServing returns a discovery client serving datastoremigrations at each given version.
func discoveryServing(versions ...schema.GroupVersion) discovery.DiscoveryInterface {
	c := fake.NewClientset()
	for _, gv := range versions {
		c.Resources = append(c.Resources, &metav1.APIResourceList{
			GroupVersion: gv.String(),
			APIResources: []metav1.APIResource{{Name: Resource, Kind: Kind}},
		})
	}
	return c.Discovery()
}

func TestServedGroupVersion(t *testing.T) {
	cases := []struct {
		name   string
		disco  discovery.DiscoveryInterface
		want   schema.GroupVersion
		wantOK bool
	}{
		{"v1 only", discoveryServing(GroupVersionV1), GroupVersionV1, true},
		{"v1beta1 only", discoveryServing(GroupVersionV1beta1), GroupVersionV1beta1, true},
		{"both served prefers v1", discoveryServing(GroupVersionV1beta1, GroupVersionV1), GroupVersionV1, true},
		{"neither served", discoveryServing(), schema.GroupVersion{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ServedGroupVersion(tc.disco)
			if ok != tc.wantOK {
				t.Fatalf("ServedGroupVersion() ok = %t, want %t", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("ServedGroupVersion() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServedGroupVersionIgnoresGroupWithoutResource(t *testing.T) {
	c := fake.NewClientset()
	c.Resources = []*metav1.APIResourceList{{GroupVersion: GroupVersionV1.String()}}

	if _, ok := ServedGroupVersion(c.Discovery()); ok {
		t.Error("ServedGroupVersion() = true, want false when the group serves no datastoremigrations")
	}
}

func TestResolveServedVersion(t *testing.T) {
	cases := []struct {
		name  string
		disco discovery.DiscoveryInterface
		want  schema.GroupVersion
	}{
		{"switches to the legacy version", discoveryServing(GroupVersionV1beta1), GroupVersionV1beta1},
		{"stays on v1 when nothing is served", discoveryServing(), GroupVersionV1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := SchemeGroupVersion
			t.Cleanup(func() { SchemeGroupVersion = original })

			ResolveServedVersion(tc.disco)
			if SchemeGroupVersion != tc.want {
				t.Fatalf("SchemeGroupVersion = %v, want %v", SchemeGroupVersion, tc.want)
			}
			if got := WatchObject().APIVersion; got != tc.want.String() {
				t.Errorf("WatchObject() APIVersion = %q, want %q", got, tc.want.String())
			}
		})
	}
}
