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

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDecideV3CRDs(t *testing.T) {
	cases := []struct {
		name                            string
		v1present, v3present, mapServed bool
		want                            bool
		wantErr                         bool
	}{
		{"v1 present stays v1", true, false, true, false, false},
		{"both present stays v1", true, true, true, false, false},
		{"v3 present with MAP stays v3", false, true, true, true, false},
		{"v3 present without MAP errors", false, true, false, false, true},
		{"greenfield capable goes v3", false, false, true, true, false},
		{"greenfield not capable stays v1", false, false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decideV3CRDs(tc.v1present, tc.v3present, tc.mapServed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("decideV3CRDs(v1=%t,v3=%t,map=%t) err = %v, wantErr %t",
					tc.v1present, tc.v3present, tc.mapServed, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("decideV3CRDs(v1=%t,v3=%t,map=%t) = %t, want %t",
					tc.v1present, tc.v3present, tc.mapServed, got, tc.want)
			}
		})
	}
}

func mapResourceList() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: "admissionregistration.k8s.io/v1beta1",
		APIResources: []metav1.APIResource{{Name: "mutatingadmissionpolicies", Kind: "MutatingAdmissionPolicy"}},
	}
}

func TestUseV3CRDsFromDiscovery(t *testing.T) {
	v1 := &metav1.APIResourceList{GroupVersion: "crd.projectcalico.org/v1"}
	v3 := &metav1.APIResourceList{GroupVersion: "projectcalico.org/v3"}

	cases := []struct {
		name      string
		resources []*metav1.APIResourceList
		want      bool
		wantErr   bool
	}{
		{"v1 present stays v1", []*metav1.APIResourceList{v1, mapResourceList()}, false, false},
		{"both present stays v1", []*metav1.APIResourceList{v1, v3, mapResourceList()}, false, false},
		{"v3 present with MAP stays v3", []*metav1.APIResourceList{v3, mapResourceList()}, true, false},
		{"v3 present without MAP errors", []*metav1.APIResourceList{v3}, false, true},
		{"greenfield capable goes v3", []*metav1.APIResourceList{mapResourceList()}, true, false},
		{"greenfield not capable stays v1", []*metav1.APIResourceList{}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientset()
			c.Resources = tc.resources
			got, err := useV3CRDsFromDiscovery(c.Discovery())
			if (err != nil) != tc.wantErr {
				t.Fatalf("useV3CRDsFromDiscovery() err = %v, wantErr %t", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("useV3CRDsFromDiscovery() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestRequireMAPForV3(t *testing.T) {
	cases := []struct {
		name      string
		useV3     bool
		resources []*metav1.APIResourceList
		want      bool
		wantErr   bool
	}{
		{"v1 passes through, MAP irrelevant", false, []*metav1.APIResourceList{}, false, false},
		{"v3 with MAP is allowed", true, []*metav1.APIResourceList{mapResourceList()}, true, false},
		{"v3 without MAP errors", true, []*metav1.APIResourceList{}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientset()
			c.Resources = tc.resources
			got, err := requireMAPForV3(tc.useV3, c.Discovery())
			if (err != nil) != tc.wantErr {
				t.Fatalf("requireMAPForV3() err = %v, wantErr %t", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("requireMAPForV3() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestMutatingAdmissionPolicyServed(t *testing.T) {
	cases := []struct {
		name      string
		resources []*metav1.APIResourceList
		want      bool
	}{
		{
			name: "served when MAP resource present",
			resources: []*metav1.APIResourceList{{
				GroupVersion: "admissionregistration.k8s.io/v1beta1",
				APIResources: []metav1.APIResource{{Name: "mutatingadmissionpolicies", Kind: "MutatingAdmissionPolicy"}},
			}},
			want: true,
		},
		{
			name: "not served when group present without MAP kind",
			resources: []*metav1.APIResourceList{{
				GroupVersion: "admissionregistration.k8s.io/v1",
				APIResources: []metav1.APIResource{{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"}},
			}},
			want: false,
		},
		{
			name:      "not served on empty cluster",
			resources: []*metav1.APIResourceList{},
			want:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientset()
			c.Resources = tc.resources
			got := mutatingAdmissionPolicyServed(c.Discovery())
			if got != tc.want {
				t.Errorf("mutatingAdmissionPolicyServed() = %t, want %t", got, tc.want)
			}
		})
	}
}
