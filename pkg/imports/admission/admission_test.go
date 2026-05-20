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

package admission

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/restmapper"

	opv1 "github.com/tigera/operator/api/v1"
)

// fakeMapper builds a RESTMapper that only knows the given GroupVersionResources.
func fakeMapper(gvrs ...schema.GroupVersionResource) meta.RESTMapper {
	apiGroupRes := []*restmapper.APIGroupResources{
		{
			Group: metav1.APIGroup{
				Name: APIGroup,
			},
			VersionedResources: map[string][]metav1.APIResource{},
		},
	}
	for _, gvr := range gvrs {
		kind := "MutatingAdmissionPolicy"
		if gvr.Resource == "mutatingadmissionpolicybindings" {
			kind = "MutatingAdmissionPolicyBinding"
		}
		apiGroupRes[0].VersionedResources[gvr.Version] = append(
			apiGroupRes[0].VersionedResources[gvr.Version],
			metav1.APIResource{Name: gvr.Resource, Namespaced: false, Kind: kind},
		)
		// Group versions need to be advertised too.
		seen := false
		for _, v := range apiGroupRes[0].Group.Versions {
			if v.Version == gvr.Version {
				seen = true
				break
			}
		}
		if !seen {
			apiGroupRes[0].Group.Versions = append(apiGroupRes[0].Group.Versions, metav1.GroupVersionForDiscovery{
				GroupVersion: gvr.GroupVersion().String(),
				Version:      gvr.Version,
			})
		}
	}
	return restmapper.NewDiscoveryRESTMapper(apiGroupRes)
}

var _ = Describe("MutatingAdmissionPolicies", func() {
	Describe("DiscoverAPIVersion", func() {
		It("prefers v1 when both are served", func() {
			mapper := fakeMapper(
				schema.GroupVersionResource{Group: APIGroup, Version: "v1", Resource: "mutatingadmissionpolicies"},
				schema.GroupVersionResource{Group: APIGroup, Version: "v1beta1", Resource: "mutatingadmissionpolicies"},
			)
			Expect(DiscoverAPIVersion(mapper)).To(Equal(VersionV1))
		})

		It("falls back to v1beta1", func() {
			mapper := fakeMapper(
				schema.GroupVersionResource{Group: APIGroup, Version: "v1beta1", Resource: "mutatingadmissionpolicies"},
			)
			Expect(DiscoverAPIVersion(mapper)).To(Equal(VersionV1Beta1))
		})

		It("returns empty when nothing is served", func() {
			Expect(DiscoverAPIVersion(fakeMapper())).To(BeEmpty())
		})
	})

	Describe("GetMutatingAdmissionPolicies", func() {
		It("returns Calico v1beta1 MAPs when v3=true", func() {
			objs := GetMutatingAdmissionPolicies(opv1.Calico, true, VersionV1Beta1)
			Expect(objs).To(HaveLen(4))

			var mapCount, mapbCount int
			for _, obj := range objs {
				switch obj.(type) {
				case *admissionv1beta1.MutatingAdmissionPolicy:
					mapCount++
				case *admissionv1beta1.MutatingAdmissionPolicyBinding:
					mapbCount++
				}
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
			}
			Expect(mapCount).To(Equal(2))
			Expect(mapbCount).To(Equal(2))
		})

		It("returns Calico v1 MAPs when discovered version is v1", func() {
			objs := GetMutatingAdmissionPolicies(opv1.Calico, true, VersionV1)
			Expect(objs).To(HaveLen(4))

			var mapCount, mapbCount int
			for _, obj := range objs {
				switch o := obj.(type) {
				case *admissionregistrationv1.MutatingAdmissionPolicy:
					mapCount++
					Expect(o.APIVersion).To(Equal(APIGroup + "/" + VersionV1))
				case *admissionregistrationv1.MutatingAdmissionPolicyBinding:
					mapbCount++
					Expect(o.APIVersion).To(Equal(APIGroup + "/" + VersionV1))
				}
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
			}
			Expect(mapCount).To(Equal(2))
			Expect(mapbCount).To(Equal(2))
		})

		It("returns Enterprise MAPs at the chosen version", func() {
			objs := GetMutatingAdmissionPolicies(opv1.CalicoEnterprise, true, VersionV1)
			Expect(objs).To(HaveLen(4))

			var mapCount, mapbCount int
			for _, obj := range objs {
				switch obj.(type) {
				case *admissionregistrationv1.MutatingAdmissionPolicy:
					mapCount++
				case *admissionregistrationv1.MutatingAdmissionPolicyBinding:
					mapbCount++
				}
			}
			Expect(mapCount).To(Equal(2))
			Expect(mapbCount).To(Equal(2))
		})

		It("returns empty when v3=false", func() {
			Expect(GetMutatingAdmissionPolicies(opv1.Calico, false, VersionV1)).To(BeEmpty())
			Expect(GetMutatingAdmissionPolicies(opv1.CalicoEnterprise, false, VersionV1)).To(BeEmpty())
		})

		It("returns empty when apiVersion is empty", func() {
			Expect(GetMutatingAdmissionPolicies(opv1.Calico, true, "")).To(BeEmpty())
		})

		It("parses MAP names correctly", func() {
			objs := GetMutatingAdmissionPolicies(opv1.Calico, true, VersionV1)
			for _, obj := range objs {
				Expect(obj.GetName()).ToNot(BeEmpty())
			}
		})
	})
})
