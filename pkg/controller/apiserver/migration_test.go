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

package apiserver

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

func apiService(ns string, available bool) *apiregv1.APIService {
	st := apiregv1.ConditionFalse
	if available {
		st = apiregv1.ConditionTrue
	}
	return &apiregv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: calicoAPIServiceName},
		Spec: apiregv1.APIServiceSpec{
			Group:   "projectcalico.org",
			Version: "v3",
			Service: &apiregv1.ServiceReference{Name: "calico-api", Namespace: ns},
		},
		Status: apiregv1.APIServiceStatus{
			Conditions: []apiregv1.APIServiceCondition{
				{Type: apiregv1.Available, Status: st},
			},
		},
	}
}

func newReader(objs ...client.Object) client.Client {
	s := runtime.NewScheme()
	Expect(apiregv1.AddToScheme(s)).NotTo(HaveOccurred())
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

var _ = Describe("readAPIServiceState", func() {
	ctx := context.Background()

	It("reports layoutAbsent when the APIService does not exist", func() {
		layout, available, err := readAPIServiceState(ctx, newReader())
		Expect(err).NotTo(HaveOccurred())
		Expect(layout).To(Equal(layoutAbsent))
		Expect(available).To(BeFalse())
	})

	It("reports the deprecated layout when the APIService points at tigera-system", func() {
		layout, available, err := readAPIServiceState(ctx, newReader(apiService("tigera-system", true)))
		Expect(err).NotTo(HaveOccurred())
		Expect(layout).To(Equal(layoutDeprecated))
		Expect(available).To(BeTrue())
	})

	It("reports the current layout when the APIService points at calico-system", func() {
		layout, available, err := readAPIServiceState(ctx, newReader(apiService("calico-system", true)))
		Expect(err).NotTo(HaveOccurred())
		Expect(layout).To(Equal(layoutCurrent))
		Expect(available).To(BeTrue())
	})

	It("reports unavailable when the Available condition is False", func() {
		_, available, err := readAPIServiceState(ctx, newReader(apiService("tigera-system", false)))
		Expect(err).NotTo(HaveOccurred())
		Expect(available).To(BeFalse())
	})

	It("reports unavailable when there is no Available condition at all", func() {
		as := apiService("tigera-system", true)
		as.Status.Conditions = nil
		_, available, err := readAPIServiceState(ctx, newReader(as))
		Expect(err).NotTo(HaveOccurred())
		Expect(available).To(BeFalse())
	})
})

func denyPolicy() *v3.NetworkPolicy {
	return &v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.default-deny", Namespace: "calico-system"},
		Spec:       v3.NetworkPolicySpec{Tier: "allow-tigera", Selector: "all()"},
	}
}

func newV3Reader(objs ...client.Object) client.Client {
	s := runtime.NewScheme()
	Expect(apiregv1.AddToScheme(s)).NotTo(HaveOccurred())
	Expect(v3.AddToScheme(s)).NotTo(HaveOccurred())
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

// errReader returns a fixed error from Get, so the no-swallowing behaviour is testable.
type errReader struct {
	client.Reader
	err error
}

func (e errReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return e.err
}

var _ = Describe("deprecatedDenyPresent", func() {
	ctx := context.Background()

	It("reports false when the policy is absent", func() {
		present, err := deprecatedDenyPresent(ctx, newV3Reader())
		Expect(err).NotTo(HaveOccurred())
		Expect(present).To(BeFalse())
	})

	It("reports true when the policy is present", func() {
		present, err := deprecatedDenyPresent(ctx, newV3Reader(denyPolicy()))
		Expect(err).NotTo(HaveOccurred())
		Expect(present).To(BeTrue())
	})

	It("returns a NoMatch error instead of treating it as absent", func() {
		noMatch := &meta.NoKindMatchError{
			GroupKind: schema.GroupKind{Group: "projectcalico.org", Kind: "NetworkPolicy"},
		}
		_, err := deprecatedDenyPresent(ctx, errReader{err: noMatch})
		Expect(err).To(HaveOccurred())
		Expect(meta.IsNoMatchError(err)).To(BeTrue())
	})

	It("returns any other error", func() {
		_, err := deprecatedDenyPresent(ctx, errReader{err: errors.New("boom")})
		Expect(err).To(MatchError("boom"))
	})
})

var _ = Describe("decideMigration", func() {
	It("proceeds on a fresh install", func() {
		Expect(decideMigration(layoutAbsent, false, false)).To(Equal(decisionProceed))
	})

	It("proceeds once the APIService already points at calico-system, even if the deny lingers", func() {
		// This is the state a two-hop upgrade through CE 3.22 leaves behind: the namespace
		// is gone and allow-tigera.default-deny is still present, excluding the API server
		// by selector. There is no move left to make, so there is nothing to wait for.
		Expect(decideMigration(layoutCurrent, true, true)).To(Equal(decisionProceed))
	})

	It("holds without acting when a migration is pending and the aggregated API cannot serve", func() {
		Expect(decideMigration(layoutDeprecated, false, true)).To(Equal(decisionHoldAPIUnavailable))
		Expect(decideMigration(layoutDeprecated, false, false)).To(Equal(decisionHoldAPIUnavailable))
	})

	It("waits for the deny to be removed when a migration is pending and the API can serve", func() {
		Expect(decideMigration(layoutDeprecated, true, true)).To(Equal(decisionWaitForDenyRemoval))
	})

	It("proceeds when a migration is pending, the API can serve and the deny is gone", func() {
		Expect(decideMigration(layoutDeprecated, true, false)).To(Equal(decisionProceed))
	})
})

var _ = Describe("policyComponentFirst", func() {
	It("is false when the policy is not being rendered at all", func() {
		Expect(policyComponentFirst(true, false)).To(BeFalse())
	})

	It("is false on an ordinary reconcile with no migration pending", func() {
		Expect(policyComponentFirst(false, true)).To(BeFalse())
	})

	It("is true on the pass that performs the migration", func() {
		Expect(policyComponentFirst(true, true)).To(BeTrue())
	})
})
