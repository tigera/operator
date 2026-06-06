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

package utils

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/apis"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("PatchFelixConfiguration", Label("headless"), func() {
	It("returns an error detectable by meta.IsNoMatchError when the v3 API is not served", func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())

		// Simulate a cluster in which the projectcalico.org/v3 API is not served.
		c := ctrlrfake.DefaultFakeClientBuilder(scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, withWatch client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*v3.FelixConfiguration); ok {
						return &meta.NoKindMatchError{
							GroupKind: schema.GroupKind{Group: "projectcalico.org", Kind: "FelixConfiguration"},
						}
					}
					return withWatch.Get(ctx, key, obj, opts...)
				},
			}).
			Build()

		_, err := PatchFelixConfiguration(context.Background(), c, func(fc *v3.FelixConfiguration) (bool, error) {
			return true, nil
		})
		Expect(err).To(HaveOccurred())
		// Callers rely on detecting this condition through the wrapped error.
		Expect(meta.IsNoMatchError(err)).To(BeTrue())
	})
})
