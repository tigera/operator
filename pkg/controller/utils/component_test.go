// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package utils_test

import (
	"context"

	ocsv1 "github.com/openshift/api/security/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	"github.com/tigera/operator/pkg/apis"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	v1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var log = logf.Log.WithName("test_utils_logger")

var _ = Describe("Component handler tests", func() {
	var (
		c        client.Client
		instance *operatorv1.Manager
		ctx      context.Context
		scheme   *runtime.Scheme
		sm       status.StatusManager
		fc       render.Component
		handler  utils.ComponentHandler
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		Expect(v1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()
		sm = status.New(c, "fake-component")
		fc = &fakeComponent{}

		// We need to provide something to handler even though it seems to be unused..
		instance = &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		handler = utils.NewComponentHandler(log, c, scheme, instance)
	})
	It("merges annotations and reconciles only operator added annotations", func() {
		err := handler.CreateOrUpdate(ctx, fc, *sm)
		Expect(err).To(BeNil())

		By("checking that the namespace is created and desired annotations is present")
		expectedAnnotations := map[string]string{
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		nsKey := client.ObjectKey{
			Name: "test-namespace",
		}
		ns := &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("ovewriting the namespace with SCC annotations")
		annotations := map[string]string{
			ocsv1.UIDRangeAnnotation: "1-65535",
		}
		updatedNs := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-namespace",
				Annotations: annotations,
			},
		}
		c.Update(ctx, updatedNs)

		By("checking that the namespace is updated with SCC annotation")
		expectedAnnotations = map[string]string{
			ocsv1.UIDRangeAnnotation: "1-65535",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("initiating a merge with Openshift SCC annotations")
		err = handler.CreateOrUpdate(ctx, fc, *sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that both current and desired annotations are still present")
		expectedAnnotations = map[string]string{
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		ns = &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("changing a desired annotation")
		annotations = map[string]string{
			ocsv1.UIDRangeAnnotation:   "1-65535",
			"cattle-not-pets":          "indeed",
			fakeComponentAnnotationKey: "not-present",
		}
		updatedNs = &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-namespace",
				Annotations: annotations,
			},
		}
		c.Update(ctx, updatedNs)

		By("checking that the namespace is updated with new modified annotation")
		expectedAnnotations = map[string]string{
			"cattle-not-pets":          "indeed",
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: "not-present",
		}
		nsKey = client.ObjectKey{
			Name: "test-namespace",
		}
		ns = &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))

		By("initiating a merge with namespace containing modified desired annotation")
		err = handler.CreateOrUpdate(ctx, fc, *sm)
		Expect(err).To(BeNil())

		By("retrieving the namespace and checking that desired annotation is reconciled, everything else is left as-is")
		expectedAnnotations = map[string]string{
			"cattle-not-pets":          "indeed",
			ocsv1.UIDRangeAnnotation:   "1-65535",
			fakeComponentAnnotationKey: fakeComponentAnnotationValue,
		}
		ns = &v1.Namespace{}
		c.Get(ctx, nsKey, ns)
		Expect(ns.GetAnnotations()).To(Equal(expectedAnnotations))
	})
})

const (
	fakeComponentAnnotationKey   = "tigera.io/annotation-should-be"
	fakeComponentAnnotationValue = "present"
)

// A fake component that only returns ready and always creates the "test-namespace" Namespace.
type fakeComponent struct {
}

func (c *fakeComponent) Ready() bool {
	return true
}

func (c *fakeComponent) Objects() ([]runtime.Object, []runtime.Object) {
	objsToCreate := []runtime.Object{
		&v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-namespace",
				Annotations: map[string]string{
					fakeComponentAnnotationKey: fakeComponentAnnotationValue,
				},
			},
		},
	}
	return objsToCreate, nil
}
