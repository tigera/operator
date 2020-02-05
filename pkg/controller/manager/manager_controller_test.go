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

package manager

import (
	"context"

	"github.com/tigera/operator/pkg/apis"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Manager controller tests", func() {
	var c client.Client
	var instance *operatorv1.Manager

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme := runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		c = fake.NewFakeClientWithScheme(scheme)
	})

	AfterEach(func() {
		err := c.Delete(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should query a default manager instance", func() {
		By("Creating a CRD")
		instance = &operatorv1.Manager{
			TypeMeta:   metav1.TypeMeta{Kind: "Manager", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		err := c.Create(context.Background(), instance)
		Expect(err).NotTo(HaveOccurred())
		instance, err = GetManager(context.Background(), c)
		Expect(err).NotTo(HaveOccurred())
	})
})
