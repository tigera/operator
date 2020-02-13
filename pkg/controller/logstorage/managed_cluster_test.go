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

package logstorage

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/render"

	"github.com/tigera/operator/pkg/apis"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/status"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Managed cluster tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileLogStorage
	var scheme *runtime.Scheme
	var inst *operatorv1.Installation

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = fake.NewFakeClientWithScheme(scheme)
		ctx = context.Background()

		// Create an object we can use throughout the test to do the reconcile loops.
		r = ReconcileLogStorage{
			client:   c,
			scheme:   scheme,
			provider: operatorv1.ProviderNone,
			status:   status.New(c, "logstorage"),
			localDNS: "example.org",
		}

		// Define what kind of installation we want to render.
		inst = &operatorv1.Installation{
			Spec: operatorv1.InstallationSpec{
				Registry: "my-reg",
				// The test is provider agnostic.
				KubernetesProvider:    operatorv1.ProviderNone,
				ClusterManagementType: operatorv1.ClusterManagementTypeManaged,
			},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
	})

	It("should remove the lingering eck webhook when changing Standalone -> Managed", func() {

		By("setting up the lingering webhook")
		webhook := &corev1.Service{
			TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ECKWebhookName,
				Namespace: render.ECKOperatorNamespace,
			},
		}
		Expect(c.Create(ctx, webhook)).NotTo(HaveOccurred())

		By("verifying the webhook is created and that it can be retrieved by object key")
		key, err := client.ObjectKeyFromObject(webhook)
		Expect(err).NotTo(HaveOccurred())

		By("reconciling for managed clusters")
		result, err := r.reconcileManaged(ctx, inst, nil)
		Expect(result.Requeue).NotTo(BeTrue())
		Expect(err).NotTo(HaveOccurred())

		By("verifying the webhook is no longer there")
		key, err = client.ObjectKeyFromObject(webhook)
		Expect(err).NotTo(HaveOccurred())
		Expect(errors.IsNotFound(c.Get(ctx, key, webhook))).To(BeTrue())
	})
})
