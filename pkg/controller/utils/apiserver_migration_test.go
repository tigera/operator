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

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/apis"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("APIServerMigrationInProgress", func() {
	var (
		ctx    context.Context
		c      client.Client
		scheme *runtime.Scheme
	)

	allowTigeraTier := func() *v3.Tier {
		return &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}}
	}
	apiserverDeployment := func(ready int32) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"},
			Status:     appsv1.DeploymentStatus{ReadyReplicas: ready},
		}
	}

	BeforeEach(func() {
		ctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
	})

	It("returns false when the allow-tigera tier does not exist", func() {
		inProgress, err := APIServerMigrationInProgress(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(inProgress).To(BeFalse())
	})

	It("returns true when the allow-tigera tier exists but calico-apiserver is absent", func() {
		Expect(c.Create(ctx, allowTigeraTier())).NotTo(HaveOccurred())
		inProgress, err := APIServerMigrationInProgress(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(inProgress).To(BeTrue())
	})

	It("returns true when the allow-tigera tier exists and calico-apiserver has zero ready replicas", func() {
		Expect(c.Create(ctx, allowTigeraTier())).NotTo(HaveOccurred())
		Expect(c.Create(ctx, apiserverDeployment(0))).NotTo(HaveOccurred())
		inProgress, err := APIServerMigrationInProgress(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(inProgress).To(BeTrue())
	})

	It("returns false when the allow-tigera tier exists and calico-apiserver is ready", func() {
		Expect(c.Create(ctx, allowTigeraTier())).NotTo(HaveOccurred())
		Expect(c.Create(ctx, apiserverDeployment(1))).NotTo(HaveOccurred())
		inProgress, err := APIServerMigrationInProgress(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(inProgress).To(BeFalse())
	})
})
