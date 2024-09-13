// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package nonclusterhost

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/status"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("NonClusterHost controller tests", func() {
	var (
		cli            client.Client
		ctx            context.Context
		mockStatus     *status.MockStatus
		r              ReconcileNonClusterHost
		scheme         *runtime.Scheme
		nonclusterhost *operatorv1.NonClusterHost
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		mockStatus = &status.MockStatus{}
		mockStatus.On("ClearDegraded")
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		r = ReconcileNonClusterHost{
			client: cli,
			scheme: scheme,
			status: mockStatus,
		}

		nonclusterhost = &operatorv1.NonClusterHost{
			TypeMeta:   metav1.TypeMeta{Kind: "NonClusterHost", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
	})

	Context("controller reconciliation", func() {
		var (
			sa     = &corev1.ServiceAccount{}
			secret = &corev1.Secret{}
			cr     = &rbacv1.ClusterRole{}
			crb    = &rbacv1.ClusterRoleBinding{}
		)

		It("should render NonClusterHost resources", func() {
			Expect(cli.Create(ctx, nonclusterhost)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			// resources will be created after reconciliation
			err = cli.Get(ctx, client.ObjectKey{Name: "tigera-noncluster-host", Namespace: "calico-system"}, sa)
			Expect(err).NotTo(HaveOccurred())
			err = cli.Get(ctx, client.ObjectKey{Name: "tigera-noncluster-host", Namespace: "calico-system"}, secret)
			Expect(err).NotTo(HaveOccurred())
			err = cli.Get(ctx, client.ObjectKey{Name: "tigera-noncluster-host"}, cr)
			Expect(err).NotTo(HaveOccurred())
			err = cli.Get(ctx, client.ObjectKey{Name: "tigera-noncluster-host"}, crb)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
