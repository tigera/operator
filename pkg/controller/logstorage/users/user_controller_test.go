// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package users

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	tigeraelastic "github.com/tigera/operator/pkg/controller/logstorage/elastic"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func NewReconcilerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	esCliCreator utils.ElasticsearchClientCreator,
	clusterDomain string,
) (*UserController, error) {
	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
	}

	r := &UserController{
		client:      cli,
		scheme:      scheme,
		esClientFn:  esCliCreator,
		status:      status,
		multiTenant: opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage users controller", func() {
	var (
		cli client.Client
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(operatorv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
	})

	It("should clean up Elastic users for tenants that no longer exist", func() {
		t := &testing.T{}
		ctrl := UserController{
			client:     cli,
			esClientFn: tigeraelastic.MockESCLICreator,
		}
		testESClient := tigeraelastic.MockESClient{}
		ctx := context.WithValue(context.Background(), "esClient", &testESClient)

		esTestUsers := []utils.User{
			{
				Username: "tigera-ee-linseed-1",
			},
			{
				Username: "tigera-ee-linseed-2",
			},
		}

		testESClient.On("GetUsers", ctx).Return(esTestUsers, nil)
		testESClient.On("DeleteUser", ctx, &utils.User{Username: "tigera-ee-linseed-1"}).Return(nil)

		t1 := operatorv1.Tenant{
			ObjectMeta: v1.ObjectMeta{
				Name: "default",
			},
			Spec: operatorv1.TenantSpec{
				ID: "2",
			},
		}

		err := cli.Create(ctx, &t1)
		Expect(err).NotTo(HaveOccurred())

		logr := logf.Log.WithName("user-controller-test")
		err = ctrl.cleanupStaleUsers(ctx, logr)
		Expect(err).NotTo(HaveOccurred())

		Expect(testESClient.AssertExpectations(t))
	})
})
