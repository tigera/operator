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

package esmetrics

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func NewESMetricsControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
	multiTenant bool,
	readyFlag *utils.ReadyFlag,
) (*ESMetricsSubController, error) {

	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		MultiTenant:      multiTenant,
	}

	r := &ESMetricsSubController{
		client:         cli,
		scheme:         scheme,
		status:         status,
		clusterDomain:  opts.ClusterDomain,
		multiTenant:    opts.MultiTenant,
		tierWatchReady: readyFlag,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage Linseed controller", func() {
	var (
		cli        client.Client
		mockStatus *status.MockStatus
		scheme     *runtime.Scheme
		ctx        context.Context
		r          *ESMetricsSubController
		readyFlag  *utils.ReadyFlag
	)
	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		mockStatus = &status.MockStatus{}
		mockStatus.On("Run").Return()
		mockStatus.On("AddDeployments", mock.Anything)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()

		// Create the allow-tigera Tier, since the controller blocks on its existence.
		tier := &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}}
		Expect(cli.Create(ctx, tier)).ShouldNot(HaveOccurred())

		var err error
		r, err = NewESMetricsControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, false, readyFlag)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should reconcile resources", func() {
		err := cli.Create(ctx, &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      esmetrics.ElasticsearchMetricsSecret,
				Namespace: common.OperatorNamespace(),
			},
		})
		Expect(err).ShouldNot(HaveOccurred())

		install := &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Computed: &operatorv1.InstallationSpec{},
			},
			Spec: operatorv1.InstallationSpec{
				Variant: operatorv1.TigeraSecureEnterprise,
			},
		}
		Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

		cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		serverKeyPair, err := cm.GetOrCreateKeyPair(cli, esmetrics.ElasticsearchMetricsServerTLSSecret, render.ElasticsearchNamespace, []string{"filler"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, serverKeyPair.Secret(render.ElasticsearchNamespace))).ShouldNot(HaveOccurred())

		bundle := cm.CreateTrustedBundle(serverKeyPair)
		Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).ShouldNot(HaveOccurred())

		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should terminate early on managed cluster", func() {
		mgmtClusterConnection := &operatorv1.ManagementClusterConnection{
			ObjectMeta: metav1.ObjectMeta{
				Name: utils.DefaultTSEEInstanceKey.Name,
			},
		}

		err := cli.Create(ctx, mgmtClusterConnection)
		Expect(err).NotTo(HaveOccurred())

		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
	})
})
