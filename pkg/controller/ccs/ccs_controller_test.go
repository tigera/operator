// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ccs

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	ccsrender "github.com/tigera/operator/pkg/render/ccs"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("CCS controller tests", func() {
	var c client.Client
	var ctx context.Context
	var cr *operatorv1.ComplianceConfigurationSecurity
	var r ReconcileCCS
	var mockStatus *status.MockStatus
	var scheme *runtime.Scheme
	var installation *operatorv1.Installation

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDeployments", mock.Anything).Return()
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("AddCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		// Create an object we can use throughout the test to do the CCS reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileCCS{
			client:          c,
			scheme:          scheme,
			provider:        operatorv1.ProviderNone,
			status:          mockStatus,
			clusterDomain:   dns.DefaultClusterDomain,
			licenseAPIReady: &utils.ReadyFlag{},
			tierWatchReady:  &utils.ReadyFlag{},
		}
		// We start off with a 'standard' installation, with nothing special
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Registry: "some.registry.org/",
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.TigeraSecureEnterprise,
				Computed: &operatorv1.InstallationSpec{
					Registry: "my-reg",
					// The test is provider agnostic.
					KubernetesProvider: operatorv1.ProviderNone,
				},
			},
		}
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &operatorv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}, Status: operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ComplianceFeature}}})).NotTo(HaveOccurred())

		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		esDNSNames := dns.GetServiceDNSNames(render.TigeraElasticsearchGatewaySecret, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
		linseedKeyPair, err := certificateManager.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, render.ElasticsearchNamespace, esDNSNames)
		Expect(err).NotTo(HaveOccurred())

		//For managed clusters, we also need the public cert for Linseed.
		linseedPublicCert, err := certificateManager.GetOrCreateKeyPair(c, render.VoltronLinseedPublicCert, common.OperatorNamespace(), esDNSNames)
		Expect(err).NotTo(HaveOccurred())

		Expect(c.Create(ctx, linseedKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(c.Create(ctx, linseedPublicCert.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Apply the CCS CR to the fake cluster.
		cr = &operatorv1.ComplianceConfigurationSecurity{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
		Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

		// Mark that watches were successful.
		r.licenseAPIReady.MarkAsReady()
		r.tierWatchReady.MarkAsReady()
	})

	It("should create resources for standalone clusters", func() {
		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Requeue).NotTo(BeTrue())

		dpl := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{}}

		Expect(c.Get(ctx, client.ObjectKey{Name: ccsrender.APIResourceName, Namespace: ccsrender.Namespace}, &dpl)).Error().NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(ccsrender.APIResourceName))
		Expect(c.Get(ctx, client.ObjectKey{Name: ccsrender.ControllerResourceName, Namespace: ccsrender.Namespace}, &dpl)).Error().NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(ccsrender.ControllerResourceName))

	})

})
