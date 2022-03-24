// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package certificatemanager

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Certificate manager controller tests", func() {
	var c client.Client
	var scheme *runtime.Scheme
	var installation *operatorv1.Installation
	var ctx context.Context
	var r ReconcileCertificateManager
	var mockStatus *status.MockStatus
	var certificateManagement *operatorv1.CertificateManagement

	BeforeEach(func() {
		ctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		mockStatus = &status.MockStatus{}
		c = fake.NewClientBuilder().WithScheme(scheme).Build()
		r = ReconcileCertificateManager{
			client: c,
			scheme: scheme,
			status: mockStatus,
		}
		installation = &operatorv1.Installation{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
		ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		Expect(err).NotTo(HaveOccurred())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		certificateManagement = &operatorv1.CertificateManagement{CACert: cert}
	})

	It("should not render anything if no installation is present", func() {
		mockStatus.On("OnCRNotFound").Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		secret, err := utils.GetSecret(ctx, c, certificatemanagement.CASecretName, common.OperatorNamespace())
		Expect(secret).To(BeNil())
		Expect(err).NotTo(HaveOccurred())
	})

	It("should render the CA if installation is present", func() {
		mockStatus.On("ClearDegraded").Return()
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		secret, err := utils.GetSecret(ctx, c, certificatemanagement.CASecretName, common.OperatorNamespace())
		Expect(secret).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not render anything if certificate management is used", func() {
		mockStatus.On("ClearDegraded").Return()
		installation.Spec.CertificateManagement = certificateManagement
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		secret, err := utils.GetSecret(ctx, c, certificatemanagement.CASecretName, common.OperatorNamespace())
		Expect(secret).To(BeNil())
		Expect(err).NotTo(HaveOccurred())
	})
})
