// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package authentication_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/authentication"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("authentication controller tests", func() {

	var (
		cli        client.Client
		scheme     *runtime.Scheme
		ctx        context.Context
		mockStatus *status.MockStatus
		idpSecret  *corev1.Secret
	)

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = fake.NewFakeClientWithScheme(scheme)

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")

		idpSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.OIDCSecretName,
				Namespace: render.OperatorNamespace(),
			},
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			Data: map[string][]byte{
				"clientID":     []byte("a.b.com"),
				"clientSecret": []byte("my-secret"),
			}}
	})

	Context("OIDC connector config options", func() {
		It("should set oidc defaults ", func() {
			// Apply prerequisites for the basic reconcile to succeed.
			Expect(cli.Create(ctx, &operatorv1.Installation{
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
			})).ToNot(HaveOccurred())

			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-dex"}})).ToNot(HaveOccurred())

			// Apply an authentication spec that triggers all the logic in the updateAuthenticationWithDefaults() func.
			Expect(cli.Create(ctx, &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:      "https://example.com",
						UsernameClaim:  "email",
						GroupsClaim:    "group",
						GroupsPrefix:   "g",
						UsernamePrefix: "u",
					},
				},
			})).ToNot(HaveOccurred())

			// Reconcile
			r := authentication.NewReconciler(cli, scheme, operatorv1.ProviderNone, mockStatus)
			_, err := r.Reconcile(reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			authentication, err := utils.GetAuthentication(ctx, cli)
			Expect(err).NotTo(HaveOccurred())

			// Verify all the expected defaults.
			Expect(*authentication.Spec.OIDC.EmailVerification).To(Equal(operatorv1.EmailVerificationTypeVerify))
			Expect(authentication.Spec.UsernamePrefix).To(Equal("u"))
			Expect(authentication.Spec.GroupsPrefix).To(Equal("g"))
		})
	})
})
