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
	. "github.com/onsi/ginkgo/extensions/table"
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
		auth       *operatorv1.Authentication
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
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything).Return()

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

		auth = &operatorv1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://example.com",
			},
		}
	})

	Context("OIDC connector config options", func() {
		It("should set oidc defaults ", func() {
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-dex"}})).ToNot(HaveOccurred())
			auth.Spec.OIDC = &operatorv1.AuthenticationOIDC{
				IssuerURL:      "https://example.com",
				UsernameClaim:  "email",
				GroupsClaim:    "group",
				GroupsPrefix:   "g",
				UsernamePrefix: "u",
			}
			// Apply an authentication spec that triggers all the logic in the updateAuthenticationWithDefaults() func.
			Expect(cli.Create(ctx, auth)).ToNot(HaveOccurred())

			// Reconcile
			r := authentication.NewReconciler(cli, scheme, operatorv1.ProviderNone, mockStatus, "")
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			authentication, err := utils.GetAuthentication(ctx, cli)
			Expect(err).NotTo(HaveOccurred())

			// Verify all the expected defaults.
			Expect(*authentication.Spec.OIDC.EmailVerification).To(Equal(operatorv1.EmailVerificationTypeVerify))
			Expect(authentication.Spec.UsernamePrefix).To(Equal("u"))
			Expect(authentication.Spec.GroupsPrefix).To(Equal("g"))
		})
	})

	const (
		validCA       = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"
		validPW       = "dc=example,dc=com"
		validDN       = "dc=example,dc=com"
		invalidDN     = "dc=example,dc=com,pancake"
		validFilter   = "(objectClass=posixGroup)"
		invalidFilter = "(objectClass=posixGroup)pancake"
		attribute     = "uid"
	)
	DescribeTable("LDAP connector config options should be validated", func(ldap *operatorv1.AuthenticationLDAP, secretDN, secretPW, secretCA []byte, expectReconcilePass bool) {
		nameAttrEmpty := ldap.UserSearch.NameAttribute == ""
		auth.Spec.LDAP = ldap
		idpSecret.Name = render.LDAPSecretName
		idpSecret.Data = map[string][]byte{
			render.BindDNSecretField: secretDN,
			render.BindPWSecretField: secretPW,
			render.RootCASecretField: secretCA,
		}
		Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-dex"}})).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, auth)).ToNot(HaveOccurred())
		r := authentication.NewReconciler(cli, scheme, operatorv1.ProviderNone, mockStatus, "")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		if expectReconcilePass {
			Expect(err).ToNot(HaveOccurred())
		} else {
			Expect(err).To(HaveOccurred())
		}

		if nameAttrEmpty {
			err = cli.Get(ctx, client.ObjectKey{Name: auth.GetName()}, auth)
			Expect(auth.Spec.LDAP.UserSearch.NameAttribute).To(Equal(authentication.DefaultNameAttribute))
		}
	},
		Entry("Proper configuration",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}}},
			[]byte(validDN), []byte(validPW), []byte(validCA),
			true),
		Entry("Proper configuration w/o name attribute",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}}},
			[]byte(validDN), []byte(validPW), []byte(validCA),
			true),
		Entry("Proper configuration w/o groupSearch",
			&operatorv1.AuthenticationLDAP{
				UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute}},
			[]byte(validDN), []byte(validPW), []byte(validCA),
			true),
		Entry("Wrong DN in secret",
			&operatorv1.AuthenticationLDAP{
				UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute}},
			[]byte(invalidDN), []byte(validPW), []byte(validCA),
			false),
		Entry("Missing PW in secret",
			&operatorv1.AuthenticationLDAP{
				UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute}},
			[]byte(validDN), []byte(""), []byte(validCA),
			false),
		Entry("Missing CA field in secret",
			&operatorv1.AuthenticationLDAP{
				UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute}},
			[]byte(validDN), []byte(validPW), []byte(""),
			false),
		Entry("Wrong DN in LDAP spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}}},
			[]byte(invalidDN), []byte(validPW), []byte(validCA),
			false),
		Entry("Wrong filter in LDAP userSearch spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: invalidFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}}},
			[]byte(validDN), []byte(validPW), []byte(validCA),
			false),
		Entry("Proper spec, filter omitted in userSearch spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: validFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}}},
			[]byte(validDN), []byte(validPW), []byte(validCA),
			true),
		Entry("Wrong filter in LDAP groupSearch spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, Filter: invalidFilter, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}}},
			[]byte(validDN), []byte(validPW), []byte(validCA),
			false),
		Entry("Proper spec, filter omitted in groupSearch spec",
			&operatorv1.AuthenticationLDAP{
				UserSearch:  &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute},
				GroupSearch: &operatorv1.GroupSearch{BaseDN: validDN, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}}},
			[]byte(validDN), []byte(validPW), []byte(validCA),
			true),
	)
})
