// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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

package authentication

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
		readyFlag  *utils.ReadyFlag
		idpSecret  *corev1.Secret
		auth       *operatorv1.Authentication
		replicas   int32
	)

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("SetMetaData", mock.Anything).Return()

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
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.TigeraSecureEnterprise,
				Registry:             "some.registry.org/",
			},
		})).To(BeNil())
		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
		})).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-dex"}})).ToNot(HaveOccurred())
		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()

		// Establish base specifications for context-sensitive resources to create.
		idpSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.OIDCSecretName,
				Namespace: common.OperatorNamespace(),
			},
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			Data: map[string][]byte{
				"clientID":     []byte("a.b.com"),
				"clientSecret": []byte("my-secret"),
			}}
		auth = &operatorv1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://example.com",
			},
		}

		replicas = 2
	})

	Context("Reconcile for Condition status", func() {
		BeforeEach(func() {
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
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
		})
		generation := int64(2)
		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "authentication"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())
			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", readyFlag, true}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "authentication",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetAuthentication(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(1))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
		})
		It("should reconcile with empty tigerastatus conditions ", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "authentication"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}

			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())

			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", readyFlag, true}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "authentication",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetAuthentication(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(0))
		})
		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "authentication"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentProgressing,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.ResourceNotReady),
							Message:            "Progressing Installation.operatorv1.tigera.io",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.ResourceUpdateError),
							Message:            "Error resolving ImageSet for components",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())
			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", readyFlag, true}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "authentication",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetAuthentication(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))

			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.ResourceNotReady)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Progressing Installation.operatorv1.tigera.io"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.ResourceUpdateError)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
		})
		It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "authentication"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentProgressing,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())
			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", readyFlag, true}
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "authentication",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetAuthentication(ctx, r.client)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))

			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
		})
	})

	Context("OIDC connector config options", func() {
		It("should set oidc defaults ", func() {
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
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
			r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", readyFlag, true}
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

	Context("image reconciliation", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
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
		})

		It("should use builtin images", func() {

			r := ReconcileAuthentication{
				client:         cli,
				scheme:         scheme,
				provider:       operatorv1.ProviderNone,
				status:         mockStatus,
				tierWatchReady: readyFlag,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.DexObjectName,
					Namespace: render.DexNamespace,
				},
			}
			Expect(test.GetResource(cli, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			dexC := test.GetContainer(d.Spec.Template.Spec.Containers, render.DexObjectName)
			Expect(dexC).ToNot(BeNil())
			Expect(dexC.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentDex.Image,
					components.ComponentDex.Version)))
		})
		It("should use images from imageset", func() {
			Expect(cli.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/dex", Digest: "sha256:dexhash"},
					},
				},
			})).ToNot(HaveOccurred())

			r := ReconcileAuthentication{
				client:         cli,
				scheme:         scheme,
				provider:       operatorv1.ProviderNone,
				status:         mockStatus,
				tierWatchReady: readyFlag,
			}
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.DexObjectName,
					Namespace: render.DexNamespace,
				},
			}
			Expect(test.GetResource(cli, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			apiserver := test.GetContainer(d.Spec.Template.Spec.Containers, render.DexObjectName)
			Expect(apiserver).ToNot(BeNil())
			Expect(apiserver.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentDex.Image,
					"sha256:dexhash")))
		})
	})

	Context("allow-tigera reconciliation", func() {
		var r *ReconcileAuthentication
		BeforeEach(func() {
			Expect(cli.Create(ctx, idpSecret)).ToNot(HaveOccurred())
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

			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			r = &ReconcileAuthentication{
				client:         cli,
				scheme:         scheme,
				provider:       operatorv1.ProviderNone,
				status:         mockStatus,
				tierWatchReady: readyFlag,
			}
		})

		It("should wait if allow-tigera tier is unavailable", func() {
			mockStatus.On("SetMetaData", mock.Anything).Return()
			utils.DeleteAllowTigeraTierAndExpectWait(ctx, cli, r, mockStatus)
		})

		It("should wait if tier watch is not ready", func() {
			mockStatus.On("SetMetaData", mock.Anything).Return()
			r.tierWatchReady = &utils.ReadyFlag{}
			utils.ExpectWaitForTierWatch(ctx, r, mockStatus)
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
		Expect(cli.Create(ctx, auth)).ToNot(HaveOccurred())
		r := &ReconcileAuthentication{cli, scheme, operatorv1.ProviderNone, mockStatus, "", readyFlag, true}
		_, err := r.Reconcile(ctx, reconcile.Request{})
		if expectReconcilePass {
			Expect(err).ToNot(HaveOccurred())
		} else {
			Expect(err).To(HaveOccurred())
		}

		if nameAttrEmpty {
			err = cli.Get(ctx, client.ObjectKey{Name: auth.GetName()}, auth)
			Expect(err).ToNot(HaveOccurred())
			Expect(auth.Spec.LDAP.UserSearch.NameAttribute).To(Equal(defaultNameAttribute))
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
	var (
		iss  = "https://issuer.com"
		ocp  = &operatorv1.AuthenticationOpenshift{IssuerURL: iss}
		ldap = &operatorv1.AuthenticationLDAP{UserSearch: &operatorv1.UserSearch{BaseDN: validDN}}
		oidc = &operatorv1.AuthenticationOIDC{IssuerURL: iss, UsernameClaim: "email"}
	)
	DescribeTable("should validate the authentication spec", func(auth *operatorv1.Authentication, expectPass bool) {
		if expectPass {
			Expect(validateAuthentication(auth)).NotTo(HaveOccurred())
		} else {
			Expect(validateAuthentication(auth)).To(HaveOccurred())
		}
	},
		Entry("Expect single Openshift config to pass validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{Openshift: ocp}}, true),
		Entry("Expect single LDAP config to pass validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{LDAP: ldap}}, true),
		Entry("Expect single OIDC config to pass validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: oidc}}, true),
		Entry("Expect 0 configs to fail validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{}}, false),
		Entry("Expect two configs to fail validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: oidc, LDAP: ldap}}, false),
		Entry("Expect three configs to fail validation", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: oidc, LDAP: ldap, Openshift: ocp}}, false),
		Entry("Expect prompt type to be used without other values", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: copyAndAddPromptTypes(oidc, []operatorv1.PromptType{operatorv1.PromptTypeNone})}}, true),
		Entry("Expect prompt type to fail when none is combined", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: copyAndAddPromptTypes(oidc, []operatorv1.PromptType{operatorv1.PromptTypeNone, operatorv1.PromptTypeLogin})}}, false),
		Entry("Expect prompt type to be able to be combined", &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{OIDC: copyAndAddPromptTypes(oidc, []operatorv1.PromptType{operatorv1.PromptTypeSelectAccount, operatorv1.PromptTypeLogin})}}, true),
	)
})

func copyAndAddPromptTypes(auth *operatorv1.AuthenticationOIDC, promptTypes []operatorv1.PromptType) *operatorv1.AuthenticationOIDC {
	copy := auth.DeepCopy()
	copy.PromptTypes = promptTypes
	return copy
}
