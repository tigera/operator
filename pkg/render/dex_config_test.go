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

package render_test

import (
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("dex config tests", func() {
	verify := operatorv1.EmailVerificationTypeSkip
	email := "a@b.com"

	// Create two different authentication objects
	authentication := &operatorv1.Authentication{
		Spec: operatorv1.AuthenticationSpec{
			ManagerDomain: "https://example.com",
			OIDC: &operatorv1.AuthenticationOIDC{
				IssuerURL:         "https://example.com",
				UsernameClaim:     "email",
				GroupsClaim:       "group",
				RequestedScopes:   []string{"scope"},
				EmailVerification: &verify,
			},
		},
	}
	authenticationDiff := &operatorv1.Authentication{
		Spec: operatorv1.AuthenticationSpec{
			ManagerDomain: "https://example.org",
			OIDC: &operatorv1.AuthenticationOIDC{
				IssuerURL:     "https://example.org",
				UsernameClaim: "email",
			},
		},
	}
	// Create the necessary secrets.
	idpSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.OIDCSecretName,
			Namespace: rmeta.OperatorNamespace(),
		},
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		Data: map[string][]byte{
			"adminEmail":           []byte(email),
			"clientID":             []byte("a.b.com"),
			"clientSecret":         []byte("my-secret"),
			"serviceAccountSecret": []byte("my-secret2"),
		},
	}
	dexSecret := render.CreateDexClientSecret()
	tlsSecret := render.CreateDexTLSSecret("tigera-dex.tigera-dex.svc.cluster.local")

	Context("OIDC connector config options", func() {
		It("should configure insecureSkipEmailVerified ", func() {
			connector := render.NewDexConfig(authentication, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).Connector()
			cfg := connector["config"].(map[string]interface{})
			Expect(cfg["insecureSkipEmailVerified"]).To(Equal(true))
		})
	})

	Context("Hashes should be consistent and not be affected by fields with pointers", func() {
		It("should produce consistent hashes for dex config", func() {
			hashes1 := render.NewDexConfig(authentication, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := render.NewDexConfig(authentication.DeepCopy(), tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := render.NewDexConfig(authenticationDiff, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(4))
			Expect(hashes2).To(HaveLen(4))
			Expect(hashes3).To(HaveLen(4))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})

		It("should produce consistent hashes for rp's", func() {
			hashes1 := render.NewDexRelyingPartyConfig(authentication, tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := render.NewDexRelyingPartyConfig(authentication.DeepCopy(), tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := render.NewDexRelyingPartyConfig(authenticationDiff, tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(3))
			Expect(hashes2).To(HaveLen(3))
			Expect(hashes3).To(HaveLen(3))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})

		It("should produce consistent hashes for verifiers", func() {
			hashes1 := render.NewDexKeyValidatorConfig(authentication, tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes2 := render.NewDexKeyValidatorConfig(authentication.DeepCopy(), tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			hashes3 := render.NewDexKeyValidatorConfig(authenticationDiff, tlsSecret, idpSecret, dns.DefaultClusterDomain).RequiredAnnotations()
			Expect(hashes1).To(HaveLen(2))
			Expect(hashes2).To(HaveLen(2))
			Expect(hashes3).To(HaveLen(2))
			Expect(reflect.DeepEqual(hashes1, hashes2)).To(BeTrue())
			Expect(reflect.DeepEqual(hashes1, hashes3)).To(BeFalse())
		})
	})

	var (
		domain      = "https://example.com"
		iss         = "https://issuer.com"
		defaultMode = int32(420)
		validDN     = "dc=example,dc=com"
		validFilter = "(objectClass=posixGroup)"
		attribute   = "uid"
		oidc        = &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{ManagerDomain: domain, OIDC: &operatorv1.AuthenticationOIDC{IssuerURL: iss, UsernameClaim: "email", GroupsClaim: "group"}}}
		google      = &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{ManagerDomain: domain, OIDC: &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"}}}
		ocp         = &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{ManagerDomain: domain, Openshift: &operatorv1.AuthenticationOpenshift{IssuerURL: iss}}}
		ldap        = &operatorv1.Authentication{Spec: operatorv1.AuthenticationSpec{ManagerDomain: domain, LDAP: &operatorv1.AuthenticationLDAP{Host: iss, UserSearch: &operatorv1.UserSearch{BaseDN: validDN, Filter: validFilter, NameAttribute: attribute}, GroupSearch: &operatorv1.GroupSearch{NameAttribute: attribute, Filter: validFilter, BaseDN: validDN, UserMatchers: []operatorv1.UserMatch{{UserAttribute: attribute, GroupAttribute: attribute}}}}}}
		ldapSecret  = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.LDAPSecretName, Namespace: rmeta.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			Data: map[string][]byte{"bindDN": []byte(validDN), "bindPW": []byte("my-secret"), "rootCA": []byte("ca")}}
		ocpSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.OpenshiftSecretName, Namespace: rmeta.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			Data: map[string][]byte{"clientID": []byte(validDN), "clientSecret": []byte("my-secret"), "rootCA": []byte("ca")}}
	)

	DescribeTable("Test DexConfig methods for various connectors ", func(auth *operatorv1.Authentication, expectedConnector map[string]interface{}, expectedVolumes []corev1.Volume, expectedEnv []corev1.EnvVar, secret *corev1.Secret) {
		dexConfig := render.NewDexConfig(auth, tlsSecret, dexSecret, secret, dns.DefaultClusterDomain)
		Expect(dexConfig.Connector()).To(BeEquivalentTo(expectedConnector))
		annotations := dexConfig.RequiredAnnotations()
		Expect(annotations["hash.operator.tigera.io/tigera-dex-config"]).NotTo(BeEmpty())
		Expect(annotations["hash.operator.tigera.io/tigera-idp-secret"]).NotTo(BeEmpty())
		Expect(annotations["hash.operator.tigera.io/tigera-dex-secret"]).NotTo(BeEmpty())
		Expect(annotations["hash.operator.tigera.io/tigera-dex-tls-secret"]).NotTo(BeEmpty())
		Expect(dexConfig.ManagerURI()).To(Equal(domain))

		Expect(dexConfig.RequiredVolumes()).To(ConsistOf(expectedVolumes))
		Expect(dexConfig.RequiredEnv("")).To(ConsistOf(expectedEnv))
		Expect(dexConfig.RequiredSecrets("tigera-operator")).To(ConsistOf(tlsSecret, dexSecret, secret))

	},
		Entry("Compare actual and expected OIDC config",
			oidc, map[string]interface{}{
				"id":   "oidc",
				"type": "oidc",
				"name": "oidc",
				"config": map[string]interface{}{
					"issuer":                    iss,
					"clientID":                  "$CLIENT_ID",
					"clientSecret":              "$CLIENT_SECRET",
					"redirectURI":               "https://example.com/dex/callback",
					"scopes":                    []string{"openid", "email", "profile"},
					"userNameKey":               "email",
					"userIDKey":                 "email",
					"claimMapping":              map[string]string{"groups": "group"},
					"insecureSkipEmailVerified": false,
					"insecureEnableGroups":      true,
				},
			}, []corev1.Volume{
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: render.DexObjectName}, Items: []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}}}},
				},
				{
					Name:         "tls",
					VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: render.DexTLSSecretName}},
				},
				{
					Name:         "secrets",
					VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: idpSecret.Name, Items: []corev1.KeyToPath{{Key: "serviceAccountSecret", Path: "google-groups.json"}}}},
				},
			}, []corev1.EnvVar{
				{Name: "DEX_SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: dexSecret.Name}}}},
				{Name: "CLIENT_ID", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.ClientIDSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: idpSecret.Name}}}},
				{Name: "CLIENT_SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: idpSecret.Name}}}},
				{Name: "ADMIN_EMAIL", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "adminEmail", LocalObjectReference: corev1.LocalObjectReference{Name: idpSecret.Name}}}},
			},
			idpSecret,
		),
		Entry("Compare actual and expected LDAP config",
			ldap, map[string]interface{}{
				"id":   "ldap",
				"type": "ldap",
				"name": "ldap",
				"config": map[string]interface{}{
					"bindDN":                 "$BIND_DN",
					"bindPW":                 "$BIND_PW",
					"host":                   iss,
					render.RootCASecretField: "/etc/ssl/certs/idp.pem",
					"startTLS":               false,
					"userSearch": map[string]string{
						"baseDN":    validDN,
						"filter":    validFilter,
						"emailAttr": attribute,
						"idAttr":    attribute,
						"username":  attribute,
						"nameAttr":  attribute,
					},
					"groupSearch": map[string]interface{}{
						"baseDN":   validDN,
						"filter":   validFilter,
						"nameAttr": attribute,
						"userMatchers": []map[string]string{{
							"userAttr":  attribute,
							"groupAttr": attribute,
						}},
					},
				},
			}, []corev1.Volume{
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: render.DexObjectName}, Items: []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}}}},
				},
				{
					Name:         "tls",
					VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: render.DexTLSSecretName}},
				},
				{
					Name:         "secrets",
					VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: ldapSecret.Name, Items: []corev1.KeyToPath{{Key: render.RootCASecretField, Path: "idp.pem"}}}},
				},
			}, []corev1.EnvVar{
				{Name: "DEX_SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: dexSecret.Name}}}},
				{Name: "BIND_DN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.BindDNSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: ldapSecret.Name}}}},
				{Name: "BIND_PW", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.BindPWSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: ldapSecret.Name}}}},
			},
			ldapSecret,
		),
		Entry("Compare actual and expected Openshift config",
			ocp, map[string]interface{}{
				"id":   "openshift",
				"type": "openshift",
				"name": "openshift",
				"config": map[string]interface{}{
					"issuer":                 iss,
					"clientID":               "$CLIENT_ID",
					"clientSecret":           "$CLIENT_SECRET",
					"redirectURI":            "https://example.com/dex/callback",
					render.RootCASecretField: "/etc/ssl/certs/idp.pem",
				},
			}, []corev1.Volume{
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: render.DexObjectName}, Items: []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}}}},
				},
				{
					Name:         "tls",
					VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: render.DexTLSSecretName}},
				},
				{
					Name:         "secrets",
					VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: ocpSecret.Name, Items: []corev1.KeyToPath{{Key: render.RootCASecretField, Path: "idp.pem"}}}},
				},
			}, []corev1.EnvVar{
				{Name: "DEX_SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: dexSecret.Name}}}},
				{Name: "CLIENT_ID", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.ClientIDSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: ocpSecret.Name}}}},
				{Name: "CLIENT_SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: render.ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: ocpSecret.Name}}}},
			},
			ocpSecret,
		),
	)

	DescribeTable("Test DexRPConfig methods for various connectors ", func(auth *operatorv1.Authentication) {
		dexConfig := render.NewDexRelyingPartyConfig(auth, tlsSecret, dexSecret, dns.DefaultClusterDomain)

		Expect(dexConfig.TokenURI()).To(Equal("https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/token"))
		Expect(dexConfig.UserInfoURI()).To(Equal("https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/userinfo"))
		Expect(dexConfig.JWKSURI()).To(Equal("https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys"))
		Expect(dexConfig.ClientSecret()).To(Equal(dexSecret.Data["clientSecret"]))
		Expect(dexConfig.UsernameClaim()).To(Equal("email"))

		annotations := dexConfig.RequiredAnnotations()
		Expect(annotations["hash.operator.tigera.io/tigera-dex-secret"]).NotTo(BeEmpty())
		Expect(annotations["hash.operator.tigera.io/tigera-dex-tls-secret"]).NotTo(BeEmpty())
		Expect(dexConfig.ManagerURI()).To(Equal(domain))

		Expect(dexConfig.RequiredVolumes()).To(ConsistOf(corev1.Volume{
			Name: render.DexTLSSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: render.DexTLSSecretName,
					Items: []corev1.KeyToPath{
						{Key: "tls.crt", Path: "tls-dex.crt"},
					},
				},
			}}))
		Expect(dexConfig.RequiredSecrets("tigera-operator")).To(ConsistOf(tlsSecret, dexSecret))
	},
		Entry("Compare actual and expected OIDC config", oidc),
		Entry("Compare actual and expected LDAP config", ldap),
		Entry("Compare actual and expected Openshift config", ocp),
	)

	DescribeTable("Test DexKVConfig methods for various connectors ", func(auth *operatorv1.Authentication) {
		dexConfig := render.NewDexKeyValidatorConfig(auth, tlsSecret, idpSecret, dns.DefaultClusterDomain)

		annotations := dexConfig.RequiredAnnotations()
		Expect(annotations["hash.operator.tigera.io/tigera-dex-tls-secret"]).NotTo(BeEmpty())
		Expect(dexConfig.ManagerURI()).To(Equal(domain))

		Expect(dexConfig.RequiredVolumes()).To(ConsistOf(corev1.Volume{
			Name: render.DexTLSSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: render.DexTLSSecretName,
					Items: []corev1.KeyToPath{
						{Key: "tls.crt", Path: "tls-dex.crt"},
					},
				},
			}}))
		Expect(dexConfig.RequiredSecrets("tigera-operator")).To(ConsistOf(tlsSecret))
	},
		Entry("Compare actual and expected OIDC config", oidc),
		Entry("Compare actual and expected LDAP config", ldap),
		Entry("Compare actual and expected Openshift config", ocp),
	)

	DescribeTable("Test dex connector for Google ", func(secretData map[string][]byte, expectPresent bool) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.OIDCSecretName,
				Namespace: rmeta.OperatorNamespace(),
			},
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			Data:     secretData,
		}
		dexConfig := render.NewDexConfig(google, tlsSecret, dexSecret, secret, dns.DefaultClusterDomain)
		connector := dexConfig.Connector()["config"].(map[string]interface{})

		email, emailFound := connector["adminEmail"]
		saPath, saFound := connector["serviceAccountFilePath"]
		if expectPresent {
			Expect(email).To(Equal(email))
			Expect(emailFound).To(BeTrue())
			Expect(saPath).To(Equal("/etc/dex/secrets/google-groups.json"))
			Expect(saFound).To(BeTrue())
		} else {
			Expect(emailFound).To(BeFalse())
			Expect(saFound).To(BeFalse())
		}
	},
		Entry("Compare actual and expected OIDC config", map[string][]byte{
			"adminEmail":           []byte(email),
			"clientID":             []byte("a.b.com"),
			"clientSecret":         []byte("my-secret"),
			"serviceAccountSecret": []byte("my-secret2"),
		}, true),
		Entry("Compare actual and expected OIDC config", map[string][]byte{
			"clientID":     []byte("a.b.com"),
			"clientSecret": []byte("my-secret"),
		}, false),
		Entry("Compare actual and expected OIDC config", map[string][]byte{
			"clientID":             []byte("a.b.com"),
			"clientSecret":         []byte("my-secret"),
			"serviceAccountSecret": []byte("my-secret2"),
		}, false),
		Entry("Compare actual and expected OIDC config", map[string][]byte{
			"adminEmail":   []byte(email),
			"clientID":     []byte("a.b.com"),
			"clientSecret": []byte("my-secret"),
		}, false))

	DescribeTable("Test values for promptTypes ", func(in []operatorv1.PromptType, result string) {
		auth := oidc.DeepCopy()
		auth.Spec.OIDC.PromptTypes = in
		dexConfig := render.NewDexConfig(auth, tlsSecret, dexSecret, idpSecret, dns.DefaultClusterDomain)
		config, ok := dexConfig.Connector()["config"].(map[string]interface{})
		Expect(ok).To(BeTrue())
		if result == "" {
			Expect(config["promptType"]).To(BeNil())
		} else {
			promptTypes, ok := config["promptType"].(string)
			Expect(ok).To(BeTrue())
			Expect(promptTypes).To(Equal(result))
		}
	},
		Entry("Compare actual and expected promptType", nil, ""),
		Entry("Compare actual and expected promptType", []operatorv1.PromptType{operatorv1.PromptTypeConsent}, "consent"),
		Entry("Compare actual and expected promptType", []operatorv1.PromptType{operatorv1.PromptTypeSelectAccount}, "select_account"),
		Entry("Compare actual and expected promptType", []operatorv1.PromptType{operatorv1.PromptTypeNone}, "none"),
		Entry("Compare actual and expected promptType", []operatorv1.PromptType{operatorv1.PromptTypeLogin}, "login"),
		Entry("Compare actual and expected promptType", []operatorv1.PromptType{operatorv1.PromptTypeConsent, operatorv1.PromptTypeSelectAccount}, "consent select_account"),
		Entry("Compare actual and expected promptType", []operatorv1.PromptType{operatorv1.PromptTypeConsent, operatorv1.PromptTypeSelectAccount, operatorv1.PromptTypeLogin}, "consent select_account login"),
	)
})
