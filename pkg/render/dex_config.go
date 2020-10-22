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
//
package render

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	oprv1 "github.com/tigera/operator/api/v1"
)

type connectorType string

const (
	connectorTypeOIDC      = "oidc"
	connectorTypeOpenshift = "openshift"
	connectorTypeGoogle    = "google"

	// Various annotations to keep the pod up-to-date
	authenticationAnnotation = "hash.operator.tigera.io/tigera-dex-auth"
	dexIdpSecretAnnotation   = "hash.operator.tigera.io/tigera-idp-secret"
	dexSecretAnnotation      = "hash.operator.tigera.io/tigera-dex-secret"
	dexTLSSecretAnnotation   = "hash.operator.tigera.io/tigera-dex-tls-secret"

	// Constants related to secrets.
	serviceAccountSecretField = "serviceAccountSecret"
	ClientSecretSecretField   = "clientSecret"
	adminEmailSecretField     = "adminEmail"
	RootCASecretField         = "rootCA"
)

// DexConfig is a config for DexIdP itself.
type DexConfig interface {
	// UsernameClaim returns the part of the JWT that represents a unique username.
	UsernameClaim() string
	// GroupsClaim returns the part of the JWT that represents the list of user groups.
	GroupsClaim() string
	// The issuer URL of the upstream IdP
	IssuerURL() string
	ConnectorType() string
	DexKeyValidatorConfig
}

// DexKeyValidatorConfig is a config for (backend) servers that validate JWTs issued by Dex.
type DexKeyValidatorConfig interface {
	// RequiredEnv returns env that is used to configure pods with dex options.
	RequiredEnv(prefix string) []corev1.EnvVar
	// RequiredVolumes returns volumes that are related to dex.
	RequiredVolumes() []corev1.Volume
	// RequiredVolumeMounts returns volume mounts that are related to dex.
	RequiredVolumeMounts() []corev1.VolumeMount
	baseConfig
}

// DexRelyingPartyConfig is a config for relying parties / applications that use Dex as their IdP.
type DexRelyingPartyConfig interface {
	// ClientSecret returns the secret for Dex' auth endpoint
	ClientSecret() []byte
	// ManagerURI returns the address where the Manager UI can be found. Ex: https://example.org
	RequestedScopes() []string
	// UsernameClaim returns the part of the JWT that represents a unique username.
	UsernameClaim() string
	// GroupsClaim returns the part of the JWT that represents the list of user groups.
	GroupsClaim() string
	baseConfig
}

type baseConfig interface {
	// ManagerURI returns the address where the Manager UI can be found. Ex: https://example.org
	ManagerURI() string
	// RequiredAnnotations returns annotations that make your the pods get refreshed if any of the config/secrets change.
	RequiredAnnotations() map[string]string
	// RequiredSecrets returns secrets that you need to render for dex.
	RequiredSecrets(namespace string) []*corev1.Secret
}

func NewDexRelyingPartyConfig(
	authentication *oprv1.Authentication,
	tlsSecret *corev1.Secret,
	dexSecret *corev1.Secret) DexRelyingPartyConfig {
	return &dexRelyingPartyConfig{baseCfg(authentication, tlsSecret, dexSecret, nil)}
}

func NewDexKeyValidatorConfig(
	authentication *oprv1.Authentication,
	tlsSecret *corev1.Secret) DexKeyValidatorConfig {
	return &dexKeyValidatorConfig{baseCfg(authentication, tlsSecret, nil, nil)}
}

// Create a new DexConfig.
func NewDexConfig(
	authentication *oprv1.Authentication,
	tlsSecret *corev1.Secret,
	dexSecret *corev1.Secret,
	idpSecret *corev1.Secret) DexConfig {
	return &dexConfig{baseCfg(authentication, tlsSecret, dexSecret, idpSecret)}
}

type dexKeyValidatorConfig struct {
	*dexBaseCfg
}

type dexConfig struct {
	*dexBaseCfg
}

type dexRelyingPartyConfig struct {
	*dexBaseCfg
}

// Create a struct to hold the base configuration of dex.
func baseCfg(
	authentication *oprv1.Authentication,
	tlsSecret *corev1.Secret,
	dexSecret *corev1.Secret,
	idpSecret *corev1.Secret) *dexBaseCfg {

	// If the manager domain is not a URL, prepend https://.
	baseUrl := authentication.Spec.ManagerDomain
	if !strings.HasPrefix(baseUrl, "http://") && !strings.HasPrefix(baseUrl, "https://") {
		baseUrl = fmt.Sprintf("https://%s", baseUrl)
	}

	var connType connectorType
	var issuer string
	if authentication.Spec.OIDC != nil {
		issuer = authentication.Spec.OIDC.IssuerURL
		if issuer == "https://accounts.google.com" {
			connType = connectorTypeGoogle
		} else {
			connType = connectorTypeOIDC
		}
	} else if authentication.Spec.Openshift != nil {
		issuer = authentication.Spec.Openshift.IssuerURL
		connType = connectorTypeOpenshift
	}

	return &dexBaseCfg{
		authentication: authentication,
		tlsSecret:      tlsSecret,
		idpSecret:      idpSecret,
		dexSecret:      dexSecret,
		connectorType:  connType,
		issuer:         issuer,
		managerURI:     baseUrl,
	}
}

type dexBaseCfg struct {
	authentication *oprv1.Authentication
	tlsSecret      *corev1.Secret
	idpSecret      *corev1.Secret
	dexSecret      *corev1.Secret
	managerURI     string
	issuer         string
	connectorType  connectorType
}

func (d *dexBaseCfg) ManagerURI() string {
	return d.managerURI
}

func (d *dexBaseCfg) UsernameClaim() string {
	claim := "email"
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.UsernameClaim != "" {
		claim = d.authentication.Spec.OIDC.UsernameClaim
	}
	return claim
}

func (d *dexBaseCfg) GroupsClaim() string {
	claim := "groups"
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.GroupsClaim != "" {
		claim = d.authentication.Spec.OIDC.GroupsClaim
	}
	return claim
}

func (d *dexBaseCfg) ClientSecret() []byte {
	return d.dexSecret.Data[ClientSecretSecretField]
}

// connectorType returns the type of connector that is configured.
func (d *dexBaseCfg) ConnectorType() string {
	return string(d.connectorType)
}

// Issuer URL of the connector
func (d *dexBaseCfg) IssuerURL() string {
	if d.connectorType == connectorTypeOIDC {
		return d.authentication.Spec.OIDC.IssuerURL
	}
	if d.connectorType == connectorTypeOpenshift {
		return d.authentication.Spec.Openshift.IssuerURL
	}
	return ""
}

func (d *dexBaseCfg) RequestedScopes() []string {
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.RequestedScopes != nil {
		return d.authentication.Spec.OIDC.RequestedScopes
	}
	return []string{"openid", "email", "profile", "groups", "offline_access"}
}

func (d *dexBaseCfg) RequiredSecrets(namespace string) []*corev1.Secret {
	secrets := []*corev1.Secret{
		CopySecrets(namespace, d.tlsSecret)[0],
	}
	if d.dexSecret != nil {
		secrets = append(secrets, CopySecrets(namespace, d.dexSecret)...)
	}
	if d.idpSecret != nil {
		secrets = append(secrets, CopySecrets(namespace, d.idpSecret)...)
	}
	return secrets
}

func (d *dexBaseCfg) RequiredAnnotations() map[string]string {
	var annotations = map[string]string{
		dexTLSSecretAnnotation:   AnnotationHash(d.tlsSecret.Data),
		authenticationAnnotation: AnnotationHash(d.authentication.Spec),
	}
	if d.idpSecret != nil {
		annotations[dexIdpSecretAnnotation] = AnnotationHash(d.idpSecret.Data)
	}
	if d.dexSecret != nil {
		annotations[dexSecretAnnotation] = AnnotationHash(d.dexSecret.Data)
	}
	return annotations
}

// Append variables that are necessary for using the dex authenticator.
func (d *dexKeyValidatorConfig) RequiredEnv(prefix string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: fmt.Sprintf("%sDEX_ENABLED", prefix), Value: strconv.FormatBool(true)},
		{Name: fmt.Sprintf("%sDEX_ISSUER", prefix), Value: fmt.Sprintf("%s/dex", d.ManagerURI())},
		{Name: fmt.Sprintf("%sDEX_URL", prefix), Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/"},
		{Name: fmt.Sprintf("%sDEX_JWKS_URL", prefix), Value: DexJWKSURI},
		{Name: fmt.Sprintf("%sDEX_CLIENT_ID", prefix), Value: DexClientId},
		{Name: fmt.Sprintf("%sDEX_USERNAME_CLAIM", prefix), Value: d.UsernameClaim()},
		{Name: fmt.Sprintf("%sDEX_GROUPS_CLAIM", prefix), Value: d.GroupsClaim()},
		{Name: fmt.Sprintf("%sDEX_USERNAME_PREFIX", prefix), Value: d.authentication.Spec.UsernamePrefix},
		{Name: fmt.Sprintf("%sDEX_GROUPS_PREFIX", prefix), Value: d.authentication.Spec.GroupsPrefix},
	}
}

// Append variables that are necessary for configuring dex.
func (d *dexConfig) RequiredEnv(string) []corev1.EnvVar {
	env := []corev1.EnvVar{
		{Name: ClientIDEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientIDSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}},
		{Name: ClientSecretEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}},
		{Name: DexSecretEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.dexSecret.Name}}}},
	}
	if d.idpSecret != nil && d.idpSecret.Data[adminEmailSecretField] != nil {
		env = append(env, corev1.EnvVar{Name: GoogleAdminEmailEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: adminEmailSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}})
	}
	return env
}

func (d *dexConfig) RequiredVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name:         "config",
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: DexObjectName}, Items: []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}}}},
		},
		{
			Name:         "tls",
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: DexTLSSecretName}},
		},
	}

	if d.idpSecret != nil && d.idpSecret.Data[serviceAccountSecretField] != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name:         "secrets",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: d.idpSecret.Name, Items: []corev1.KeyToPath{{Key: serviceAccountSecretField, Path: "google-groups.json"}}}},
			},
		)
	}

	if d.idpSecret != nil && d.idpSecret.Data[RootCASecretField] != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name:         "secrets",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: d.idpSecret.Name, Items: []corev1.KeyToPath{{Key: RootCASecretField, Path: "openshift.pem"}}}},
			},
		)
	}
	return volumes
}

// Add volume for Dex TLS secret.
func (d *dexKeyValidatorConfig) RequiredVolumes() []corev1.Volume {
	return []corev1.Volume{
		{
			Name: DexTLSSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: DexTLSSecretName,
					Items: []corev1.KeyToPath{
						{Key: "tls.crt", Path: "tls-dex.crt"},
					},
				},
			},
		},
	}
}

// AppendDexVolumeMount adds mount for ubi base image trusted cert location
func (d *dexKeyValidatorConfig) RequiredVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{{Name: DexTLSSecretName, MountPath: "/etc/ssl/certs"}}
}

// AppendDexVolumeMount adds mount for ubi base image trusted cert location
func (d *dexConfig) RequiredVolumeMounts() []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "config",
			MountPath: "/etc/dex/baseCfg",
			ReadOnly:  true,
		},
		{
			Name:      "tls",
			MountPath: "/etc/dex/tls",
			ReadOnly:  true,
		},
	}
	if d.idpSecret.Data[serviceAccountSecretField] != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "secrets",
			MountPath: "/etc/dex/secrets",
			ReadOnly:  true,
		})
	}
	if d.idpSecret.Data[RootCASecretField] != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "secrets",
			MountPath: "/etc/ssl/",
			ReadOnly:  true,
		})
	}
	return volumeMounts
}
