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
)

type DexConfig interface {
	// BaseURL returns the address where the Manager UI can be found. Ex: https://example.org
	BaseURL() string
	// UsernamePrefix returns the string to prepend to every username for RBAC.
	UsernamePrefix() string
	// GroupsPrefix returns the string to prepend to every group for RBAC.
	GroupsPrefix() string
	// UsernameClaim returns the part of the JWT that represents a unique username.
	UsernameClaim() string
	// GroupsClaim returns the part of the JWT that represents the list of user groups.
	GroupsClaim() string
	// ClientSecret returns the secret for Dex' auth endpoint
	ClientSecret() []byte
	TLSSecret() *corev1.Secret
	IdpSecret() *corev1.Secret
	DexSecret() *corev1.Secret
	GoogleServiceAccountSecret() []byte
	OpenshiftRootCA() []byte

	// DexEnv returns env that is used to configure pods with dex options.
	DexEnv(prefix string) []corev1.EnvVar
	// DexVolumes returns volumes that are related to dex.
	DexVolumes() []corev1.Volume
	//DexVolumeMounts returns volume mounts that are related to dex.
	DexVolumeMounts() []corev1.VolumeMount

	ConnectorType() string
	IssuerURL() string
	RequestedScopes() []string
}

// DexOption can be passed during the creation of a DexConfig.
type DexOption func(*dexConfig) error

// WithDexSecret creates a DexConfig for consumers that need the client secret of Dex. It can use an existing secret
// or generate a new one.
func WithDexSecret(secret *corev1.Secret, createIfMissing bool) DexOption {
	return func(d *dexConfig) error {
		if secret == nil {
			if createIfMissing {
				secret = CreateDexClientSecret()
			} else {
				return fmt.Errorf("dexSecret is missing")
			}
		}
		d.dexSecret = secret
		return nil
	}
}

// WithDexSecret creates a DexConfig for consumers that need to create a secure tls connection with Dex. It can use an
// existing secret or generate a new one.
func WithTLSSecret(secret *corev1.Secret, createIfMissing bool) DexOption {
	return func(d *dexConfig) error {
		if secret == nil {
			if createIfMissing {
				secret = CreateDexTLSSecret()
			} else {
				return fmt.Errorf("tlsSecret is missing")
			}
		}
		d.tlsSecret = secret
		return nil
	}
}

// WithIdpSecret creates a DexConfig and pass in the config of the upstream IdP, such that Dex can connect to it.
func WithIdpSecret(secret *corev1.Secret) DexOption {
	return func(d *dexConfig) error {
		if secret == nil {
			return fmt.Errorf("idpSecret is missing")
		}
		d.idpSecret = secret
		return nil
	}
}

// Create a new DexConfig.
func NewDexConfig(
	authentication *oprv1.Authentication,
	options []DexOption) (DexConfig, error) {

	if authentication == nil {
		return nil, fmt.Errorf("authentication is missing")
	}
	if authentication.Spec.OIDC != nil && authentication.Spec.Openshift != nil {
		return nil, fmt.Errorf("multiple IdP connectors were specified, but only 1 is allowed in the Authentication spec")
	} else if authentication.Spec.OIDC == nil && authentication.Spec.Openshift == nil {
		return nil, fmt.Errorf("no IdP connector was specified, please add a connector to the Authentication spec")
	}

	// Backwards compatibility settings.
	userPrefix := authentication.Spec.UsernamePrefix
	groupsPrefix := authentication.Spec.GroupsPrefix

	if authentication.Spec.OIDC != nil {
		if authentication.Spec.OIDC.UsernamePrefix != "" && userPrefix == "" {
			userPrefix = authentication.Spec.OIDC.UsernamePrefix
		}
		if authentication.Spec.OIDC.GroupsPrefix != "" && groupsPrefix == "" {
			groupsPrefix = authentication.Spec.OIDC.GroupsPrefix
		}
	}

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

	dexConfig := &dexConfig{
		authentication: authentication,
		connectorType:  connType,
		issuer:         issuer,
		baseUrl:        baseUrl,
		usernamePrefix: userPrefix,
		groupsPrefix:   groupsPrefix,
	}

	for _, option := range options {
		if err := option(dexConfig); err != nil {
			return nil, err
		}
	}

	return dexConfig, nil
}

type dexConfig struct {
	authentication *oprv1.Authentication
	tlsSecret      *corev1.Secret
	idpSecret      *corev1.Secret
	dexSecret      *corev1.Secret
	baseUrl        string
	issuer         string
	connectorType  connectorType
	usernamePrefix string
	groupsPrefix   string
}

func (d *dexConfig) BaseURL() string {
	return d.baseUrl
}

func (d *dexConfig) UsernamePrefix() string {
	return d.usernamePrefix
}

func (d *dexConfig) GroupsPrefix() string {
	return d.groupsPrefix
}

func (d *dexConfig) UsernameClaim() string {
	claim := "email"
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.UsernameClaim != "" {
		claim = d.authentication.Spec.OIDC.UsernameClaim
	}
	return claim
}

func (d *dexConfig) GroupsClaim() string {
	claim := "groups"
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.GroupsClaim != "" {
		claim = d.authentication.Spec.OIDC.GroupsClaim
	}
	return claim
}

func (d *dexConfig) ClientSecret() []byte {
	return d.dexSecret.Data[ClientSecretSecretField]
}

func (d *dexConfig) TLSSecret() *corev1.Secret {
	return d.tlsSecret
}

func (d *dexConfig) IdpSecret() *corev1.Secret {
	return d.idpSecret
}

func (d *dexConfig) DexSecret() *corev1.Secret {
	return d.dexSecret
}

func (d *dexConfig) GoogleServiceAccountSecret() []byte {
	if d.idpSecret == nil {
		return nil
	}
	return d.idpSecret.Data[ServiceAccountSecretField]
}

func (d *dexConfig) OpenshiftRootCA() []byte {
	if d.idpSecret == nil {
		return nil
	}
	return d.idpSecret.Data[RootCASecretField]
}

// Append variables that are necessary for using the dex authenticator.
func (d *dexConfig) DexEnv(prefix string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: fmt.Sprintf("%sDEX_ENABLED", prefix), Value: strconv.FormatBool(true)},
		{Name: fmt.Sprintf("%sDEX_ISSUER", prefix), Value: fmt.Sprintf("%s/dex", d.BaseURL())},
		{Name: fmt.Sprintf("%sDEX_URL", prefix), Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/"},
		{Name: fmt.Sprintf("%sDEX_JWKS_URL", prefix), Value: DexJWKSURI},
		{Name: fmt.Sprintf("%sDEX_CLIENT_ID", prefix), Value: DexClientId},
		{Name: fmt.Sprintf("%sDEX_USERNAME_CLAIM", prefix), Value: d.UsernameClaim()},
		{Name: fmt.Sprintf("%sDEX_GROUPS_CLAIM", prefix), Value: d.GroupsClaim()},
		{Name: fmt.Sprintf("%sDEX_USERNAME_PREFIX", prefix), Value: d.UsernamePrefix()},
		{Name: fmt.Sprintf("%sDEX_GROUPS_PREFIX", prefix), Value: d.GroupsPrefix()},
	}
}

// Add volume for Dex TLS secret.
func (d *dexConfig) DexVolumes() []corev1.Volume {
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
func (d *dexConfig) DexVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{{Name: DexTLSSecretName, MountPath: "/etc/ssl/certs"}}
}

// connectorType returns the type of connector that is configured.
func (d *dexConfig) ConnectorType() string {
	return string(d.connectorType)
}

// Issuer URL of the connector
func (d *dexConfig) IssuerURL() string {
	if d.connectorType == connectorTypeOIDC {
		return d.authentication.Spec.OIDC.IssuerURL
	}
	if d.connectorType == connectorTypeOpenshift {
		return d.authentication.Spec.Openshift.IssuerURL
	}
	return ""
}

func (d *dexConfig) RequestedScopes() []string {
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.RequestedScopes != nil {
		return d.authentication.Spec.OIDC.RequestedScopes
	}
	return []string{"openid", "email", "profile", "groups", "offline_access"}
}
