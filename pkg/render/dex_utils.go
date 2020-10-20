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

	corev1 "k8s.io/api/core/v1"

	oprv1 "github.com/tigera/operator/api/v1"
)

type DexConfig interface {
	// ManagerDomain returns the address where the Manager UI can be found. Ex: https://example.org
	ManagerDomain() string
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

	// AppendDexEnv adds env that is used to configure pods with dex options.
	AppendDexEnv(env []corev1.EnvVar, prefix string) []corev1.EnvVar
	// AppendDexVolume adds volumes that are related to dex.
	AppendDexVolume(volumes []corev1.Volume) []corev1.Volume
	//AppendDexVolumeMount adds volume mounts that are related to dex.
	AppendDexVolumeMount(mounts []corev1.VolumeMount) []corev1.VolumeMount
}

type DexOption func(*dexConfig) error

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

func WithTLSSecret(secret *corev1.Secret) DexOption {
	return func(d *dexConfig) error {
		if secret == nil {
			return fmt.Errorf("tlsSecret is missing")
		}
		d.tlsSecret = secret
		return nil
	}
}

func WithIdpSecret(secret *corev1.Secret) DexOption {
	return func(d *dexConfig) error {
		if secret == nil {
			return fmt.Errorf("idpSecret is missing")
		}
		d.idpSecret = secret
		return nil
	}
}

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
	if authentication.Spec.OIDC != nil {
		if authentication.Spec.OIDC.UsernamePrefix != "" && authentication.Spec.UsernamePrefix == "" {
			authentication.Spec.UsernamePrefix = authentication.Spec.OIDC.UsernamePrefix
		}
		if authentication.Spec.OIDC.GroupsPrefix != "" && authentication.Spec.GroupsPrefix == "" {
			authentication.Spec.GroupsPrefix = authentication.Spec.OIDC.GroupsPrefix
		}
	}

	dexConfig := &dexConfig{authentication: authentication}

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
}

func (d *dexConfig) ManagerDomain() string {
	return d.authentication.Spec.ManagerDomain
}

func (d *dexConfig) UsernamePrefix() string {
	return d.authentication.Spec.UsernamePrefix
}

func (d *dexConfig) GroupsPrefix() string {
	return d.authentication.Spec.GroupsPrefix
}

func (d *dexConfig) UsernameClaim() string {
	if d.authentication.Spec.OIDC != nil {
		return d.authentication.Spec.OIDC.UsernameClaim
	}
	return "email"
}

func (d *dexConfig) GroupsClaim() string {
	if d.authentication.Spec.OIDC != nil {
		return d.authentication.Spec.OIDC.GroupsClaim
	}
	return "groups"
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
func (d *dexConfig) AppendDexEnv(env []corev1.EnvVar, prefix string) []corev1.EnvVar {
	return append(env,
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_ENABLED", prefix), Value: strconv.FormatBool(true)},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_ISSUER", prefix), Value: fmt.Sprintf("%s/dex", d.ManagerDomain())},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_URL", prefix), Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/"},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_JWKS_URL", prefix), Value: DexJWKSURI},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_CLIENT_ID", prefix), Value: DexClientId},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_USERNAME_CLAIM", prefix), Value: d.UsernameClaim()},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_GROUPS_CLAIM", prefix), Value: d.GroupsClaim()},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_USERNAME_PREFIX", prefix), Value: d.UsernamePrefix()},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_GROUPS_PREFIX", prefix), Value: d.GroupsPrefix()})
}

// Add volume for Dex TLS secret.
func (d *dexConfig) AppendDexVolume(volumes []corev1.Volume) []corev1.Volume {
	return append(volumes, corev1.Volume{

		Name: DexTLSSecretName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: DexTLSSecretName,
				Items: []corev1.KeyToPath{
					{Key: "tls.crt", Path: "tls-dex.crt"},
				},
			},
		},
	})
}

// Add mount for ubi base image trusted cert location
func (d *dexConfig) AppendDexVolumeMount(mounts []corev1.VolumeMount) []corev1.VolumeMount {
	return append(mounts, corev1.VolumeMount{Name: DexTLSSecretName, MountPath: "/etc/ssl/certs"})
}
