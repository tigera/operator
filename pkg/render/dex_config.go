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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"strconv"
	"strings"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"golang.org/x/oauth2"

	oprv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Types of dex connectors.
	connectorTypeOIDC      = "oidc"
	connectorTypeOpenshift = "openshift"
	connectorTypeGoogle    = "google"
	connectorTypeLDAP      = "ldap"

	// Various annotations to keep the pod up-to-date
	authenticationAnnotation = "hash.operator.tigera.io/tigera-dex-auth"
	dexConfigMapAnnotation   = "hash.operator.tigera.io/tigera-dex-config"
	dexIdpSecretAnnotation   = "hash.operator.tigera.io/tigera-idp-secret"
	dexSecretAnnotation      = "hash.operator.tigera.io/tigera-dex-secret"
	dexTLSSecretAnnotation   = "hash.operator.tigera.io/tigera-dex-tls-secret"

	// Constants related to secrets.
	serviceAccountSecretField    = "serviceAccountSecret"
	ClientSecretSecretField      = "clientSecret"
	adminEmailSecretField        = "adminEmail"
	serviceAccountFilePathField  = "serviceAccountFilePath"
	RootCASecretField            = "rootCA"
	OIDCSecretName               = "tigera-oidc-credentials"
	OpenshiftSecretName          = "tigera-openshift-credentials"
	LDAPSecretName               = "tigera-ldap-credentials"
	serviceAccountSecretLocation = "/etc/dex/secrets/google-groups.json"
	rootCASecretLocation         = "/etc/ssl/certs/idp.pem"
	ClientIDSecretField          = "clientID"
	BindDNSecretField            = "bindDN"
	BindPWSecretField            = "bindPW"

	// OIDC well-known-config related constants.
	jwksURI     = "https://tigera-dex.tigera-dex.svc.%s:5556/dex/keys"
	tokenURI    = "https://tigera-dex.tigera-dex.svc.%s:5556/dex/token"
	userInfoURI = "https://tigera-dex.tigera-dex.svc.%s:5556/dex/userinfo"

	// Env related constants.
	googleAdminEmailEnv = "ADMIN_EMAIL"
	clientIDEnv         = "CLIENT_ID"
	clientSecretEnv     = "CLIENT_SECRET"
	dexSecretEnv        = "DEX_SECRET"
	bindDNEnv           = "BIND_DN"
	bindPWEnv           = "BIND_PW"

	// Default claims to use to data from a JWT.
	DefaultGroupsClaim   = "groups"
	defaultUsernameClaim = "email"

	// Other constants
	googleIssuer = "https://accounts.google.com"
)

// DexConfig is a config for DexIdP itself.
type DexConfig interface {
	Connector() map[string]interface{}
	DexKeyValidatorConfig
}

// DexKeyValidatorConfig is a config for (backend) servers that validate JWTs issued by Dex.
type DexKeyValidatorConfig interface {
	// ManagerURI returns the address where the Manager UI can be found. Ex: https://example.org
	ManagerURI() string
	// The issuer of the OIDC bearer tokens used during a UI session.
	Issuer() string
	ClientId() string
	RequiredConfigMaps(namespace string) []*corev1.ConfigMap
	// RequiredEnv returns env that is used to configure pods with dex options.
	RequiredEnv(prefix string) []corev1.EnvVar
	// RequiredAnnotations returns annotations that make your the pods get refreshed if any of the config/secrets change.
	RequiredAnnotations() map[string]string
	// RequiredSecrets returns secrets that you need to render for dex.
	RequiredSecrets(namespace string) []*corev1.Secret
	// RequiredVolumeMounts returns volume mounts that are related to dex.
	RequiredVolumeMounts() []corev1.VolumeMount
	// RequiredVolumes returns volumes that are related to dex.
	RequiredVolumes() []corev1.Volume
}

// DexRelyingPartyConfig is a config for relying parties / applications that use Dex as their IdP.
type DexRelyingPartyConfig interface {
	// JWKSURI returns the endpoint for public keys
	JWKSURI() string
	// TokenURI returns the endpoint for exchanging tokens
	TokenURI() string
	// UserInfoURI returns the endpoint for user info.
	UserInfoURI() string
	// ClientSecret returns the secret for Dex' auth endpoint
	ClientSecret() []byte
	// ManagerURI returns the address where the Manager UI can be found. Ex: https://example.org
	RequestedScopes() []string
	// UsernameClaim returns the part of the JWT that represents a unique username.
	UsernameClaim() string
	DexKeyValidatorConfig
}

func NewDexRelyingPartyConfig(
	authentication *oprv1.Authentication,
	tlsSecret *corev1.Secret,
	dexSecret *corev1.Secret,
	clusterDomain string) DexRelyingPartyConfig {
	return &dexRelyingPartyConfig{baseCfg(authentication, tlsSecret, dexSecret, nil, clusterDomain)}
}

func NewDexKeyValidatorConfig(
	authentication *oprv1.Authentication,
	tlsSecret *corev1.Secret,
	idpSecret *corev1.Secret,
	clusterDomain string) DexKeyValidatorConfig {
	return &dexKeyValidatorConfig{baseCfg(authentication, tlsSecret, nil, idpSecret, clusterDomain)}
}

// Create a new DexConfig.
func NewDexConfig(
	authentication *oprv1.Authentication,
	tlsSecret *corev1.Secret,
	dexSecret *corev1.Secret,
	idpSecret *corev1.Secret,
	clusterDomain string) DexConfig {
	return &dexConfig{baseCfg(authentication, tlsSecret, dexSecret, idpSecret, clusterDomain)}
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
	idpSecret *corev1.Secret,
	clusterDomain string) *dexBaseCfg {

	// If the manager domain is not a URL, prepend https://.
	baseUrl := authentication.Spec.ManagerDomain
	if !strings.HasPrefix(baseUrl, "http://") && !strings.HasPrefix(baseUrl, "https://") {
		baseUrl = fmt.Sprintf("https://%s", baseUrl)
	}

	var connType string
	if authentication.Spec.OIDC != nil {
		if authentication.Spec.OIDC.IssuerURL == googleIssuer {
			connType = connectorTypeGoogle
		} else {
			connType = connectorTypeOIDC
		}
	} else if authentication.Spec.Openshift != nil {
		connType = connectorTypeOpenshift
	} else if authentication.Spec.LDAP != nil {
		connType = connectorTypeLDAP
	}

	return &dexBaseCfg{
		authentication: authentication,
		tlsSecret:      tlsSecret,
		idpSecret:      idpSecret,
		dexSecret:      dexSecret,
		connectorType:  connType,
		managerURI:     baseUrl,
		clusterDomain:  clusterDomain,
	}
}

type dexBaseCfg struct {
	authentication *oprv1.Authentication
	tlsSecret      *corev1.Secret
	idpSecret      *corev1.Secret
	dexSecret      *corev1.Secret
	managerURI     string
	connectorType  string
	clusterDomain  string
}

func (d *dexBaseCfg) ManagerURI() string {
	return d.managerURI
}

func (d *dexBaseCfg) Issuer() string {
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.OIDCType == oprv1.OIDCTypeTigera {
		return d.authentication.Spec.OIDC.IssuerURL
	}
	return fmt.Sprintf("%s/dex", d.managerURI)
}

func (d *dexBaseCfg) RequiredConfigMaps(namespace string) []*corev1.ConfigMap {
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.OIDCType == oprv1.OIDCTypeTigera {
		p, wellknown, keys := d.getStuff()

		wellknown = strings.ReplaceAll(wellknown, p.JWKSURL, "/discovery/keys")
		return []*corev1.ConfigMap{
			{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      ManagerOIDCConfig,
					Namespace: namespace,
					Labels:    map[string]string{
						//"unsupported.operator.tigera.io/ignore": "true", // nice hack for now :-). todo: use http get and replace stuff etc.
					},
				},
				Data: map[string]string{
					"openid-configuration": wellknown,
					"keys":                 keys,
				},
			},
		}
	}
	return nil
}

func (d *dexBaseCfg) ClientId() string {
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.OIDCType == oprv1.OIDCTypeTigera {
		return string(d.idpSecret.Data[ClientIDSecretField])
	}
	return fmt.Sprintf("%s/dex", d.managerURI)
}

func (d *dexBaseCfg) UsernameClaim() string {
	claim := defaultUsernameClaim
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.UsernameClaim != "" {
		claim = d.authentication.Spec.OIDC.UsernameClaim
	}
	return claim
}

func (d *dexBaseCfg) ClientSecret() []byte {
	return d.dexSecret.Data[ClientSecretSecretField]
}

func (d *dexBaseCfg) RequestedScopes() []string {
	if d.authentication.Spec.OIDC != nil && d.authentication.Spec.OIDC.RequestedScopes != nil {
		return d.authentication.Spec.OIDC.RequestedScopes
	}
	return []string{"openid", "email", "profile"}
}

func (d *dexBaseCfg) RequiredSecrets(namespace string) []*corev1.Secret {
	secrets := []*corev1.Secret{
		secret.CopyToNamespace(namespace, d.tlsSecret)[0],
	}
	if d.dexSecret != nil {
		secrets = append(secrets, secret.CopyToNamespace(namespace, d.dexSecret)...)
	}
	if d.idpSecret != nil {
		secrets = append(secrets, secret.CopyToNamespace(namespace, d.idpSecret)...)
	}
	return secrets
}

// RequiredAnnotations returns the annotations that are relevant for a Dex deployment.
func (d *dexConfig) RequiredAnnotations() map[string]string {
	var annotations = map[string]string{
		dexConfigMapAnnotation: rmeta.AnnotationHash(d.Connector()),
		dexTLSSecretAnnotation: rmeta.AnnotationHash(d.tlsSecret.Data),
	}
	if d.idpSecret != nil {
		annotations[dexIdpSecretAnnotation] = rmeta.AnnotationHash(d.idpSecret.Data)
	}
	if d.dexSecret != nil {
		annotations[dexSecretAnnotation] = rmeta.AnnotationHash(d.dexSecret.Data)
	}
	return annotations
}

// RequiredAnnotations returns the annotations that are relevant for a relying party config.
func (d *dexRelyingPartyConfig) RequiredAnnotations() map[string]string {
	var annotations = map[string]string{
		authenticationAnnotation: rmeta.AnnotationHash([]interface{}{d.UsernameClaim(), d.ManagerURI(), d.RequestedScopes()}),
		dexTLSSecretAnnotation:   rmeta.AnnotationHash(d.tlsSecret.Data),
	}
	if d.dexSecret != nil {
		annotations[dexSecretAnnotation] = rmeta.AnnotationHash(d.dexSecret.Data)
	}
	return annotations
}

// RequiredAnnotations returns the annotations that are relevant for a validator config.
func (d *dexKeyValidatorConfig) RequiredAnnotations() map[string]string {
	var annotations = map[string]string{
		authenticationAnnotation: rmeta.AnnotationHash([]interface{}{d.UsernameClaim(), d.ManagerURI(), d.RequiredConfigMaps("")}),
		dexTLSSecretAnnotation:   rmeta.AnnotationHash(d.tlsSecret.Data),
	}
	return annotations
}

type providerJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

func (d *dexBaseCfg) getStuff() (providerJSON, string, string) {
	ctx := context.TODO()
	wellKnown := strings.TrimSuffix(d.Issuer(), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		panic(err)
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("unable to read response body: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("%s: %s", resp.Status, body))
	}

	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		panic(fmt.Sprintf("oidc: failed to decode provider discovery object: %v", err))
	}
	wellKnownJson := string(body)
	// fetch the keys
	req, err = http.NewRequest("GET", p.JWKSURL, nil)
	if err != nil {
		panic(fmt.Errorf("oidc: can't create request: %v", err))
	}

	resp, err = doRequest(ctx, req)
	if err != nil {
		panic(fmt.Errorf("oidc: get keys failed %v", err))
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("unable to read response body: %v", err))
	}
	return p, wellKnownJson, string(body)

}

// Append variables that are necessary for using the dex authenticator.
func (d *dexKeyValidatorConfig) RequiredEnv(prefix string) []corev1.EnvVar {
	oidc := d.authentication.Spec.OIDC
	if d.connectorType == connectorTypeOIDC && oidc.OIDCType == oprv1.OIDCTypeTigera {
		p, _, _ := d.getStuff()
		return []corev1.EnvVar{
			{Name: fmt.Sprintf("%sDEX_ENABLED", prefix), Value: strconv.FormatBool(true)},
			{Name: fmt.Sprintf("%sDEX_ISSUER", prefix), Value: d.Issuer()},
			{Name: fmt.Sprintf("%sDEX_URL", prefix), Value: d.Issuer()},
			{Name: fmt.Sprintf("%sDEX_JWKSURL", prefix), Value: p.JWKSURL}, //todo: get from well-known
			{Name: fmt.Sprintf("%sDEX_CLIENT_ID", prefix), Value: d.ClientId()},
			{Name: fmt.Sprintf("%sDEX_USERNAME_CLAIM", prefix), Value: oidc.UsernameClaim},
			{Name: fmt.Sprintf("%sDEX_GROUPS_CLAIM", prefix), Value: oidc.GroupsClaim},
			{Name: fmt.Sprintf("%sDEX_USERNAME_PREFIX", prefix), Value: d.authentication.Spec.UsernamePrefix},
			{Name: fmt.Sprintf("%sDEX_GROUPS_PREFIX", prefix), Value: d.authentication.Spec.GroupsPrefix},
		}
	}

	return []corev1.EnvVar{
		{Name: fmt.Sprintf("%sDEX_ENABLED", prefix), Value: strconv.FormatBool(true)},
		{Name: fmt.Sprintf("%sDEX_ISSUER", prefix), Value: fmt.Sprintf("%s/dex", d.ManagerURI())},
		{Name: fmt.Sprintf("%sDEX_URL", prefix), Value: fmt.Sprintf("https://tigera-dex.tigera-dex.svc.%s:5556/", d.clusterDomain)},
		{Name: fmt.Sprintf("%sDEX_JWKSURL", prefix), Value: fmt.Sprintf(jwksURI, d.clusterDomain)},
		{Name: fmt.Sprintf("%sDEX_CLIENT_ID", prefix), Value: DexClientId},
		{Name: fmt.Sprintf("%sDEX_USERNAME_CLAIM", prefix), Value: d.UsernameClaim()},
		{Name: fmt.Sprintf("%sDEX_GROUPS_CLAIM", prefix), Value: DefaultGroupsClaim},
		{Name: fmt.Sprintf("%sDEX_USERNAME_PREFIX", prefix), Value: d.authentication.Spec.UsernamePrefix},
		{Name: fmt.Sprintf("%sDEX_GROUPS_PREFIX", prefix), Value: d.authentication.Spec.GroupsPrefix},
	}
}

// Append variables that are necessary for using the dex authenticator.
func (d *dexRelyingPartyConfig) RequiredEnv(prefix string) []corev1.EnvVar {
	return nil
}

// Append variables that are necessary for configuring dex.
func (d *dexConfig) RequiredEnv(string) []corev1.EnvVar {
	env := []corev1.EnvVar{
		{Name: dexSecretEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.dexSecret.Name}}}},
	}
	if d.idpSecret != nil {
		for key := range d.idpSecret.Data {
			switch key {
			case ClientIDSecretField:
				env = append(env, corev1.EnvVar{Name: clientIDEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientIDSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}})
				break
			case ClientSecretSecretField:
				env = append(env, corev1.EnvVar{Name: clientSecretEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}})
				break
			case adminEmailSecretField:
				env = append(env, corev1.EnvVar{Name: googleAdminEmailEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: adminEmailSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}})
				break
			case BindDNSecretField:
				env = append(env, corev1.EnvVar{Name: bindDNEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: BindDNSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}})
				break
			case BindPWSecretField:
				env = append(env, corev1.EnvVar{Name: bindPWEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: BindPWSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: d.idpSecret.Name}}}})
				break
			}
		}
	}

	return env
}

func (d *dexConfig) RequiredVolumes() []corev1.Volume {
	defaultMode := int32(420)
	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: DexObjectName}, Items: []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}}}},
		},
		{
			Name:         "tls",
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: DexTLSSecretName}},
		},
	}

	if d.idpSecret != nil && d.idpSecret.Data[serviceAccountSecretField] != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name:         "secrets",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: d.idpSecret.Name, Items: []corev1.KeyToPath{{Key: serviceAccountSecretField, Path: "google-groups.json"}}}},
			},
		)
	}

	if d.idpSecret != nil && d.idpSecret.Data[RootCASecretField] != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name:         "secrets",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{DefaultMode: &defaultMode, SecretName: d.idpSecret.Name, Items: []corev1.KeyToPath{{Key: RootCASecretField, Path: "idp.pem"}}}},
			},
		)
	}
	return volumes
}

// Add volume for Dex TLS secret.
func (d *dexKeyValidatorConfig) RequiredVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
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
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.OIDCType == oprv1.OIDCTypeTigera {
		defaultMode := int32(420)
		return append(volumes, []corev1.Volume{
			{
				Name: ManagerOIDCConfig,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: ManagerOIDCConfig,
						},
						DefaultMode: &defaultMode,
					},
				},
			},
		}...)
	}

	return volumes
}

// Add volume for Dex TLS secret.
func (d *dexRelyingPartyConfig) RequiredVolumes() []corev1.Volume {
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
	mounts := []corev1.VolumeMount{{Name: DexTLSSecretName, MountPath: "/etc/ssl/certs"}} //todo dont use this secret anywhere for OIDCTypeTigera
	if d.connectorType == connectorTypeOIDC && d.authentication.Spec.OIDC.OIDCType == oprv1.OIDCTypeTigera {
		ManagerOIDCWellknownURI := "/usr/share/nginx/html/.well-known" //todo move
		ManagerOIDCJwksURI := "/usr/share/nginx/html/discovery"        //todo move
		return append(mounts, []corev1.VolumeMount{
			{Name: ManagerOIDCConfig, MountPath: ManagerOIDCWellknownURI},
			{Name: ManagerOIDCConfig, MountPath: ManagerOIDCJwksURI},
		}...)
	}

	return mounts
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
			MountPath: "/etc/ssl/certs/",
			ReadOnly:  true,
		})
	}
	return volumeMounts
}

// AppendDexVolumeMount adds mount for ubi base image trusted cert location
func (d *dexRelyingPartyConfig) RequiredVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{{Name: DexTLSSecretName, MountPath: "/usr/share/elasticsearch/config/dex/"}}
}

func (d *dexRelyingPartyConfig) DexIssuer() string {
	return fmt.Sprintf("%s/dex", d.ManagerURI())
}

func (d *dexRelyingPartyConfig) AuthURI() string {
	return fmt.Sprintf("%s/dex/auth", d.ManagerURI())
}

func (d *dexRelyingPartyConfig) JWKSURI() string {
	return fmt.Sprintf(jwksURI, d.clusterDomain)
}

func (d *dexRelyingPartyConfig) TokenURI() string {
	return fmt.Sprintf(tokenURI, d.clusterDomain)
}

func (d *dexRelyingPartyConfig) UserInfoURI() string {
	return fmt.Sprintf(userInfoURI, d.clusterDomain)
}

// This func prepares the configuration and objects that will be rendered related to the connector and its secrets.
func (d *dexConfig) Connector() map[string]interface{} {
	var config map[string]interface{}
	connectorType := d.connectorType

	switch connectorType {
	case connectorTypeOIDC:
		config = map[string]interface{}{
			"issuer":       d.authentication.Spec.OIDC.IssuerURL,
			"clientID":     fmt.Sprintf("$%s", clientIDEnv),
			"clientSecret": fmt.Sprintf("$%s", clientSecretEnv),
			"redirectURI":  fmt.Sprintf("%s/dex/callback", d.ManagerURI()),
			"scopes":       d.RequestedScopes(),
			"userNameKey":  d.UsernameClaim(),
			"userIDKey":    d.UsernameClaim(),
			"insecureSkipEmailVerified": d.authentication.Spec.OIDC.EmailVerification != nil &&
				*d.authentication.Spec.OIDC.EmailVerification == oprv1.EmailVerificationTypeSkip,
			// Although the field is called insecure, it no longer is. It was first introduced without proper refreshing
			// of the groups claim, leading to stale groups. This has been addressed in Dex v2.25, yet the field retains
			// this name.
			"insecureEnableGroups": true,
		}
		promptTypes := d.authentication.Spec.OIDC.PromptTypes
		if promptTypes != nil {
			length := len(promptTypes)
			prompts := make([]string, length)
			for i, v := range promptTypes {
				switch v {
				case oprv1.PromptTypeNone:
					prompts[i] = "none"
				case oprv1.PromptTypeSelectAccount:
					prompts[i] = "select_account"
				case oprv1.PromptTypeLogin:
					prompts[i] = "login"
				case oprv1.PromptTypeConsent:
					prompts[i] = "consent"
				}
			}
			// RFC specifies space delimited case sensitive list: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			config["promptType"] = strings.Join(prompts, " ")
		}
		groupsClaim := d.authentication.Spec.OIDC.GroupsClaim
		if groupsClaim != "" && groupsClaim != DefaultGroupsClaim {
			config["claimMapping"] = map[string]string{
				"groups": groupsClaim,
			}
		}

	case connectorTypeGoogle:
		config = map[string]interface{}{
			"issuer":       googleIssuer,
			"clientID":     fmt.Sprintf("$%s", clientIDEnv),
			"clientSecret": fmt.Sprintf("$%s", clientSecretEnv),
			"redirectURI":  fmt.Sprintf("%s/dex/callback", d.ManagerURI()),
			"scopes":       d.RequestedScopes(),
		}
		if d.idpSecret.Data[serviceAccountSecretField] != nil && d.idpSecret.Data[adminEmailSecretField] != nil {
			config[serviceAccountFilePathField] = serviceAccountSecretLocation
			config[adminEmailSecretField] = fmt.Sprintf("$%s", googleAdminEmailEnv)
		}

	case connectorTypeOpenshift:
		config = map[string]interface{}{
			"issuer":          d.authentication.Spec.Openshift.IssuerURL,
			"clientID":        fmt.Sprintf("$%s", clientIDEnv),
			"clientSecret":    fmt.Sprintf("$%s", clientSecretEnv),
			"redirectURI":     fmt.Sprintf("%s/dex/callback", d.ManagerURI()),
			RootCASecretField: rootCASecretLocation,
		}
	case connectorTypeLDAP:
		config = map[string]interface{}{
			"host":            d.authentication.Spec.LDAP.Host,
			"bindDN":          fmt.Sprintf("$%s", bindDNEnv),
			"bindPW":          fmt.Sprintf("$%s", bindPWEnv),
			"startTLS":        d.authentication.Spec.LDAP.StartTLS != nil && *d.authentication.Spec.LDAP.StartTLS,
			RootCASecretField: rootCASecretLocation,
			"userSearch": map[string]string{
				"baseDN":    d.authentication.Spec.LDAP.UserSearch.BaseDN,
				"filter":    d.authentication.Spec.LDAP.UserSearch.Filter,
				"emailAttr": d.authentication.Spec.LDAP.UserSearch.NameAttribute,
				"idAttr":    d.authentication.Spec.LDAP.UserSearch.NameAttribute,
				"username":  d.authentication.Spec.LDAP.UserSearch.NameAttribute,
				"nameAttr":  d.authentication.Spec.LDAP.UserSearch.NameAttribute,
			},
		}
		if d.authentication.Spec.LDAP.GroupSearch != nil {
			matchers := make([]map[string]string, len(d.authentication.Spec.LDAP.GroupSearch.UserMatchers))
			for i, match := range d.authentication.Spec.LDAP.GroupSearch.UserMatchers {
				matchers[i] = map[string]string{
					"userAttr":  match.UserAttribute,
					"groupAttr": match.GroupAttribute,
				}
			}

			config["groupSearch"] = map[string]interface{}{
				"baseDN":       d.authentication.Spec.LDAP.GroupSearch.BaseDN,
				"filter":       d.authentication.Spec.LDAP.GroupSearch.Filter,
				"nameAttr":     d.authentication.Spec.LDAP.GroupSearch.NameAttribute,
				"userMatchers": matchers,
			}
		}
	default:

	}

	return map[string]interface{}{
		"id":     connectorType,
		"type":   connectorType,
		"name":   connectorType,
		"config": config,
	}
}
