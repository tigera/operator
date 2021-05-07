package tigerakvc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultGroupsClaim   = "groups"
	defaultUsernameClaim = "email"
)

// KeyValidatorConfig implements the KeyValidatorConfig interface. It uses the OIDC implicit flow, and maps the
// wellknown config / jwks keys to a config map.
type KeyValidatorConfig struct {
	wellKnownConfig *authentication.WellKnownConfig
	jwks            string
	issuerURL       string
	clientID        string
	usernameClaim   string
	groupsClaim     string
	usernamePrefix  string
	groupsPrefix    string
}

func New(issuerURL string, clientID string, options ...Option) (authentication.KeyValidatorConfig, error) {
	kvc := &KeyValidatorConfig{
		issuerURL:     issuerURL,
		clientID:      clientID,
		usernameClaim: defaultUsernameClaim,
		groupsClaim:   defaultGroupsClaim,
	}

	for _, option := range options {
		option(kvc)
	}

	wellKnownConfig, err := NewWellKnownConfig(kvc.issuerURL)
	if err != nil {
		return nil, err
	}

	jwks, err := wellKnownConfig.GetJWKS()
	if err != nil {
		return nil, err
	}

	kvc.wellKnownConfig = wellKnownConfig
	kvc.jwks = string(jwks)

	return kvc, nil
}

func (kvc *KeyValidatorConfig) Issuer() string {
	return kvc.issuerURL
}

func (kvc *KeyValidatorConfig) ClientID() string {
	return kvc.clientID
}

func (kvc *KeyValidatorConfig) RequiredEnv(prefix string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: fmt.Sprintf("%sOIDC_AUTH_ENABLED", prefix), Value: strconv.FormatBool(true)},
		{Name: fmt.Sprintf("%sOIDC_AUTH_ISSUER", prefix), Value: kvc.Issuer()},
		{Name: fmt.Sprintf("%sOIDC_AUTH_URL", prefix), Value: kvc.Issuer()},
		{Name: fmt.Sprintf("%sOIDC_AUTH_JWKSURL", prefix), Value: kvc.wellKnownConfig.JWKSURL},
		{Name: fmt.Sprintf("%sOIDC_AUTH_CLIENT_ID", prefix), Value: kvc.ClientID()},
		{Name: fmt.Sprintf("%sOIDC_AUTH_USERNAME_CLAIM", prefix), Value: kvc.usernameClaim},
		{Name: fmt.Sprintf("%sOIDC_AUTH_GROUPS_CLAIM", prefix), Value: kvc.groupsClaim},
		{Name: fmt.Sprintf("%sOIDC_AUTH_USERNAME_PREFIX", prefix), Value: kvc.usernamePrefix},
		{Name: fmt.Sprintf("%sOIDC_AUTH_GROUPS_PREFIX", prefix), Value: kvc.groupsPrefix},
	}
}

func (kvc *KeyValidatorConfig) RequiredAnnotations() map[string]string {
	return map[string]string{
		"hash.operator.tigera.io/tigera-wellknown": rmeta.AnnotationHash(kvc.wellKnownConfig),
		"hash.operator.tigera.io/tigera-auth-jwks": rmeta.AnnotationHash(kvc.jwks),
	}
}

func (kvc *KeyValidatorConfig) RequiredSecrets(namespace string) []*corev1.Secret {
	return nil
}

func (kvc *KeyValidatorConfig) RequiredVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: render.ManagerOIDCConfig, MountPath: "/usr/share/nginx/html/.well-known"},
		{Name: render.ManagerOIDCConfig, MountPath: "/usr/share/nginx/html/discovery"},
	}
}

func (kvc *KeyValidatorConfig) RequiredVolumes() []corev1.Volume {
	defaultMode := int32(420)
	return []corev1.Volume{{
		Name: render.ManagerOIDCConfig,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: render.ManagerOIDCConfig,
				},
				DefaultMode: &defaultMode,
			},
		},
	}}
}

func (kvc *KeyValidatorConfig) RequiredConfigMaps(namespace string) []*corev1.ConfigMap {
	wellKnown := *kvc.wellKnownConfig
	wellKnown.JWKSURL = "/discovery/keys"
	return []*corev1.ConfigMap{
		{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ManagerOIDCConfig,
				Namespace: namespace,
			},
			Data: map[string]string{
				"openid-configuration": wellKnown.ToString(),
				"keys":                 kvc.jwks,
			},
		},
	}
}

func NewWellKnownConfig(issuerURL string) (*authentication.WellKnownConfig, error) {
	httpClient := http.DefaultClient

	wellKnown := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	wellKnownConfig := authentication.WellKnownConfig{}
	if err = json.Unmarshal(body, &wellKnownConfig); err != nil {
		return nil, err
	}

	return &wellKnownConfig, nil
}
