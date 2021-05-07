package authentication

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	corev1 "k8s.io/api/core/v1"
)

type KeyValidatorConfig interface {
	Issuer() string
	ClientID() string
	// RequiredConfigMaps returns config maps that the KeyValidatorConfig implementation requires.
	RequiredConfigMaps(namespace string) []*corev1.ConfigMap
	// RequiredEnv returns env variables that the KeyValidatorConfig implementation requires.
	RequiredEnv(prefix string) []corev1.EnvVar
	// RequiredAnnotations returns annotations that the KeyValidatorConfig implementation requires.
	RequiredAnnotations() map[string]string
	// RequiredSecrets returns secrets that the KeyValidatorConfig implementation requires.
	RequiredSecrets(namespace string) []*corev1.Secret
	// RequiredVolumeMounts returns volume mounts that the KeyValidatorConfig implementation requires.
	RequiredVolumeMounts() []corev1.VolumeMount
	// RequiredVolumes returns volumes that the KeyValidatorConfig implementation requires.
	RequiredVolumes() []corev1.Volume
}

type WellKnownConfig struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

func (wk *WellKnownConfig) GetJWKS() ([]byte, error) {
	httpClient := http.DefaultClient

	req, err := http.NewRequest("GET", wk.JWKSURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	keys, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

func (wk *WellKnownConfig) ToString() string {
	str, err := json.Marshal(wk)
	if err != nil {
		// TODO rethink panicking
		panic(err)
	}

	return string(str)
}
