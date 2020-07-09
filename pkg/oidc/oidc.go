package oidc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type WellKnownConfig struct {
	Issuer                string   `json:"issuer"`
	ScopesSupported       []string `json:"scopes_supported"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSetURI             string   `json:"jwks_uri"`
}

func LookupWellKnownConfig(issuerURL string) (*WellKnownConfig, error) {
	resp, err := http.Get(fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL))
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	wellKnown := WellKnownConfig{}
	if err := json.Unmarshal(body, &wellKnown); err != nil {
		return nil, err
	}

	return &wellKnown, nil
}
