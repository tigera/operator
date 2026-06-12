// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package kubecontrollers

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/common"
)

// MergeWAFPullSecret synthesizes the dedicated WAF wasm pull secret
// (tigera-waf-pull-secret) by merging the registry auths of every Installation
// pull secret. The EnvoyExtensionPolicy image source takes a single
// pullSecretRef, so a merged secret is the only way to honor multiple
// Installation pull secrets for the Coraza wasm OCI pull (e.g. the Tigera pull
// secret plus credentials for a private registry mirror).
//
// If the same registry appears in more than one secret, the first secret in
// Installation order wins. Secrets that cannot be parsed are skipped and their
// names returned, so the caller can log them without failing the reconcile.
// Returns a nil Secret when no registry auths could be collected.
func MergeWAFPullSecret(pullSecrets []*corev1.Secret) (*corev1.Secret, []string) {
	merged := map[string]json.RawMessage{}
	var skipped []string
	for _, s := range pullSecrets {
		auths, err := registryAuths(s)
		if err != nil {
			skipped = append(skipped, s.Name)
			continue
		}
		for registry, auth := range auths {
			if _, ok := merged[registry]; !ok {
				merged[registry] = auth
			}
		}
	}
	if len(merged) == 0 {
		return nil, skipped
	}

	// Marshalling a map sorts its keys, so the rendered bytes are deterministic
	// and do not churn the object on every reconcile.
	data, err := json.Marshal(map[string]map[string]json.RawMessage{"auths": merged})
	if err != nil {
		// Each auth entry round-trips from a successful Unmarshal above, so
		// this cannot fail in practice; treat it as nothing to render.
		return nil, skipped
	}

	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WASMPullSecretName, Namespace: common.CalicoNamespace},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: data},
	}, skipped
}

// registryAuths extracts the per-registry auth entries from a pull secret of
// either the dockerconfigjson type (auths nested under an "auths" key) or the
// legacy dockercfg type (a bare registry -> auth map).
func registryAuths(s *corev1.Secret) (map[string]json.RawMessage, error) {
	if raw, ok := s.Data[corev1.DockerConfigJsonKey]; ok {
		var cfg struct {
			Auths map[string]json.RawMessage `json:"auths"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, err
		}
		if len(cfg.Auths) == 0 {
			return nil, fmt.Errorf("secret %s has no auths entries", s.Name)
		}
		return cfg.Auths, nil
	}
	if raw, ok := s.Data[corev1.DockerConfigKey]; ok {
		var auths map[string]json.RawMessage
		if err := json.Unmarshal(raw, &auths); err != nil {
			return nil, err
		}
		if len(auths) == 0 {
			return nil, fmt.Errorf("secret %s has no auths entries", s.Name)
		}
		return auths, nil
	}
	return nil, fmt.Errorf("secret %s has neither a %s nor a %s key", s.Name, corev1.DockerConfigJsonKey, corev1.DockerConfigKey)
}
