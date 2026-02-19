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

package admission

import (
	"bytes"
	"embed"
	"fmt"
	"path"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	opv1 "github.com/tigera/operator/api/v1"
)

const (
	// ManagedMAPLabel is the label key applied to operator-managed MutatingAdmissionPolicy and
	// MutatingAdmissionPolicyBinding resources.
	ManagedMAPLabel = "operator.tigera.io/mutating-admission-policy"
	// ManagedMAPLabelValue is the label value for operator-managed MAP resources.
	ManagedMAPLabelValue = "managed"
)

var (
	//go:embed calico
	calicoAdmissionFiles embed.FS
	//go:embed enterprise
	enterpriseAdmissionFiles embed.FS
)

// GetMutatingAdmissionPolicies returns MutatingAdmissionPolicy and MutatingAdmissionPolicyBinding
// objects for the given variant. These are only applicable when v3 CRDs are enabled.
// Each returned object is labeled with ManagedMAPLabel to enable stale resource cleanup.
func GetMutatingAdmissionPolicies(variant opv1.ProductVariant, v3 bool) []client.Object {
	if !v3 {
		return nil
	}

	var fs embed.FS
	var dir string
	if variant == opv1.Calico {
		fs = calicoAdmissionFiles
		dir = "calico"
	} else {
		fs = enterpriseAdmissionFiles
		dir = "enterprise"
	}

	entries, err := fs.ReadDir(dir)
	if err != nil {
		panic(fmt.Sprintf("Failed to read admission policy files from %s: %v", dir, err))
	}

	var objs []client.Object
	for _, entry := range entries {
		b, err := fs.ReadFile(path.Join(dir, entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("Failed to read admission policy file %s: %v", entry.Name(), err))
		}

		docs := bytes.Split(b, []byte("\n---"))
		for _, doc := range docs {
			doc = bytes.TrimSpace(doc)
			if len(doc) == 0 {
				continue
			}

			obj, err := parseAdmissionPolicyYAML(doc, entry.Name())
			if err != nil {
				panic(fmt.Sprintf("Failed to parse admission policy %s: %v", entry.Name(), err))
			}

			// Add managed label for stale resource cleanup.
			labels := obj.GetLabels()
			if labels == nil {
				labels = map[string]string{}
			}
			labels[ManagedMAPLabel] = ManagedMAPLabelValue
			obj.SetLabels(labels)

			objs = append(objs, obj)
		}
	}

	return objs
}

// parseAdmissionPolicyYAML parses a YAML document into either a MutatingAdmissionPolicy
// or MutatingAdmissionPolicyBinding based on its kind field.
func parseAdmissionPolicyYAML(doc []byte, filename string) (client.Object, error) {
	// First, determine the kind.
	var meta struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal(doc, &meta); err != nil {
		return nil, fmt.Errorf("unable to determine kind from %s: %v", filename, err)
	}

	switch meta.Kind {
	case "MutatingAdmissionPolicy":
		obj := &admissionv1beta1.MutatingAdmissionPolicy{}
		if err := yaml.Unmarshal(doc, obj); err != nil {
			return nil, fmt.Errorf("unable to parse MutatingAdmissionPolicy from %s: %v", filename, err)
		}
		return obj, nil
	case "MutatingAdmissionPolicyBinding":
		obj := &admissionv1beta1.MutatingAdmissionPolicyBinding{}
		if err := yaml.Unmarshal(doc, obj); err != nil {
			return nil, fmt.Errorf("unable to parse MutatingAdmissionPolicyBinding from %s: %v", filename, err)
		}
		return obj, nil
	default:
		return nil, fmt.Errorf("unexpected kind %q in %s", meta.Kind, filename)
	}
}
