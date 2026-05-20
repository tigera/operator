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
	"context"
	"embed"
	"fmt"
	"path"
	"time"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

	// APIGroup is the API group for MutatingAdmissionPolicy resources.
	APIGroup = "admissionregistration.k8s.io"
	// VersionV1 is the GA API version (k8s 1.36+).
	VersionV1 = "v1"
	// VersionV1Beta1 is the beta API version (k8s 1.32-1.36).
	VersionV1Beta1 = "v1beta1"

	// KindPolicy is the MutatingAdmissionPolicy kind.
	KindPolicy = "MutatingAdmissionPolicy"
	// KindBinding is the MutatingAdmissionPolicyBinding kind.
	KindBinding = "MutatingAdmissionPolicyBinding"
)

// PolicyGroupKind is the GroupKind for MutatingAdmissionPolicy. Exposed so the API discovery
// registry in cmd/main.go can pre-resolve its served version at startup.
var PolicyGroupKind = schema.GroupKind{Group: APIGroup, Kind: KindPolicy}

var (
	//go:embed calico
	calicoAdmissionFiles embed.FS
	//go:embed enterprise
	enterpriseAdmissionFiles embed.FS
)

// GetMutatingAdmissionPolicies returns MutatingAdmissionPolicy and MutatingAdmissionPolicyBinding
// objects for the given variant, typed at the requested API version. These are only applicable
// when v3 CRDs are enabled.
// Each returned object is labeled with ManagedMAPLabel to enable stale resource cleanup.
func GetMutatingAdmissionPolicies(variant opv1.ProductVariant, v3 bool, apiVersion string) []client.Object {
	if !v3 || apiVersion == "" {
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

			obj, err := parseAdmissionPolicyYAML(doc, entry.Name(), apiVersion)
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

// Ensure ensures that MutatingAdmissionPolicies necessary for bootstrapping exist in the cluster.
// Further reconciliation is handled by the core controller. If apiVersion is empty (no served
// version of MutatingAdmissionPolicy on the cluster), a warning is logged and the function returns
// nil. MAPs are only installed when v3 CRDs are enabled.
func Ensure(c client.Client, variant string, v3 bool, apiVersion string, log logr.Logger) error {
	if !v3 {
		return nil
	}

	if apiVersion == "" {
		log.Info("MutatingAdmissionPolicy API not available on cluster, skipping bootstrap")
		return nil
	}

	objs := GetMutatingAdmissionPolicies(opv1.ProductVariant(variant), v3, apiVersion)

	for _, obj := range objs {
		log.Info("ensuring MutatingAdmissionPolicy resource exists", "name", obj.GetName(), "kind", obj.GetObjectKind().GroupVersionKind().Kind)
		// Cancel explicitly rather than using defer, since defer only runs at
		// function return and would leak contexts across loop iterations.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := c.Create(ctx, obj); err != nil {
			cancel()
			if errors.IsAlreadyExists(err) {
				continue
			}

			// If the API is not available, log a warning and skip.
			if errors.IsNotFound(err) || errors.IsForbidden(err) {
				log.Info("MutatingAdmissionPolicy API not available, skipping", "error", err)
				return nil
			}

			// Log an error but continue. We'll handle any persistent issues in the core controller's reconciliation loop.
			log.Error(err, "Failed to create MutatingAdmissionPolicy resource", "name", obj.GetName(), "kind", obj.GetObjectKind().GroupVersionKind().Kind)
		} else {
			cancel()
		}
	}
	return nil
}

// parseAdmissionPolicyYAML parses a YAML document into either a MutatingAdmissionPolicy
// or MutatingAdmissionPolicyBinding at the requested API version. The MAP types are identical
// in shape between v1beta1 and v1, so we deserialize the same YAML into the requested target type
// and overwrite TypeMeta to reflect the chosen GroupVersion.
func parseAdmissionPolicyYAML(doc []byte, filename, apiVersion string) (client.Object, error) {
	var meta struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal(doc, &meta); err != nil {
		return nil, fmt.Errorf("unable to determine kind from %s: %v", filename, err)
	}

	gv := APIGroup + "/" + apiVersion

	switch apiVersion {
	case VersionV1:
		switch meta.Kind {
		case "MutatingAdmissionPolicy":
			obj := &admissionregistrationv1.MutatingAdmissionPolicy{}
			if err := yaml.Unmarshal(doc, obj); err != nil {
				return nil, fmt.Errorf("unable to parse MutatingAdmissionPolicy from %s: %v", filename, err)
			}
			obj.TypeMeta = metav1.TypeMeta{Kind: meta.Kind, APIVersion: gv}
			return obj, nil
		case "MutatingAdmissionPolicyBinding":
			obj := &admissionregistrationv1.MutatingAdmissionPolicyBinding{}
			if err := yaml.Unmarshal(doc, obj); err != nil {
				return nil, fmt.Errorf("unable to parse MutatingAdmissionPolicyBinding from %s: %v", filename, err)
			}
			obj.TypeMeta = metav1.TypeMeta{Kind: meta.Kind, APIVersion: gv}
			return obj, nil
		}
	case VersionV1Beta1:
		switch meta.Kind {
		case "MutatingAdmissionPolicy":
			obj := &admissionv1beta1.MutatingAdmissionPolicy{}
			if err := yaml.Unmarshal(doc, obj); err != nil {
				return nil, fmt.Errorf("unable to parse MutatingAdmissionPolicy from %s: %v", filename, err)
			}
			obj.TypeMeta = metav1.TypeMeta{Kind: meta.Kind, APIVersion: gv}
			return obj, nil
		case "MutatingAdmissionPolicyBinding":
			obj := &admissionv1beta1.MutatingAdmissionPolicyBinding{}
			if err := yaml.Unmarshal(doc, obj); err != nil {
				return nil, fmt.Errorf("unable to parse MutatingAdmissionPolicyBinding from %s: %v", filename, err)
			}
			obj.TypeMeta = metav1.TypeMeta{Kind: meta.Kind, APIVersion: gv}
			return obj, nil
		}
	default:
		return nil, fmt.Errorf("unsupported MutatingAdmissionPolicy API version %q", apiVersion)
	}
	return nil, fmt.Errorf("unexpected kind %q in %s", meta.Kind, filename)
}

// ListManaged returns the operator-managed MutatingAdmissionPolicy and MutatingAdmissionPolicyBinding
// objects currently present on the cluster at the given API version. Returns nil if apiVersion is empty.
func ListManaged(ctx context.Context, c client.Client, apiVersion string) (policies, bindings []client.Object, err error) {
	if apiVersion == "" {
		return nil, nil, nil
	}
	switch apiVersion {
	case VersionV1:
		mapList := &admissionregistrationv1.MutatingAdmissionPolicyList{}
		if err := c.List(ctx, mapList, client.MatchingLabels{ManagedMAPLabel: ManagedMAPLabelValue}); err != nil {
			return nil, nil, fmt.Errorf("listing MutatingAdmissionPolicies: %w", err)
		}
		for i := range mapList.Items {
			policies = append(policies, &mapList.Items[i])
		}

		bindList := &admissionregistrationv1.MutatingAdmissionPolicyBindingList{}
		if err := c.List(ctx, bindList, client.MatchingLabels{ManagedMAPLabel: ManagedMAPLabelValue}); err != nil {
			return nil, nil, fmt.Errorf("listing MutatingAdmissionPolicyBindings: %w", err)
		}
		for i := range bindList.Items {
			bindings = append(bindings, &bindList.Items[i])
		}
	case VersionV1Beta1:
		mapList := &admissionv1beta1.MutatingAdmissionPolicyList{}
		if err := c.List(ctx, mapList, client.MatchingLabels{ManagedMAPLabel: ManagedMAPLabelValue}); err != nil {
			return nil, nil, fmt.Errorf("listing MutatingAdmissionPolicies: %w", err)
		}
		for i := range mapList.Items {
			policies = append(policies, &mapList.Items[i])
		}

		bindList := &admissionv1beta1.MutatingAdmissionPolicyBindingList{}
		if err := c.List(ctx, bindList, client.MatchingLabels{ManagedMAPLabel: ManagedMAPLabelValue}); err != nil {
			return nil, nil, fmt.Errorf("listing MutatingAdmissionPolicyBindings: %w", err)
		}
		for i := range bindList.Items {
			bindings = append(bindings, &bindList.Items[i])
		}
	default:
		return nil, nil, fmt.Errorf("unsupported MutatingAdmissionPolicy API version %q", apiVersion)
	}
	return policies, bindings, nil
}

// IsPolicyKind returns whether obj is a MutatingAdmissionPolicy (any served version).
func IsPolicyKind(obj client.Object) bool {
	switch obj.(type) {
	case *admissionregistrationv1.MutatingAdmissionPolicy, *admissionv1beta1.MutatingAdmissionPolicy:
		return true
	}
	return false
}

// IsBindingKind returns whether obj is a MutatingAdmissionPolicyBinding (any served version).
func IsBindingKind(obj client.Object) bool {
	switch obj.(type) {
	case *admissionregistrationv1.MutatingAdmissionPolicyBinding, *admissionv1beta1.MutatingAdmissionPolicyBinding:
		return true
	}
	return false
}
