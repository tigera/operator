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

package sharedconfig

import (
	"encoding/json"
	"fmt"
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// reclaimablePaths lists fields a plain update owns that hold the operator's own value.
// An apply must force ownership across once.
func reclaimablePaths(fc *v3.FelixConfiguration) (map[string]bool, error) {
	updated, err := updateOwnedPaths(fc)
	if err != nil || len(updated) == 0 {
		return nil, err
	}
	lastWritten, err := lastWrittenValues(fc)
	if err != nil || len(lastWritten) == 0 {
		return nil, err
	}
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(fc)
	if err != nil {
		return nil, fmt.Errorf("unable to read FelixConfiguration fields: %w", err)
	}

	reclaimable := map[string]bool{}
	for path := range lastWritten {
		if !updated[path] {
			continue
		}
		changed, err := changedByOther(content, lastWritten, path)
		if err != nil {
			return nil, err
		}
		if !changed {
			reclaimable[path] = true
		}
	}
	return reclaimable, nil
}

// updateOwnedPaths lists the fields owned through a plain update rather than an apply.
func updateOwnedPaths(fc *v3.FelixConfiguration) (map[string]bool, error) {
	owned := map[string]bool{}
	for _, entry := range fc.ManagedFields {
		if entry.Operation != metav1.ManagedFieldsOperationUpdate || entry.FieldsV1 == nil {
			continue
		}
		fields := map[string]any{}
		if err := json.Unmarshal(entry.FieldsV1.Raw, &fields); err != nil {
			return nil, fmt.Errorf("unable to parse the fields managed by %q: %w", entry.Manager, err)
		}
		collectFieldPaths(fields, "", owned)
	}
	return owned, nil
}

// collectFieldPaths flattens a managed field set into paths of the "spec.field" form.
func collectFieldPaths(fields map[string]any, prefix string, out map[string]bool) {
	for key, value := range fields {
		name, found := strings.CutPrefix(key, "f:")
		if !found {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		out[path] = true
		if children, ok := value.(map[string]any); ok {
			collectFieldPaths(children, path, out)
		}
	}
}
