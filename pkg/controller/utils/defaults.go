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

package utils

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// MergeRecordedDefaults merges the defaults absent from declared over the recorded ones. Owned
// holds the dotted JSON paths the caller defaults.
func MergeRecordedDefaults(recorded *operatorv1.InstallationSpec, declared, defaulted operatorv1.InstallationSpec, owned ...string) (*operatorv1.InstallationSpec, error) {
	declaredContent, err := specToMap(declared)
	if err != nil {
		return nil, err
	}

	defaultedContent, err := specToMap(defaulted)
	if err != nil {
		return nil, err
	}
	added := addedKeys(declaredContent, defaultedContent)

	content := added
	if len(owned) > 0 {
		content = map[string]any{}
		if recorded != nil {
			if content, err = specToMap(*recorded); err != nil {
				return nil, err
			}
		}
		for _, path := range owned {
			deletePath(content, path)
			if value, present := lookupPath(added, path); present {
				setPath(content, path, value)
			}
		}
		pruneEmptyObjects(content)
	}

	if len(content) == 0 {
		return nil, nil
	}

	raw, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshal supplied defaults: %w", err)
	}

	defaults := &operatorv1.InstallationSpec{}
	if err := json.Unmarshal(raw, defaults); err != nil {
		return nil, fmt.Errorf("unmarshal supplied defaults: %w", err)
	}
	return defaults, nil
}

func lookupPath(content map[string]any, path string) (any, bool) {
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		nested, isObject := content[key].(map[string]any)
		if !isObject {
			return nil, false
		}
		content = nested
	}
	value, present := content[keys[len(keys)-1]]
	return value, present
}

func setPath(content map[string]any, path string, value any) {
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		nested, isObject := content[key].(map[string]any)
		if !isObject {
			nested = map[string]any{}
			content[key] = nested
		}
		content = nested
	}
	content[keys[len(keys)-1]] = value
}

func deletePath(content map[string]any, path string) {
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		nested, isObject := content[key].(map[string]any)
		if !isObject {
			return
		}
		content = nested
	}
	delete(content, keys[len(keys)-1])
}

// pruneEmptyObjects drops objects left empty by a deleted path, so they don't record as defaults.
func pruneEmptyObjects(content map[string]any) {
	for key, value := range content {
		object, isObject := value.(map[string]any)
		if !isObject {
			continue
		}
		pruneEmptyObjects(object)
		if len(object) == 0 {
			delete(content, key)
		}
	}
}

// LayerPoolDefaults fills fields left unset on a declared IP pool from the recorded
// default with the same CIDR.
func LayerPoolDefaults(spec, defaults *operatorv1.InstallationSpec) error {
	if spec == nil || defaults == nil || spec.CalicoNetwork == nil || defaults.CalicoNetwork == nil {
		return nil
	}

	recorded := map[string]operatorv1.IPPool{}
	for _, pool := range defaults.CalicoNetwork.IPPools {
		recorded[pool.CIDR] = pool
	}

	for i := range spec.CalicoNetwork.IPPools {
		declared := spec.CalicoNetwork.IPPools[i]
		base, ok := recorded[declared.CIDR]
		if !ok {
			continue
		}
		merged, err := layerPool(base, declared)
		if err != nil {
			return err
		}
		spec.CalicoNetwork.IPPools[i] = merged
	}
	return nil
}

// layerPool decodes the declared pool over the default, so only fields the user set win.
func layerPool(base, declared operatorv1.IPPool) (operatorv1.IPPool, error) {
	raw, err := json.Marshal(declared)
	if err != nil {
		return base, fmt.Errorf("marshal declared IP pool: %w", err)
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		return base, fmt.Errorf("unmarshal declared IP pool: %w", err)
	}
	return base, nil
}

// addedKeys walks two decoded specs and keeps only what defaulted added on top of declared.
func addedKeys(declared, defaulted map[string]any) map[string]any {
	added := map[string]any{}
	for key, defaultedValue := range defaulted {
		declaredValue, present := declared[key]
		if !present {
			if isVacuous(defaultedValue) {
				continue
			}
			added[key] = defaultedValue
			continue
		}

		// Recurse so one user-set field doesn't hide the siblings defaulted alongside it.
		declaredObject, declaredIsObject := declaredValue.(map[string]any)
		defaultedObject, defaultedIsObject := defaultedValue.(map[string]any)
		if declaredIsObject && defaultedIsObject {
			if nested := addedKeys(declaredObject, defaultedObject); len(nested) > 0 {
				added[key] = nested
			}
			continue
		}

		// Lists are all-or-nothing; per-element merging would need a merge key we don't have.
		if !reflect.DeepEqual(declaredValue, defaultedValue) {
			added[key] = defaultedValue
		}
	}
	return added
}

// isVacuous reports whether a value the user never declared is empty all the way down.
func isVacuous(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for _, nested := range typed {
			if !isVacuous(nested) {
				return false
			}
		}
		return true
	case []any:
		return len(typed) == 0
	default:
		return false
	}
}

func specToMap(spec operatorv1.InstallationSpec) (map[string]any, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("marshal installation spec: %w", err)
	}

	content := map[string]any{}
	if err := json.Unmarshal(raw, &content); err != nil {
		return nil, fmt.Errorf("unmarshal installation spec: %w", err)
	}
	pruneNulls(content)
	return content, nil
}

// pruneNulls drops null fields, which the API server prunes too, so they can't read as defaults.
func pruneNulls(content map[string]any) {
	for key, value := range content {
		if value == nil {
			delete(content, key)
			continue
		}
		if object, isObject := value.(map[string]any); isObject {
			pruneNulls(object)
		}
	}
}
