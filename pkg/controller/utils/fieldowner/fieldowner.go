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

// Package fieldowner provides a centralized mechanism for tracking operator field ownership
// on shared Kubernetes resources like FelixConfiguration and BGPConfiguration. It replaces
// ad-hoc per-field annotation tracking with a single, consistent API.
//
// The operator and end users both modify these shared resources. The tracker uses a per-controller
// annotation (JSON map of field name → last-written value) to detect when a user has modified a
// field the operator previously set, and applies a configurable conflict policy to decide whether
// to error, defer to the user, or override.
package fieldowner

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const annotationPrefix = "operator.tigera.io/managed-fields-"

// ConflictPolicy determines how to handle user modifications to operator-managed fields.
type ConflictPolicy int

const (
	// ConflictError returns an error when a user has modified an operator-managed field.
	// Use for fields where the operator must maintain control (e.g., BPFEnabled).
	ConflictError ConflictPolicy = iota

	// ConflictDefer releases operator ownership when a user modifies the field,
	// allowing the user's value to persist. Use for defaulted fields where user
	// intent should win (e.g., HealthPort, VXLANVNI).
	ConflictDefer

	// ConflictOverride always applies the operator's desired value regardless of
	// user changes. Use only for fields the operator unconditionally controls.
	ConflictOverride
)

// Tracker manages operator field ownership on a shared Kubernetes resource. Each controller
// that writes to a shared resource should create its own Tracker (identified by controller name)
// to avoid cross-controller annotation conflicts.
//
// Usage:
//
//	t := fieldowner.ForObject("installation", fc)
//	if shouldSet, err := t.Manage("BPFEnabled", current, desired, fieldowner.ConflictError); err != nil {
//	    return err
//	} else if shouldSet {
//	    fc.Spec.BPFEnabled = &desired
//	}
//	t.Flush(fc)
type Tracker struct {
	annotationKey string
	fields        map[string]string
}

// ForObject creates a Tracker loaded from the given object's annotations.
// controllerName identifies the controller managing these fields and is used
// as part of the annotation key to avoid cross-controller conflicts.
func ForObject(controllerName string, obj client.Object) *Tracker {
	t := &Tracker{
		annotationKey: annotationPrefix + controllerName,
		fields:        make(map[string]string),
	}
	annotations := obj.GetAnnotations()
	if annotations != nil {
		if raw, ok := annotations[t.annotationKey]; ok {
			_ = json.Unmarshal([]byte(raw), &t.fields)
		}
	}
	return t
}

// Manage evaluates whether the operator should set a field based on the given conflict policy.
// current is the string representation of the field's current value ("" for nil/unset).
// desired is the string representation of the operator's desired value.
//
// Returns shouldSet=true if the caller should apply the desired value to the spec.
// The caller is responsible for actually setting the spec field; the tracker only manages
// the annotation bookkeeping.
//
// Call Flush after all Manage/Release calls to write changes back to the object.
func (t *Tracker) Manage(field, current, desired string, policy ConflictPolicy) (bool, error) {
	tracked, wasTracked := t.fields[field]
	userModified := wasTracked && tracked != current

	switch policy {
	case ConflictError:
		if userModified {
			return false, fmt.Errorf(
				"field %q has been modified by another actor (operator last set %q, current value %q); refusing to override",
				field, tracked, current,
			)
		}
		// First time seeing a field that already has the value we want — adopt it.
		if !wasTracked && current != "" && current == desired {
			t.fields[field] = desired
			return false, nil
		}
		// First time seeing a field with a different value — someone else set it.
		if !wasTracked && current != "" && current != desired {
			return false, fmt.Errorf(
				"field %q already has value %q which differs from desired %q; refusing to override potential user configuration",
				field, current, desired,
			)
		}
		if current == desired && wasTracked {
			return false, nil
		}
		t.fields[field] = desired
		return true, nil

	case ConflictDefer:
		if userModified {
			delete(t.fields, field)
			return false, nil
		}
		// Not tracked and already has a value — assume user/other set it, don't claim.
		if !wasTracked && current != "" {
			return false, nil
		}
		if current == desired && wasTracked {
			return false, nil
		}
		t.fields[field] = desired
		return current != desired, nil

	case ConflictOverride:
		t.fields[field] = desired
		return current != desired, nil
	}

	return false, fmt.Errorf("unknown conflict policy: %d", policy)
}

// Release removes operator ownership of a field. Call this when a controller
// no longer needs to manage a field (e.g., during cleanup/finalization).
//
// Call Flush after all Manage/Release calls to write changes back to the object.
func (t *Tracker) Release(field string) {
	delete(t.fields, field)
}

// IsManaged returns true if the operator is currently tracking the given field.
func (t *Tracker) IsManaged(field string) bool {
	_, ok := t.fields[field]
	return ok
}

// ManagedFields returns a copy of all currently tracked field names and their last-written values.
func (t *Tracker) ManagedFields() map[string]string {
	out := make(map[string]string, len(t.fields))
	maps.Copy(out, t.fields)
	return out
}

// MigrateAnnotation migrates a legacy per-field annotation into the consolidated tracker.
// If the old annotation exists on the object, its value is adopted into the tracker and
// the old annotation is removed from the object. This enables incremental migration from
// the old per-field annotation pattern.
func (t *Tracker) MigrateAnnotation(obj client.Object, field, oldAnnotationKey string) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return
	}
	val, ok := annotations[oldAnnotationKey]
	if !ok {
		return
	}
	if _, exists := t.fields[field]; !exists {
		t.fields[field] = val
	}
	delete(annotations, oldAnnotationKey)
	obj.SetAnnotations(annotations)
}

// Flush writes the tracker's state back to the object's annotations.
// Must be called after all Manage/Release calls and before patching the object.
func (t *Tracker) Flush(obj client.Object) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	if len(t.fields) == 0 {
		delete(annotations, t.annotationKey)
	} else {
		raw, _ := json.Marshal(t.fields)
		annotations[t.annotationKey] = string(raw)
	}
	obj.SetAnnotations(annotations)
}

// FormatValue converts a value to its string representation for use with Manage.
// Returns "" for nil values and nil pointers. For pointer types, dereferences before
// formatting. Uses fmt.Sprint for primitive types and JSON for structs/maps/slices.
func FormatValue(v any) string {
	if v == nil {
		return ""
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return ""
		}
		return FormatValue(val.Elem().Interface())
	}
	switch val.Kind() {
	case reflect.Struct, reflect.Map, reflect.Slice:
		raw, _ := json.Marshal(v)
		return string(raw)
	default:
		return fmt.Sprint(v)
	}
}
