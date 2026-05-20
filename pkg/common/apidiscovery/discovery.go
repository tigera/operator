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

// Package apidiscovery exposes the served versions of API kinds that the operator cares about.
// A snapshot is taken once at startup so controllers can ask which version of an API is available
// (and use that to choose between typed Go imports) without issuing further discovery requests at
// reconcile time.
package apidiscovery

import (
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Discovery is a snapshot of which API versions a cluster serves for a pre-registered set of
// GroupKinds. Lookups are pure map reads; no API calls are made after construction.
type Discovery struct {
	versions map[schema.GroupKind]string
}

// New consults the supplied RESTMapper for each tracked GroupKind and records the preferred
// served version. GroupKinds not served by the cluster (or unknown to the RESTMapper) map to the
// empty string. Callers should pass every GroupKind that any controller will later look up; only
// pre-registered kinds will return a non-empty version, so this list is the single place to add a
// new API the operator wants to discover.
func New(mapper meta.RESTMapper, tracked []schema.GroupKind) *Discovery {
	d := &Discovery{versions: map[schema.GroupKind]string{}}
	for _, gk := range tracked {
		// RESTMappings returns mappings sorted by the group's preferred-version order from
		// discovery — for a GA API like v1+v1beta1, v1 comes first.
		mappings, err := mapper.RESTMappings(gk)
		if err != nil || len(mappings) == 0 {
			continue
		}
		d.versions[gk] = mappings[0].GroupVersionKind.Version
	}
	return d
}

// ServedVersion returns the preferred served version for the given GroupKind, or "" if the kind
// is not served by the cluster (or was not pre-registered in the tracked list passed to New).
func (d *Discovery) ServedVersion(group, kind string) string {
	if d == nil {
		return ""
	}
	return d.versions[schema.GroupKind{Group: group, Kind: kind}]
}

// NewStatic constructs a Discovery from an explicit version map. Intended for tests.
func NewStatic(versions map[schema.GroupKind]string) *Discovery {
	cp := make(map[schema.GroupKind]string, len(versions))
	for k, v := range versions {
		cp[k] = v
	}
	return &Discovery{versions: cp}
}
