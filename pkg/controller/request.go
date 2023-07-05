// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package controller

import (
	"github.com/tigera/operator/pkg/common"
	"k8s.io/apimachinery/pkg/types"
)

func NewRequest(r types.NamespacedName, mt bool, defaultNS string) Request {
	return Request{
		NamespacedName:        r,
		multiTenant:           mt,
		singleTenantNamespace: defaultNS,
	}
}

// Request wraps a standard request and provides utilities to support both
// single and multi-tenant operator modes.
type Request struct {
	// The name and namespace of the object that triggered this request.
	types.NamespacedName

	// Whether the operator is running in multi-tenant or single-tenant mode.
	multiTenant bool

	// The namespace to use for single-tenant installations of this component.
	singleTenantNamespace string
}

// InstallNamespace returns the namespace that components will be installed into.
// for single-tenant clusters, this is tigera-manager. For multi-tenancy, this
// will be the tenant's namespace.
func (r *Request) InstallNamespace() string {
	if !r.multiTenant {
		return r.singleTenantNamespace
	}
	return r.NamespacedName.Namespace
}

// TruthNamespace returns the namespace to use as the source of truth for storing data.
// For single-tenant installs, this is the tigera-operator namespace.
// For multi-tenant installs, this is tenant's namespace.
func (r *Request) TruthNamespace() string {
	if !r.multiTenant {
		return common.OperatorNamespace()
	}
	return r.NamespacedName.Namespace
}
