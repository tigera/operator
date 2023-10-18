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

package utils

import (
	"context"

	"github.com/tigera/operator/pkg/common"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewSingleTenantNamespaceHelper(ns string) NamespaceHelper {
	return &namespacer{
		multiTenant:           false,
		singleTenantNamespace: ns,
	}
}

func NewNamespaceHelper(mt bool, singleTenantNS, multiTenantNS string) NamespaceHelper {
	return &namespacer{
		multiTenant:           mt,
		singleTenantNamespace: singleTenantNS,
		multiTenantNamespace:  multiTenantNS,
	}
}

type NamespaceHelper interface {
	// InstallNamespace returns the namespace that components will be installed into.
	// for single-tenant clusters, this is generally a well-known namespace of the form tigera-*.
	// For multi-tenant clusters, this is the tenant's namespace.
	InstallNamespace() string

	// TruthNamespace returns the namespace to use as the source of truth for storing data.
	// For single-tenant installs, this is the tigera-operator namespace.
	// For multi-tenant installs, this is tenant's namespace.
	TruthNamespace() string

	// TenantNamespaces returns all namespaces in the cluster for this component, across all tenants. This is useful when
	// binding global resources to potentially several different Tenant namespaces.
	// For single-tenant clusters, this simply returns the InstallNamespace.
	TenantNamespaces(client.Client) ([]string, error)
}

type namespacer struct {
	multiTenant           bool
	singleTenantNamespace string
	multiTenantNamespace  string
}

func (r *namespacer) InstallNamespace() string {
	if r.multiTenant {
		return r.multiTenantNamespace
	}
	return r.singleTenantNamespace
}

func (r *namespacer) TruthNamespace() string {
	if r.multiTenant {
		return r.multiTenantNamespace
	}
	return common.OperatorNamespace()
}

func (r *namespacer) TenantNamespaces(c client.Client) ([]string, error) {
	if r.multiTenant {
		return TenantNamespaces(context.Background(), c)
	}
	return []string{r.InstallNamespace()}, nil
}
