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

package apiserver

import (
	"context"
	"fmt"

	admregv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/render"
)

// needsConfigMapParamsAccess reports whether the API server needs cluster-wide ConfigMap read access
// for its ValidatingAdmissionPolicy plugin. Once granted, access is kept: the API server holds on to
// the ConfigMap watch after the policy is gone, and toggling access on policy churn could be used to
// break it repeatedly.
func needsConfigMapParamsAccess(ctx context.Context, c client.Client) (bool, error) {
	err := c.Get(ctx, client.ObjectKey{Name: render.ConfigMapParamsAccessName}, &rbacv1.ClusterRole{})
	if err == nil {
		return true, nil
	}
	if !errors.IsNotFound(err) {
		return false, fmt.Errorf("getting ClusterRole %s: %w", render.ConfigMapParamsAccessName, err)
	}

	bindings := &admregv1.ValidatingAdmissionPolicyBindingList{}
	if err := c.List(ctx, bindings); err != nil {
		return false, fmt.Errorf("listing ValidatingAdmissionPolicyBindings: %w", err)
	}
	for _, b := range bindings.Items {
		policy := &admregv1.ValidatingAdmissionPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Name: b.Spec.PolicyName}, policy); err != nil {
			if errors.IsNotFound(err) {
				// The plugin ignores bindings to missing policies.
				continue
			}
			return false, fmt.Errorf("getting ValidatingAdmissionPolicy %s: %w", b.Spec.PolicyName, err)
		}
		if pk := policy.Spec.ParamKind; pk != nil && pk.APIVersion == "v1" && pk.Kind == "ConfigMap" {
			return true, nil
		}
	}
	return false, nil
}
