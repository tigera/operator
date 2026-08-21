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

package extensions

import (
	"context"

	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// FactoryInputs is what the operator knows by the time it can build a variant's
// extensions: the variant an Installation asked for, a clientset, and the CRD options
// the variant's own controllers care about.
type FactoryInputs struct {
	Variant   operatorv1.ProductVariant
	Clientset kubernetes.Interface

	ManageCRDs bool
	UseV3CRDs  bool
}

// Factory builds a variant's extensions. The operator calls it once the variant is
// resolved, so a variant's main supplies the function rather than the result.
type Factory func(ctx context.Context, in FactoryInputs) (Extensions, error)
