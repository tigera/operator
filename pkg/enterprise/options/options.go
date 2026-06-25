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

package options

import "github.com/tigera/operator/pkg/controller/contexts"

// Options is the Calico Enterprise controller-phase options. The extension build
// computes it once at startup (see extensions.Set.ComputeOptions) and its
// controller hooks read it back off the ControllerContext via From. It lives in
// its own leaf package so the hooks and the operator's main can both reference it.
type Options struct {
	// MultiTenant reports whether the operator runs in multi-tenant mode.
	MultiTenant bool
}

// From returns the enterprise options carried on the controller context, or the
// zero value when none are set.
func From(cc contexts.ControllerContext) Options {
	o, _ := cc.Options.(Options)
	return o
}
