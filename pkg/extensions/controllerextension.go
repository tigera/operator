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

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
)

// ControllerExtension is a variant's controller-side reconcile hook. The
// installation controller calls it to do the work core can't: reject
// unsupported configuration (Validate) and create the controller-side artifacts
// - certificates, trusted bundle additions - that feed the render context
// (ExtendContext). A variant registers at most one; the core operator registers
// none and runs with the base behavior.
type ControllerExtension interface {
	// Validate rejects configuration the variant does not support, before any
	// rendering happens.
	Validate(cc ControllerContext) error

	// ExtendContext does the controller-side work the render modifiers can't
	// (creating certificates, extending the trusted bundle) and returns the
	// RenderContext those modifiers read, or an error that aborts the reconcile.
	ExtendContext(cc ControllerContext) (RenderContext, error)
}

// ControllerContext is the controller-phase context, the corollary to the
// render-phase RenderContext. It is the embedded RenderContext (the same data
// the render phase sees) plus the controller-side machinery a ControllerExtension
// needs to produce artifacts: a client, a certificate manager, a context. Those
// deps live here, not on RenderContext, so the modifiers that read RenderContext
// can't do I/O - they only transform objects.
//
// The controller fills the embedded RenderContext's data fields and the deps;
// ExtendContext does its work, sets the produced artifacts (e.g.
// NodePrometheusTLS) on the embedded context, and returns it.
type ControllerContext struct {
	RenderContext

	Ctx                context.Context
	Client             client.Client
	CertificateManager certificatemanager.CertificateManager
}
