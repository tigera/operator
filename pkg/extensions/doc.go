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

// Package extensions is the seam other product variants (today just Calico
// Enterprise) use to layer variant-specific behavior onto the core operator's
// render output, so core code never branches on variant.
//
// A Set holds the extensions for every variant. Per reconcile the controller
// selects one Variant from the installation's variant, so a registered hook only
// ever runs for its own variant and never re-checks it. A Variant bundles two
// kinds of extension:
//
// A ControllerExtension is the controller-side hook. It runs once per reconcile
// in the installation controller, has cluster access (Client,
// CertificateManager) via the ControllerContext, and does the side-effecting
// work a pure render hook can't: rejecting unsupported config (Validate) and
// creating certificates / extending the trusted bundle (ExtendContext). It
// returns the RenderContext, the read-only baton passed to the render phase.
//
// Per-component modifiers are the render phase: pure hooks that run after a
// component builds its objects. An image override swaps the component's image
// (resolved during ResolveImages); a Modifier post-processes the rendered
// objects (run at the componentHandler, which renders the decorated component).
// Register a modifier with Variant.Modify, or with RegisterModifier when it
// needs the component's own typed config.
//
// ControllerContext (controller phase) and RenderContext (render phase) are a
// pair: ControllerContext embeds RenderContext and adds the cluster-access deps,
// which is why modifiers, given only a RenderContext, can't do I/O.
//
// A variant wires up its controller extension and modifiers in one place at
// startup - see pkg/enterprise.
package extensions
