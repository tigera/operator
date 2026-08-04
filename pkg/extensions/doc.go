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
// A Registry holds the extensions for the one variant the operator resolved at
// startup, so nothing here re-checks the variant and a lookup that finds nothing
// hands back a no-op. It stores two kinds of extension:
//
// A ControllerExtension is the controller-side hook. It runs once per reconcile
// in the installation controller, has cluster access (Client,
// CertificateManager) via controller.Inputs, and does the side-effecting work a
// pure render hook can't: rejecting unsupported config (Validate) and creating
// certificates / extending the trusted bundle (ExtendInputs). It returns the
// render.Inputs passed on to the render phase.
//
// Per-component modifiers are the render phase: pure hooks that run after a
// component builds its objects. An image override swaps the component's image;
// a modifier post-processes the rendered objects at the componentHandler.
// Register one with RegisterModifier, passing the component's key: the key pins the
// type of the inputs the modifier receives, so one written against a different
// component won't compile.
//
// controller.Inputs and render.Inputs are a pair: controller.Inputs carries a
// render.Inputs plus the cluster-access deps, which is why modifiers, given only
// a render.Inputs, can't do I/O.
//
// A variant wires up its controller extension and modifiers in one place at
// startup - see pkg/enterprise.
package extensions
