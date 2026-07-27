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

// Package controller holds the controller-phase inputs passed between a
// controller's reconcile and a variant extension. They live here, not in the
// extensions package, because they are controller concepts (the data and
// machinery a controller gathers), not part of the extension mechanism itself -
// the extensions package consumes them.
package controller

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/render"
)

// Name identifies the controller a ControllerExtension extends, so a variant can
// register a different hook per controller. Use the constants below rather than
// bare strings so registration and lookup stay in sync.
type Name string

const (
	Installation      Name = "installation"
	Windows           Name = "windows"
	APIServer         Name = "apiserver"
	ClusterConnection Name = "clusterconnection"
)

// Inputs is what a controller hands its variant extension, the corollary to the
// render-phase render.Inputs. It is the embedded render.Inputs (the same data the
// render phase sees) plus the controller-side machinery a ControllerExtension needs
// to produce artifacts: a client and a certificate manager. Those deps live here,
// not on render.Inputs, so the modifiers that read render.Inputs can't do I/O -
// they only transform objects.
//
// Controller names which controller is reconciling, selecting that controller's
// extension hook. The controller fills the embedded render.Inputs data fields, the
// deps, and Controller; ExtendInputs does its work, sets the produced artifacts on
// the embedded render.Inputs, and returns it.
type Inputs struct {
	render.Inputs

	// Controller identifies the reconciling controller, selecting its hook.
	Controller Name

	Client             client.Client
	CertificateManager certificatemanager.CertificateManager

	// Options carries the active variant's computed controller-phase options. The
	// extension Set fills it before dispatching to a hook (Validate/ExtendInputs).
	// It's opaque so core never names a variant-only option; the variant's hooks
	// assert it back out. Nil for the core operator.
	Options any
}
