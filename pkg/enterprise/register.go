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

package enterprise

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/extensions"
)

// New builds the extension Set for the in-repo Calico Enterprise variant: the
// controller extension, every component modifier, and the image overrides. The
// operator is handed this Set at startup (the core operator is handed none).
// After the monorepo split this is what calico-private's main will construct
// instead.
func New() *extensions.Set {
	s := extensions.NewSet()

	ent := s.Variant(operatorv1.CalicoEnterprise)
	ent.Controller(extensions.InstallationController, coreControllerExtension{})
	ent.Controller(extensions.WindowsController, windowsControllerExtension{})
	registerTypha(ent)
	registerNode(ent)
	registerWindows(ent)
	registerGuardian(ent)
	registerAPIServer(ent)

	// When the enterprise operator manages a Calico installation, clean up the
	// Enterprise objects left behind by a prior Enterprise installation.
	cal := s.Variant(operatorv1.Calico)
	registerAPIServerCleanup(cal)

	return s
}
