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

package applicationlayer

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// defaultApplicationLayerKubeCC ensures that
// KubeControllersConfiguration.spec.controllers.applicationLayer is non-nil
// so that kube-controllers wires the ApplicationLayer subsystem.
//
// The function is idempotent: if the field is already set it returns without
// touching the object.
//
// TODO(Plan 1): The ApplicationLayerControllerConfig type and the
// ControllersConfig.ApplicationLayer field must be added to
// github.com/tigera/api before this helper can perform a real update.
// Until that dependency lands, this is a deliberate no-op that compiles
// cleanly and can be extended in place once Plan 1 is merged.
func defaultApplicationLayerKubeCC(_ context.Context, _ client.Client) error {
	// No-op pending Plan 1 (tigera/api: add ControllersConfig.ApplicationLayer).
	return nil
}
