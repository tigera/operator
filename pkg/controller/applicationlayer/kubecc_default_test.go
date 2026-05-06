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
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestDefaultApplicationLayerKubeCC_FillsWhenNil verifies that when
// KubeControllersConfiguration.spec.controllers.applicationLayer is nil
// the helper sets it to a non-nil default.
//
// TODO(Plan 1): Once ControllersConfig.ApplicationLayer lands in
// github.com/tigera/api, replace this with a real assertion that the
// field is set to {ReconcilerPeriod: 30s}.
func TestDefaultApplicationLayerKubeCC_FillsWhenNil(t *testing.T) {
	// Until Plan 1 lands the helper is a no-op. Verify it returns nil (no error).
	cli := fake.NewClientBuilder().Build()
	require.NoError(t, defaultApplicationLayerKubeCC(context.Background(), cli))
}

// TestDefaultApplicationLayerKubeCC_IdempotentWhenNonNil verifies that the
// helper does not overwrite an existing applicationLayer configuration.
//
// TODO(Plan 1): Once ControllersConfig.ApplicationLayer lands in
// github.com/tigera/api, replace this with a real assertion that a
// pre-existing custom ReconcilerPeriod is preserved after a second call.
func TestDefaultApplicationLayerKubeCC_IdempotentWhenNonNil(t *testing.T) {
	// Until Plan 1 lands the helper is a no-op. Two consecutive calls should
	// both return nil (idempotent / no error).
	cli := fake.NewClientBuilder().Build()
	require.NoError(t, defaultApplicationLayerKubeCC(context.Background(), cli))
	require.NoError(t, defaultApplicationLayerKubeCC(context.Background(), cli))
}
