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

package utils

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/render"
)

// APIServerMigrationInProgress reports whether the cluster is mid-way through the
// allow-tigera -> calico-system apiserver migration performed on a direct
// Calico Enterprise 3.21.x -> 3.23.x upgrade: the deprecated "allow-tigera" Tier
// still exists AND the calico-apiserver Deployment is not yet Ready in
// calico-system. Controllers use it to sequence the migration bridge and to
// suppress teardown of the transitional policies until the apiserver is stable.
//
// It reads the "allow-tigera" Tier and the calico-apiserver Deployment through the
// caller's cached client; every controller that calls it already watches those
// types.
func APIServerMigrationInProgress(ctx context.Context, c client.Client) (bool, error) {
	tier := &v3.Tier{}
	if err := c.Get(ctx, client.ObjectKey{Name: render.DeprecatedAPIServerTierName}, tier); err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			// No deprecated tier: fresh install or already-migrated cluster.
			return false, nil
		}
		return false, err
	}

	// The deprecated tier exists. Migration is in progress until calico-apiserver
	// is Ready in calico-system.
	d := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: render.APIServerName, Namespace: render.APIServerNamespace}, d)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Not created (or moved) yet.
			return true, nil
		}
		return false, err
	}
	return d.Status.ReadyReplicas == 0, nil
}
