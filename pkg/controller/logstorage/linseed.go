// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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

package logstorage

import (
	"context"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

func (r *ReconcileLogStorage) createLinseed(
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	ctx context.Context,
	linseedKeyPair certificatemanagement.KeyPairInterface,
	tokenKeyPair certificatemanagement.KeyPairInterface,
	trustedBundle certificatemanagement.TrustedBundle,
	managementCluster bool,
	usePSP bool,
	esClusterConfig *relasticsearch.ClusterConfig,
) (reconcile.Result, bool, error) {

	cfg := &linseed.Config{
		Installation:      install,
		PullSecrets:       pullSecrets,
		TrustedBundle:     trustedBundle,
		ClusterDomain:     r.clusterDomain,
		KeyPair:           linseedKeyPair,
		TokenKeyPair:      tokenKeyPair,
		UsePSP:            usePSP,
		ESClusterConfig:   esClusterConfig,
		ManagementCluster: managementCluster,
	}

	linseedComponent := linseed.Linseed(cfg)

	if err := imageset.ApplyImageSet(ctx, r.client, variant, linseedComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	for _, comp := range []render.Component{linseedComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return reconcile.Result{}, false, err
		}
	}
	return reconcile.Result{}, true, nil
}
