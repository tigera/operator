// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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

	"github.com/go-logr/logr"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
)

func (r *ReconcileLogStorage) createESMetrics(
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	reqLogger logr.Logger,
	clusterConfig *relasticsearch.ClusterConfig,
	ctx context.Context,
	hdler utils.ComponentHandler,
	serverKeyPair certificatemanagement.KeyPairInterface,
	trustedBundle certificatemanagement.TrustedBundle,
	usePSP bool,
) (reconcile.Result, bool, error) {
	esMetricsSecret, err := utils.GetSecret(context.Background(), r.client, esmetrics.ElasticsearchMetricsSecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve Elasticsearch metrics user secret.", err, reqLogger)
		return reconcile.Result{}, false, err
	} else if esMetricsSecret == nil {
		reqLogger.Info("Waiting for elasticsearch metrics secrets to become available")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for elasticsearch metrics secrets to become available", nil, reqLogger)
		return reconcile.Result{}, false, nil
	}

	esMetricsCfg := &esmetrics.Config{
		Installation:         install,
		PullSecrets:          pullSecrets,
		ESConfig:             clusterConfig,
		ESMetricsCredsSecret: esMetricsSecret,
		ClusterDomain:        r.clusterDomain,
		ServerTLS:            serverKeyPair,
		TrustedBundle:        trustedBundle,
		UsePSP:               usePSP,
	}
	esMetricsComponent := esmetrics.ElasticsearchMetrics(esMetricsCfg)
	if err = imageset.ApplyImageSet(ctx, r.client, variant, esMetricsComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, esMetricsComponent, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	return reconcile.Result{}, true, nil
}
