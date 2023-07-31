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

package linseed

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
)

func (r *LinseedSubController) createESMetrics(
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	managementClusterConnection *operatorv1.ManagementClusterConnection,
	pullSecrets []*corev1.Secret,
	reqLogger logr.Logger,
	clusterConfig *relasticsearch.ClusterConfig,
	ctx context.Context,
	hdler utils.ComponentHandler,
	trustedBundle certificatemanagement.TrustedBundleRO,
	usePSP bool,
	cm certificatemanager.CertificateManager,
) error {
	// Only install ES metrics if this is not a managed cluster.
	if managementClusterConnection != nil {
		return nil
	}

	esMetricsSecret, err := utils.GetSecret(context.Background(), r.client, esmetrics.ElasticsearchMetricsSecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve Elasticsearch metrics user secret.", err, reqLogger)
		return err
	} else if esMetricsSecret == nil {
		reqLogger.Info("Waiting for elasticsearch metrics secrets to become available")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for elasticsearch metrics secrets to become available", nil, reqLogger)
		return nil
	}

	// Getthe ES metrics server keypair. This will have previously been created by the ES secrets controller.
	serverKeyPair, err := cm.GetKeyPair(r.client, esmetrics.ElasticsearchMetricsServerTLSSecret, render.ElasticsearchNamespace)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Linseed KeyPair", err, log)
		return err
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
		return err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, esMetricsComponent, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return err
	}

	return nil
}
