// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

func (r *ReconcileLogStorage) createEsMetrics(
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	reqLogger logr.Logger,
	clusterConfig *relasticsearch.ClusterConfig,
	ctx context.Context,
	hdler utils.ComponentHandler,
	clusterDomain string,
	trustedBundle certificatemanagement.TrustedBundle,
) (reconcile.Result, bool, error) {
	esMetricsSecret, err := utils.GetSecret(context.Background(), r.client, esmetrics.ElasticsearchMetricsSecret, common.OperatorNamespace())
	if err != nil {
		reqLogger.Error(err, "Failed to retrieve Elasticsearch metrics user secret.")
		r.status.SetDegraded("Failed to retrieve Elasticsearch metrics user secret.", err.Error())
		return reconcile.Result{}, false, err
	} else if esMetricsSecret == nil {
		reqLogger.Info("Waiting for elasticsearch metrics secrets to become available")
		r.status.SetDegraded("Waiting for elasticsearch metrics secrets to become available", "")
		return reconcile.Result{}, false, nil
	}

	certificateManager, err := certificatemanager.Create(r.client, install, r.clusterDomain)
	if err != nil {
		reqLogger.Error(err, "unable to create the Tigera CA")
		r.status.SetDegraded("Unable to create the Tigera CA", err.Error())
		return reconcile.Result{}, false, err
	}

	serverTLS, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		esmetrics.ElasticsearchMetricsServerTLSSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(esmetrics.ElasticsearchMetricsName, render.ElasticsearchNamespace, clusterDomain))
	if err != nil {
		reqLogger.Error(err, "Error finding or creating TLS certificate")
		r.status.SetDegraded("Error finding or creating TLS certificate", err.Error())
		return reconcile.Result{}, false, err
	}

	esMetricsCfg := &esmetrics.Config{
		Installation:         install,
		PullSecrets:          pullSecrets,
		ESConfig:             clusterConfig,
		ESMetricsCredsSecret: esMetricsSecret,
		ClusterDomain:        r.clusterDomain,
		ServerTLS:            serverTLS,
		TrustedBundle:        trustedBundle,
	}
	esMetricsComponent := esmetrics.ElasticsearchMetrics(esMetricsCfg)
	components := []render.Component{esMetricsComponent,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       render.ElasticsearchNamespace,
			ServiceAccounts: []string{esmetrics.ElasticsearchMetricsName},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(serverTLS, true, true),
			},
			TrustedBundle: nil, // The trusted bundle should have already been rendered by the logstorage_controller.go for es-gateway.
		}),
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, esMetricsComponent); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, false, err
	}

	for _, comp := range components {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Error creating / updating resource", err.Error())
			return reconcile.Result{}, false, err
		}
	}

	return reconcile.Result{}, true, nil
}
