package logstorage

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
)

func (r *ReconcileLogStorage) createEsMetrics(
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	reqLogger logr.Logger,
	clusterConfig *relasticsearch.ClusterConfig,
	ctx context.Context,
	hdler utils.ComponentHandler,
) (reconcile.Result, bool, error) {
	esMetricsSecret, err := utils.GetSecret(context.Background(), r.client, esmetrics.ElasticsearchMetricsSecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded("Failed to retrieve Elasticsearch metrics user secret.", err.Error())
		return reconcile.Result{}, false, err
	} else if esMetricsSecret == nil {
		r.status.SetDegraded("Waiting for elasticsearch metrics secrets to become available", "")
		err = fmt.Errorf("waiting for elasticsearch metrics secrets to become available")
		return reconcile.Result{}, false, nil
	}

	publicCertSecretESCopy, err := utils.GetSecret(context.Background(), r.client, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace)
	if err != nil {
		r.status.SetDegraded("Failed to retrieve Elasticsearch public cert secret.", err.Error())
		return reconcile.Result{}, false, err
	} else if publicCertSecretESCopy == nil {
		r.status.SetDegraded("Waiting for elasticsearch public cert secret to become available", "")
		err = fmt.Errorf("waiting for elasticsearch public cert secret to become available")
		return reconcile.Result{}, false, nil
	}

	esMetricsComponent := esmetrics.ElasticsearchMetrics(install, pullSecrets, clusterConfig, esMetricsSecret, publicCertSecretESCopy, r.clusterDomain)
	if err = imageset.ApplyImageSet(ctx, r.client, variant, esMetricsComponent); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, false, err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, esMetricsComponent, r.status); err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, false, err
	}

	return reconcile.Result{}, true, nil
}
