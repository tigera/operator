package logstorage

import (
	"context"
	"fmt"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"k8s.io/apimachinery/pkg/api/errors"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
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
	clusterDomain string,
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

	certificateManager, err := certificatemanagement.CreateCertificateManager(r.client, install.CertificateManagement, r.clusterDomain)
	if err != nil {
		log.Error(err, "unable to create the Tigera CA")
		r.status.SetDegraded("unable to create the Tigera CA", err.Error())
		return reconcile.Result{}, false, err
	}
	prometheusCertificate, err := certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Prometheus secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Prometheus secrets are not available yet, waiting until they become available", "")
			return reconcile.Result{RequeueAfter: 5 * time.Second}, false, nil
		} else {
			log.Error(err, "Failed to get certificate")
			r.status.SetDegraded("Failed to get certificate", err.Error())
			return reconcile.Result{}, false, err
		}
	}
	trustedBundle := certificatemanagement.CreateTrustedBundle(certificateManager, prometheusCertificate)

	serverTLS, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		esmetrics.ElasticsearchMetricsServerTLSSecret,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(esmetrics.ElasticsearchMetricsName, render.ElasticsearchNamespace, clusterDomain))
	if err != nil {
		log.Error(err, "Error finding or creating TLS certificate")
		r.status.SetDegraded("Error finding or creating TLS certificate", err.Error())
		return reconcile.Result{}, false, err
	}

	esMetricsCfg := &esmetrics.Config{
		Installation:         install,
		PullSecrets:          pullSecrets,
		ESConfig:             clusterConfig,
		ESMetricsCredsSecret: esMetricsSecret,
		ESCertSecret:         publicCertSecretESCopy,
		ClusterDomain:        r.clusterDomain,
		ServerTLS:            serverTLS,
		TrustedBundle:        trustedBundle,
	}
	esMetricsComponent := esmetrics.ElasticsearchMetrics(esMetricsCfg)
	components := []render.Component{esMetricsComponent,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			ServiceAccountName: esmetrics.ElasticsearchMetricsName,
			Namespace:          render.ElasticsearchNamespace,
			KeyPairs:           []certificatemanagement.KeyPair{serverTLS},
			TrustedBundle:      trustedBundle,
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
