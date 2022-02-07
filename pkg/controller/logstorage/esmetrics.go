package logstorage

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/openshift/library-go/pkg/crypto"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/tls"
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

	trustedBundle, err := utils.GetPrometheusCertificateBundle(ctx, r.client, render.ElasticsearchNamespace, install.CertificateManagement)
	if trustedBundle == nil {
		r.status.SetDegraded("Waiting for the prometheus client secret to become available", "")
		err = fmt.Errorf("waiting for the prometheus client secret to become available")
		return reconcile.Result{}, false, nil
	} else if err != nil {
		log.Error(err, "Unable to create a metrics certificate bundle")
		r.status.SetDegraded("Unable to create a metrics certificate bundle", err.Error())
		return reconcile.Result{}, false, err
	}
	var serverTLS *corev1.Secret
	if install.CertificateManagement == nil {
		serverTLS, err = utils.ValidateCertPair(r.client,
			common.OperatorNamespace(),
			esmetrics.ElasticsearchMetricsServerTLSSecret,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
		)
		if err != nil {
			log.Error(err, "Invalid TLS Cert")
			r.status.SetDegraded("Error validating TLS certificate", err.Error())
			return reconcile.Result{}, false, err
		}

		if serverTLS == nil {
			dnsNames := dns.GetServiceDNSNames(esmetrics.ElasticsearchMetricsName, render.ElasticsearchNamespace, clusterDomain)
			serverTLS, err = rsecret.CreateTLSSecret(nil,
				esmetrics.ElasticsearchMetricsServerTLSSecret,
				common.OperatorNamespace(),
				corev1.TLSPrivateKeyKey,
				corev1.TLSCertKey,
				rmeta.DefaultCertificateDuration,
				[]crypto.CertificateExtensionFunc{tls.SetServerAuth},
				dnsNames...,
			)
			if err != nil {
				log.Error(err, "Error creating TLS certificate")
				r.status.SetDegraded("Error creating TLS certificate", err.Error())
				return reconcile.Result{}, false, err
			}
		}
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
	components := []render.Component{esMetricsComponent}
	if serverTLS != nil {
		oprIssued, err := utils.IsCertOperatorIssued(serverTLS.Data[corev1.TLSCertKey])
		if err != nil {
			reqLogger.Error(err, "Error checking certificate issuer")
			r.status.SetDegraded("Error checking certificate issuer", err.Error())
		}
		if oprIssued {
			components = append(components, render.NewPassthrough(serverTLS))
		}
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
