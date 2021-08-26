package logstorage

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
)

func (r *ReconcileLogStorage) createEsGateway(
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	esAdminUserSecret *corev1.Secret,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	ctx context.Context,
) (reconcile.Result, bool, error) {
	gatewayCertSecret, publicCertSecret, customerProvidedCert, err := common.GetESGatewayCertificateSecrets(ctx, install, r.client, r.clusterDomain, log)
	if err != nil {
		reqLogger.Error(err, "failed to create Elasticsearch Gateway secrets")
		r.status.SetDegraded("Failed to create Elasticsearch Gateway secrets", err.Error())
		return reconcile.Result{}, false, err
	}

	kibanaInternalCertSecret, err := utils.GetSecret(ctx, r.client, render.KibanaInternalCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Waiting for internal Kibana tls certificate secret to be available", "")
		return reconcile.Result{}, false, nil
	}

	esInternalCertSecret, err := utils.GetSecret(ctx, r.client, relasticsearch.InternalCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Waiting for internal Kibana tls certificate secret to be available", "")
		return reconcile.Result{}, false, nil
	}

	kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, err := common.CreateKubeControllersSecrets(ctx, esAdminUserSecret, r.client)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Failed to create kube-controllers secrets for Elasticsearch gateway", "")
		return reconcile.Result{}, false, err
	}

	cfg := &esgateway.Config{
		Installation:               install,
		PullSecrets:                pullSecrets,
		CertSecrets:                []*corev1.Secret{gatewayCertSecret, publicCertSecret},
		KubeControllersUserSecrets: []*corev1.Secret{kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret},
		KibanaInternalCertSecret:   kibanaInternalCertSecret,
		EsInternalCertSecret:       esInternalCertSecret,
		ClusterDomain:              r.clusterDomain,
	}

	esGatewayComponent := esgateway.EsGateway(cfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, false, err
	}

	if !customerProvidedCert {
		if err := hdler.CreateOrUpdateOrDelete(ctx, render.Secrets([]*corev1.Secret{gatewayCertSecret}), r.status); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Error creating / updating resource", err.Error())
			return reconcile.Result{}, false, err
		}
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, esGatewayComponent, r.status); err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, false, err
	}

	return reconcile.Result{}, true, nil
}
