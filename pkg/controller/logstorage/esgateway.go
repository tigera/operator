package logstorage

import (
	"context"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	corev1 "k8s.io/api/core/v1"
)

func (r *ReconcileLogStorage) renderEsGateway(
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	ctx context.Context,
) error {
	gatewayCertSecret, publicCertSecret, customerProvidedCert, err := common.GetESGatewayCertificateSecrets(ctx, install, r.client, r.clusterDomain, log)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Failed to create Elasticsearch Gateway secrets", err.Error())
		return err
	}

	kibanaInternalCertSecret, err := utils.GetSecret(ctx, r.client, render.KibanaInternalCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Waiting for internal Kibana tls certificate secret to be available", "")
		return err
	}

	esInternalCertSecret, err := utils.GetSecret(ctx, r.client, relasticsearch.InternalCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Waiting for internal Kibana tls certificate secret to be available", "")
		return err
	}

	kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, err := common.CreateKubeControllersSecrets(ctx, r.esAdminUserSecret, r.client)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Failed to create kube-controllers secrets for Elasticsearch gateway", "")
		return err
	}

	c := &esgateway.Config{
		Installation:               install,
		PullSecrets:                pullSecrets,
		CertSecrets:                []*corev1.Secret{gatewayCertSecret, publicCertSecret},
		KubeControllersUserSecrets: []*corev1.Secret{kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret},
		KibanaInternalCertSecret:   kibanaInternalCertSecret,
		EsInternalCertSecret:       esInternalCertSecret,
		ClusterDomain:              r.clusterDomain,
	}

	esGatewayComponent := esgateway.EsGateway(c)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return err
	}

	if !customerProvidedCert {
		if err := hdler.CreateOrUpdateOrDelete(ctx, render.Secrets([]*corev1.Secret{gatewayCertSecret}), r.status); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Error creating / updating resource", err.Error())
			return err
		}
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, esGatewayComponent, r.status); err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return err
	}

	return nil
}
