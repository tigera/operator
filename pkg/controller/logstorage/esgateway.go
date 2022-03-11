package logstorage

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	lscommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
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
	certificateManager certificatemanager.CertificateManager,
) (reconcile.Result, bool, error) {
	svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	svcDNSNames = append(svcDNSNames, dns.GetServiceDNSNames(esgateway.ServiceName, render.ElasticsearchNamespace, r.clusterDomain)...)
	gatewayCertSecret, err := certificateManager.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), svcDNSNames)
	if err != nil {
		log.Error(err, "Error creating TLS certificate")
		r.status.SetDegraded("Error creating TLS certificate", err.Error())
		return reconcile.Result{}, false, err
	}
	kibanaCertificate, err := certificateManager.GetCertificate(r.client, render.TigeraKibanaCertSecret, common.OperatorNamespace())
	if err != nil {
		reqLogger.Error(err, "failed to get Kibana tls certificate secret")
		r.status.SetDegraded("Failed to get Kibana tls certificate secret", err.Error())
		return reconcile.Result{}, false, err
	} else if kibanaCertificate == nil {
		reqLogger.Info("Waiting for internal Kibana tls certificate secret to be available")
		r.status.SetDegraded("Waiting for internal Kibana tls certificate secret to be available", "")
		return reconcile.Result{}, false, nil
	}
	esInternalCertificate, err := certificateManager.GetCertificate(r.client, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace())
	if err != nil {
		reqLogger.Error(err, "failed to get Elasticsearch tls certificate secret")
		r.status.SetDegraded("Failed to get Elasticsearch tls certificate secret", err.Error())
		return reconcile.Result{}, false, err
	} else if esInternalCertificate == nil {
		reqLogger.Info("Waiting for internal Elasticsearch tls certificate secret to be available")
		r.status.SetDegraded("Waiting for internal Elasticsearch tls certificate secret to be available", "")
		return reconcile.Result{}, false, nil
	}
	trustedBundle := certificateManager.CreateTrustedBundle(esInternalCertificate, kibanaCertificate)

	// This secret should only ever contain one key.
	if len(esAdminUserSecret.Data) != 1 {
		r.status.SetDegraded("Elasticsearch admin user secret contains too many entries", "")
		return reconcile.Result{}, false, nil
	}

	var esAdminUserName string
	for k := range esAdminUserSecret.Data {
		esAdminUserName = k
		break
	}

	kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, err := lscommon.CreateKubeControllersSecrets(ctx, esAdminUserSecret, esAdminUserName, r.client)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Failed to create kube-controllers secrets for Elasticsearch gateway", "")
		return reconcile.Result{}, false, err
	}

	cfg := &esgateway.Config{
		Installation:               install,
		PullSecrets:                pullSecrets,
		TrustedBundle:              trustedBundle,
		KubeControllersUserSecrets: []*corev1.Secret{kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret},
		ClusterDomain:              r.clusterDomain,
		EsAdminUserName:            esAdminUserName,
	}

	esGatewayComponent := esgateway.EsGateway(cfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, false, err
	}

	certificateComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       render.ElasticsearchNamespace,
		ServiceAccounts: []string{esgateway.ServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(gatewayCertSecret, true, true),
		},
		TrustedBundle: trustedBundle,
	})

	for _, comp := range []render.Component{esGatewayComponent, certificateComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded("Error creating / updating / deleting resource", err.Error())
			return reconcile.Result{}, false, err
		}
	}

	return reconcile.Result{}, true, nil
}
