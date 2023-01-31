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
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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
) (reconcile.Result, certificatemanagement.TrustedBundle, bool, error) {
	svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	svcDNSNames = append(svcDNSNames, dns.GetServiceDNSNames(esgateway.ServiceName, render.ElasticsearchNamespace, r.clusterDomain)...)
	gatewayKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), svcDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
		return reconcile.Result{}, nil, false, err
	}

	var kibanaCertificate certificatemanagement.CertificateInterface
	if !operatorv1.IsFIPSModeEnabled(install.FIPSMode) {
		kibanaCertificate, err = certificateManager.GetCertificate(r.client, render.TigeraKibanaCertSecret, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Kibana tls certificate secret", err, reqLogger)
			return reconcile.Result{}, nil, false, err
		} else if kibanaCertificate == nil {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for internal Kibana tls certificate secret to be available", nil, reqLogger)
			return reconcile.Result{}, nil, false, nil
		}
	}
	esInternalCertificate, err := certificateManager.GetCertificate(r.client, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch tls certificate secret", err, reqLogger)
		return reconcile.Result{}, nil, false, err
	} else if esInternalCertificate == nil {
		reqLogger.Info("Waiting for internal Elasticsearch tls certificate secret to be available")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for internal Elasticsearch tls certificate secret to be available", nil, reqLogger)
		return reconcile.Result{}, nil, false, nil
	}

	// Esgateway.go will render the trusted bundle for the whole namespace, so we want to include also the Prometheus
	// TLS certificate, which the elasticsearch-metrics server depends on.
	prometheusCertificate, err := certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get certificate", err, reqLogger)
		return reconcile.Result{}, nil, false, err
	} else if prometheusCertificate == nil {
		reqLogger.Info("Prometheus secrets are not available yet, waiting until they become available")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Prometheus secrets are not available yet, waiting until they become available", nil, reqLogger)
		return reconcile.Result{}, nil, false, nil
	}
	trustedBundle := certificateManager.CreateTrustedBundle(esInternalCertificate, kibanaCertificate, prometheusCertificate, gatewayKeyPair)

	// This secret should only ever contain one key.
	if len(esAdminUserSecret.Data) != 1 {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Elasticsearch admin user secret contains too many entries", nil, reqLogger)
		return reconcile.Result{}, nil, false, nil
	}

	var esAdminUserName string
	for k := range esAdminUserSecret.Data {
		esAdminUserName = k
		break
	}

	kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, err := lscommon.CreateKubeControllersSecrets(ctx, esAdminUserSecret, esAdminUserName, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create kube-controllers secrets for Elasticsearch gateway", err, reqLogger)
		return reconcile.Result{}, nil, false, err
	}

	cfg := &esgateway.Config{
		Installation:               install,
		PullSecrets:                pullSecrets,
		TrustedBundle:              trustedBundle,
		KubeControllersUserSecrets: []*corev1.Secret{kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret},
		ClusterDomain:              r.clusterDomain,
		EsAdminUserName:            esAdminUserName,
		ESGatewayKeyPair:           gatewayKeyPair,
	}

	esGatewayComponent := esgateway.EsGateway(cfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, nil, false, err
	}

	certificateComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       render.ElasticsearchNamespace,
		ServiceAccounts: []string{esgateway.ServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(gatewayKeyPair, true, true),
		},
		TrustedBundle: trustedBundle,
	})

	for _, comp := range []render.Component{certificateComponent, esGatewayComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return reconcile.Result{}, nil, false, err
		}
	}
	return reconcile.Result{}, trustedBundle, true, nil
}
