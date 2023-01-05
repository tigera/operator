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
		log.Error(err, "Error creating TLS certificate")
		r.status.SetDegraded("Error creating TLS certificate", err.Error())
		return reconcile.Result{}, nil, false, err
	}

	kbSecret := render.TigeraKibanaCertSecret
	esSecret := render.TigeraElasticsearchInternalCertSecret
	if r.elasticExternal {
		// These secrets are no longer used in non-external setups, we'll keep using these,
		// we could switch them and we would need to change the Secret created by
		// tesla/charts/tigera-operator/templates/cloud/lss/sealed-tigera-secure-kb-http-certs-public.yaml
		// tesla/charts/tigera-operator/templates/cloud/lss/sealed-tigera-secure-es-http-certs-public.yaml
		kbSecret = "tigera-secure-kb-http-certs-public"
		esSecret = "tigera-secure-es-http-certs-public"
	}

	var kibanaCertificate certificatemanagement.CertificateInterface
	if !operatorv1.IsFIPSModeEnabled(install.FIPSMode) {
		kibanaCertificate, err = certificateManager.GetCertificate(r.client, kbSecret, common.OperatorNamespace())
		if err != nil {
			reqLogger.Error(err, "failed to get Kibana tls certificate secret")
			r.status.SetDegraded("Failed to get Kibana tls certificate secret", err.Error())
			return reconcile.Result{}, nil, false, err
		} else if kibanaCertificate == nil {
			reqLogger.Info("Waiting for internal Kibana tls certificate secret to be available")
			r.status.SetDegraded("Waiting for internal Kibana tls certificate secret to be available", "")
			return reconcile.Result{}, nil, false, nil
		}
	}

	esInternalCertificate, err := certificateManager.GetCertificate(r.client, esSecret, common.OperatorNamespace())
	if err != nil {
		reqLogger.Error(err, "failed to get Elasticsearch tls certificate secret")
		r.status.SetDegraded("Failed to get Elasticsearch tls certificate secret", err.Error())
		return reconcile.Result{}, nil, false, err
	} else if esInternalCertificate == nil {
		reqLogger.Info("Waiting for internal Elasticsearch tls certificate secret to be available")
		r.status.SetDegraded("Waiting for internal Elasticsearch tls certificate secret to be available", "")
		return reconcile.Result{}, nil, false, nil
	}

	prometheusCertificate, err := certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		return reconcile.Result{}, nil, false, err
	} else if prometheusCertificate == nil {
		r.status.SetDegraded("Prometheus secrets are not available yet, waiting until they become available", "")
		return reconcile.Result{}, nil, false, err
	}
	trustedBundle := certificateManager.CreateTrustedBundle(esInternalCertificate, kibanaCertificate, prometheusCertificate, gatewayKeyPair)

	// This secret should only ever contain one key.
	if len(esAdminUserSecret.Data) != 1 {
		r.status.SetDegraded("Elasticsearch admin user secret contains too many entries", "")
		return reconcile.Result{}, nil, false, nil
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

	// Multi-tenancy modifications.
	if r.elasticExternal {
		if result, proceed, err := r.esGatewayAddCloudModificationsToConfig(cfg, esAdminUserSecret, reqLogger, ctx); err != nil || !proceed {
			return result, nil, proceed, err
		}
	}

	esGatewayComponent := esgateway.EsGateway(cfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
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

	for _, comp := range []render.Component{esGatewayComponent, certificateComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded("Error creating / updating / deleting resource", err.Error())
			return reconcile.Result{}, nil, false, err
		}
	}

	return reconcile.Result{}, trustedBundle, true, nil
}
