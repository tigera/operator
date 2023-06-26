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
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	lscommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

func (r *LinseedSubController) createESGateway(
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	ctx context.Context,
	trustedBundle certificatemanagement.TrustedBundle,
	usePSP bool,
) (reconcile.Result, bool, error) {
	// Get the ES admin user secret. This is provisioned by the ECK operator as part of installing Elasticsearch,
	// and so may not be immediately available.
	esAdminUserSecret, err := utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
	if err != nil {
		reqLogger.Error(err, "failed to get Elasticsearch admin user secret")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch admin user secret", err, reqLogger)
		return reconcile.Result{}, false, err
	} else if esAdminUserSecret == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for elasticsearch admin secret", nil, reqLogger)
		return reconcile.Result{}, false, nil
	}

	// This secret should only ever contain one key.
	if len(esAdminUserSecret.Data) != 1 {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Elasticsearch admin user secret contains too many entries", nil, reqLogger)
		return reconcile.Result{}, false, nil
	}

	var esAdminUserName string
	for k := range esAdminUserSecret.Data {
		esAdminUserName = k
		break
	}

	// Collect the certificates we need to provision ESGW. These will have been provisioned already by the ES secrets controller.
	cm, err := certificatemanager.Create(r.client, install, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, false, err
	}
	gatewayKeyPair, err := cm.GetKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return reconcile.Result{}, false, err
	}

	kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, err := lscommon.CreateKubeControllersSecrets(ctx, esAdminUserSecret, esAdminUserName, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create kube-controllers secrets for Elasticsearch gateway", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	cfg := &esgateway.Config{
		Installation:               install,
		PullSecrets:                pullSecrets,
		TrustedBundle:              trustedBundle,
		KubeControllersUserSecrets: []*corev1.Secret{kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret},
		ClusterDomain:              r.clusterDomain,
		EsAdminUserName:            esAdminUserName,
		ESGatewayKeyPair:           gatewayKeyPair,
		UsePSP:                     usePSP,
	}

	esGatewayComponent := esgateway.EsGateway(cfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	for _, comp := range []render.Component{esGatewayComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return reconcile.Result{}, false, err
		}
	}
	return reconcile.Result{}, true, nil
}
