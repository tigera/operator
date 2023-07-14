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
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	octrl "github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	lscommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

func (r *LinseedSubController) createESGateway(
	ctx context.Context,
	request octrl.Request,
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	pullSecrets []*corev1.Secret,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	usePSP bool,
) error {
	// Create a trusted bundle to pass to the render pacakge. The actual contents of this bundle don't matter - the ConfigMap
	// itself will be managed by the Secret controller. But, we need an interface to use as an argument to render in order
	// to configure volume mounts properly.
	trustedBundle := certificatemanagement.CreateTrustedBundle()

	// Get the ES admin user secret. This is provisioned by the ECK operator as part of installing Elasticsearch,
	// and so may not be immediately available.
	esAdminUserSecret, err := utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
	if err != nil {
		reqLogger.Error(err, "failed to get Elasticsearch admin user secret")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch admin user secret", err, reqLogger)
		return err
	} else if esAdminUserSecret == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for elasticsearch admin secret", nil, reqLogger)
		return nil
	}

	// This secret should only ever contain one key.
	if len(esAdminUserSecret.Data) != 1 {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Elasticsearch admin user secret contains too many entries", nil, reqLogger)
		return nil
	}

	var esAdminUserName string
	for k := range esAdminUserSecret.Data {
		esAdminUserName = k
		break
	}

	// Collect the certificates we need to provision ESGW. These will have been provisioned already by the ES secrets controller.
	cm, err := certificatemanager.Create(r.client, install, r.clusterDomain, request.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return err
	}
	gatewayKeyPair, err := cm.GetKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, request.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Error getting TLS certificate", err, log)
		return err
	} else if gatewayKeyPair == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "es-gateway key pair not yet available", err, log)
		return err
	}

	kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, err := lscommon.CreateKubeControllersSecrets(ctx, esAdminUserSecret, esAdminUserName, r.client, request)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create kube-controllers secrets for Elasticsearch gateway", err, reqLogger)
		return err
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
		Namespace:                  request.InstallNamespace(),
		TruthNamespace:             request.TruthNamespace(),
	}

	esGatewayComponent := esgateway.EsGateway(cfg)
	if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return err
	}

	// Copy the es admin user secret to the namespace so that es-gateway has access to it. For single-tenant, this is essentially a no-op.
	// For multi-tenant, this means copying the es-gateway admin secret to the tenant's namespace.
	// TODO: We shouldn't use the admin secret here, this is just for prototyping purposes. Instead, each tenant's esgw should get its own credentials.
	// Potentially, we do away with es-gateway in multi-tenant setups entirely - kube-controllers can talk to ES with its own non-admin credentials, since
	// es-kube-controllers is the only thing that needs to talk to ES (aside from Linseed) in multi-tenant setups. We could get rid of that need as well if
	// we have the operator provision Linseed's secret instead of kube-controllers.
	copied := []client.Object{}
	copied = append(copied, secret.CopyToNamespace(request.InstallNamespace(), esAdminUserSecret)[0])
	createSecretComponent := render.NewPassthrough(copied...)

	for _, comp := range []render.Component{createSecretComponent, esGatewayComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return err
		}
	}
	return nil
}
