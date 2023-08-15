// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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
	"fmt"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func (r *ReconcileLogStorage) createESKubeControllers(
	install *operatorv1.InstallationSpec,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	managementCluster *operatorv1.ManagementCluster,
	authentication *operatorv1.Authentication,
	esLicenseType render.ElasticsearchLicenseType,
	ctx context.Context,
) (reconcile.Result, bool, error) {
	kubeControllersUserSecret, err := utils.GetSecret(ctx, r.client, kubecontrollers.ElasticsearchKubeControllersUserSecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get kube controllers gateway secret", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	certificateManager, err := certificatemanager.Create(r.client, install, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	var managerInternalTLSSecret certificatemanagement.KeyPairInterface
	if managementCluster != nil {
		svcDNSNames := append(dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, r.clusterDomain), render.ManagerServiceIP)
		managerInternalTLSSecret, err = certificateManager.GetOrCreateKeyPair(r.client, render.ManagerInternalTLSSecretName, common.CalicoNamespace, svcDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("Error ensuring internal manager TLS certificate %q exists and has valid DNS names", render.ManagerInternalTLSSecretName), err, reqLogger)
			return reconcile.Result{}, false, err
		}
	}

	kubeControllersCfg := kubecontrollers.KubeControllersConfiguration{
		K8sServiceEp:                 k8sapi.Endpoint,
		Installation:                 install,
		ManagementCluster:            managementCluster,
		ClusterDomain:                r.clusterDomain,
		ManagerInternalSecret:        managerInternalTLSSecret,
		Authentication:               authentication,
		KubeControllersGatewaySecret: kubeControllersUserSecret,
		LogStorageExists:             true,
		TrustedBundle:                certificateManager.CreateTrustedBundle(),
	}
	esKubeControllerComponents := kubecontrollers.NewElasticsearchKubeControllers(&kubeControllersCfg)

	imageSet, err := imageset.GetImageSet(ctx, r.client, install.Variant)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting ImageSet", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error validating ImageSet", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	if err = imageset.ResolveImages(imageSet, esKubeControllerComponents); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error resolving ImageSet for elasticsearch kube-controllers components", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, esKubeControllerComponents, nil); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating  elasticsearch kube-controllers resource", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	return reconcile.Result{}, true, nil
}
