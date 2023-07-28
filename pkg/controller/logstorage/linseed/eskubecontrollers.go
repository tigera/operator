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

package linseed

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	octrl "github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"k8s.io/apimachinery/pkg/api/errors"
)

// TODO: Move this out of this controller.
func (r *LinseedSubController) createESKubeControllers(
	ctx context.Context,
	helper octrl.NamespaceHelper,
	install *operatorv1.InstallationSpec,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	managementCluster *operatorv1.ManagementCluster,
) error {
	// Get the Authentication resource.
	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, reqLogger)
		return err
	}

	// Get secrets needed for kube-controllers to talk to elastic.
	kubeControllersUserSecret, err := utils.GetSecret(ctx, r.client, kubecontrollers.ElasticsearchKubeControllersUserSecret, helper.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get kube controllers gateway secret", err, reqLogger)
		return err
	}

	certificateManager, err := certificatemanager.Create(r.client, install, r.clusterDomain, helper.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return err
	}

	var managerInternalTLSSecret certificatemanagement.KeyPairInterface
	if managementCluster != nil {
		// Add the internal traffic secret of the manager pod to the trusted bundle. We need this so we can talk to Voltron.
		// This certificate is provisioned by the manager controller, and so we need to load it lazily once it appears.
		managerInternalTLSSecret, err = certificateManager.GetKeyPair(r.client, render.ManagerInternalTLSSecretName, helper.TruthNamespace())
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("Error querying for internal manager TLS certificate (%s)", render.ManagerInternalTLSSecretName), err, reqLogger)
			return err
		}
	}

	namespaces := []string{helper.InstallNamespace()}
	if r.multiTenant {
		namespaces, err = utils.TenantNamespaces(ctx, r.client)
		if err != nil {
			return err
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
		TrustedBundle:                certificateManager.CreateTrustedBundle(), // We don't care about the contents.
		Namespace:                    helper.InstallNamespace(),                // TODO: This will give tigera-elasticsearch in single-tenant systems. Is this OK?
		BindingNamespaces:            namespaces,
	}
	esKubeControllerComponents := kubecontrollers.NewElasticsearchKubeControllers(&kubeControllersCfg)

	imageSet, err := imageset.GetImageSet(ctx, r.client, install.Variant)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting ImageSet", err, reqLogger)
		return err
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error validating ImageSet", err, reqLogger)
		return err
	}

	if err = imageset.ResolveImages(imageSet, esKubeControllerComponents); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error resolving ImageSet for elasticsearch kube-controllers components", err, reqLogger)
		return err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, esKubeControllerComponents, nil); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating  elasticsearch kube-controllers resource", err, reqLogger)
		return err
	}

	return nil
}
