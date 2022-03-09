// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package manager

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"

	"github.com/tigera/operator/pkg/render"
	iarender "github.com/tigera/operator/pkg/render/imageassurance"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

func addCloud(c controller.Controller) error {
	var err error

	// Watch the given secrets in each both the manager and operator namespaces for cloud
	for _, namespace := range []string{common.OperatorNamespace(), render.ManagerNamespace} {
		for _, secretName := range []string{iarender.APICertSecretName} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("manager-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	// Watch for changes to primary resource ImageAssurance
	err = c.Watch(&source.Kind{Type: &operatorv1.ImageAssurance{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch ImageAssurance resource: %w", err)
	}

	return nil
}

// handleCloudResources returns managerCloudResources. It returns a non reconcile.Result when it's waiting for resources to be available
func (r *ReconcileManager) handleCloudResources(ctx context.Context, reqLogger logr.Logger) (render.ManagerCloudResources, *reconcile.Result, error) {
	mcr := render.ManagerCloudResources{}
	imageAssurance, err := utils.GetImageAssurance(ctx, r.client)

	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Image Assurance CR is not found, continuing without enabling Image Assurance")
			return mcr, nil, nil
		}
		reqLogger.Error(err, "failed to check for ImageAssurance existence")
		r.status.SetDegraded("failed to check for ImageAssurance existence: %s", err.Error())
		return mcr, nil, err
	}

	// if image assurance is enabled return resources
	if imageAssurance != nil {
		s, err := utils.ValidateCertPair(r.client, common.OperatorNamespace(),
			iarender.APICertSecretName, "", corev1.TLSCertKey)

		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("failed to retrieve %s", iarender.APICertSecretName))
			r.status.SetDegraded(fmt.Sprintf("Failed to retrieve %s", iarender.APICertSecretName), err.Error())
			return mcr, nil, err
		} else if s == nil {
			reqLogger.Info(fmt.Sprintf("Waiting for secret '%s' to become available", iarender.APICertSecretName))
			r.status.SetDegraded(fmt.Sprintf("Waiting for secret '%s' to become available", iarender.APICertSecretName), "")
			return mcr, &reconcile.Result{}, nil
		}

		mcr.ImageAssuranceResources = &render.ImageAssuranceResources{TlsSecret: s}
		reqLogger.Info("Successfully processed resources for ImageAssurance")
	}

	return mcr, nil, nil

}
