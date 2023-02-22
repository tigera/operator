// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package intrusiondetection

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	iarender "github.com/tigera/operator/pkg/render/imageassurance"
)

const (
	ImageAssuranceAPIServiceAccountName = "tigera-image-assurance-intrusion-detection-controller-api-access"
)

func addCloudWatch(c controller.Controller) error {
	if err := utils.AddImageAssuranceWatch(c, render.IntrusionDetectionNamespace); err != nil {
		return err
	}

	if err := utils.AddClusterRoleWatch(c, render.IntrusionDetectionControllerImageAssuranceAPIClusterRoleName); err != nil {
		return err
	}

	return nil
}

// handleCloudResources returns managerCloudResources.
// It returns a non-nil reconcile.Result when it's waiting for resources to be available
func (r *ReconcileIntrusionDetection) handleCloudResources(ctx context.Context, reqLogger logr.Logger) (render.IntrusionDetectionCloudResources, *reconcile.Result, error) {
	idcr := render.IntrusionDetectionCloudResources{}
	if _, err := utils.GetImageAssurance(ctx, r.client); err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Image Assurance CR is not found, continuing without enabling Image Assurance")
			return idcr, nil, nil
		}
		reqLogger.Error(err, "failed to check for Image Assurance existence")
		r.status.SetDegraded("failed to check for Image Assurance existence: %s", err.Error())
		return idcr, nil, err
	}

	// get tls secret for image assurance api communication
	secret, err := utils.GetImageAssuranceTLSSecret(r.client)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to retrieve secret %s", iarender.APICertSecretName))
		r.status.SetDegraded(fmt.Sprintf("Failed to retrieve secret %s", iarender.APICertSecretName), err.Error())
		return idcr, nil, err
	} else if secret == nil {
		reqLogger.Info(fmt.Sprintf("waiting for secret '%s' to become available", iarender.APICertSecretName))
		r.status.SetDegraded(fmt.Sprintf("waiting for secret '%s' to become available", iarender.APICertSecretName), "")
		return idcr, &reconcile.Result{}, nil
	}

	// get image assurance configuration config map
	cm, err := utils.GetImageAssuranceConfigurationConfigMap(r.client)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to retrieve configmap: %s", rcimageassurance.ConfigurationConfigMapName))
		r.status.SetDegraded(fmt.Sprintf("failed to retrieve configmap: %s", rcimageassurance.ConfigurationConfigMapName), err.Error())
		return idcr, nil, err
	}

	sa := &corev1.ServiceAccount{}
	if err := r.client.Get(context.Background(), types.NamespacedName{
		Name:      ImageAssuranceAPIServiceAccountName,
		Namespace: common.OperatorNamespace(),
	}, sa); err != nil {
		return idcr, nil, err
	}

	if len(sa.Secrets) == 0 {
		reqLogger.Info(fmt.Sprintf("waiting for secret '%s' to become available", ImageAssuranceAPIServiceAccountName))
		r.status.SetDegraded(fmt.Sprintf("waiting for secret '%s' to become available", ImageAssuranceAPIServiceAccountName), "")
		return idcr, &reconcile.Result{}, nil
	}

	saSecret := &corev1.Secret{}
	if err := r.client.Get(context.Background(), types.NamespacedName{
		Name:      sa.Secrets[0].Name,
		Namespace: common.OperatorNamespace(),
	}, saSecret); err != nil {
		return idcr, nil, err
	}

	idcr.ImageAssuranceResources = &rcimageassurance.Resources{
		ConfigurationConfigMap: cm,
		TLSSecret:              secret,
		ImageAssuranceToken:    saSecret.Data["token"],
	}
	reqLogger.Info("Successfully processed resources for Image Assurance")

	return idcr, nil, nil
}
