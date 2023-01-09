// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package manager

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	rcloudrbac "github.com/tigera/operator/pkg/render/cloudrbac"
	"github.com/tigera/operator/pkg/render/common/cloudrbac"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	iarender "github.com/tigera/operator/pkg/render/imageassurance"
)

func addCloudWatch(c controller.Controller) error {
	if err := utils.AddImageAssuranceWatch(c, render.ManagerNamespace); err != nil {
		return err
	}

	if err := utils.AddCloudRBACWatch(c, render.ManagerNamespace); err != nil {
		return err
	}
	return nil
}

// handleCloudResources returns managerCloudResources.
// It returns a non-nil reconcile.Result when it's waiting for resources to be available.
func (r *ReconcileManager) handleCloudResources(ctx context.Context, reqLogger logr.Logger) (render.ManagerCloudResources, *reconcile.Result, error) {
	mcr := render.ManagerCloudResources{}

	result, err := r.handleImageAssuranceResources(ctx, &mcr, reqLogger)
	if err != nil {
		return mcr, nil, err
	}

	err = r.handleCloudRBACResources(ctx, &mcr, reqLogger)
	if err != nil {
		return mcr, nil, err
	}

	return mcr, result, err
}

// handleCloudRBACResources registers Cloud RBAC specific resources with managerCloudResources.
func (r *ReconcileManager) handleCloudRBACResources(ctx context.Context, mcr *render.ManagerCloudResources, reqLogger logr.Logger) error {

	if _, err := utils.GetCloudRBAC(ctx, r.client); err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("CloudRBAC CR is not found, continuing without enabling Cloud RBAC")
			return nil
		}
		reqLogger.Error(err, "failed to check for Cloud RBAC existence")
		r.status.SetDegraded("failed to check for Cloud RBAC existence: %s", err.Error())
		return err
	}

	// get tls secret for cloud rbac, created by the cc-management-core operator
	secret, err := utils.GetCloudRbacTLSSecret(r.client)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to retrieve secret %s", cloudrbac.TLSSecretName))
		r.status.SetDegraded(fmt.Sprintf("failed to retrieve secret %s", cloudrbac.TLSSecretName), err.Error())
		return err
	} else if secret == nil {
		reqLogger.Info(fmt.Sprintf("waiting for secret '%s' to become available", cloudrbac.TLSSecretName))
		r.status.SetDegraded(fmt.Sprintf("waiting for secret '%s' to become available", cloudrbac.TLSSecretName), "")
		return nil
	}

	mcr.CloudRBACResources = &cloudrbac.Resources{
		NamespaceName: rcloudrbac.RBACApiNamespace,
		ServiceName:   rcloudrbac.RBACApiServiceName,
		TLSSecret:     secret,
	}

	reqLogger.Info("Successfully processed resources for Cloud RBAC")
	return nil
}

// handleImageAssuranceResources registers Image Assurance specific resources with managerCloudResources.
// It returns a non-nil reconcile.Result when it's waiting for resources to be available.
func (r *ReconcileManager) handleImageAssuranceResources(ctx context.Context, mcr *render.ManagerCloudResources, reqLogger logr.Logger) (*reconcile.Result, error) {

	if _, err := utils.GetImageAssurance(ctx, r.client); err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Image Assurance CR is not found, continuing without enabling Image Assurance")
			return nil, nil
		}
		reqLogger.Error(err, "failed to check for Image Assurance existence")
		r.status.SetDegraded("failed to check for Image Assurance existence: %s", err.Error())
		return nil, err
	}

	// get tls secret for image assurance api communication
	secret, err := utils.GetImageAssuranceTLSSecret(r.client)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to retrieve secret %s", iarender.APICertSecretName))
		r.status.SetDegraded(fmt.Sprintf("Failed to retrieve secret %s", iarender.APICertSecretName), err.Error())
		return nil, err
	} else if secret == nil {
		reqLogger.Info(fmt.Sprintf("waiting for secret '%s' to become available", iarender.APICertSecretName))
		r.status.SetDegraded(fmt.Sprintf("waiting for secret '%s' to become available", iarender.APICertSecretName), "")
		return &reconcile.Result{}, nil
	}

	// Get image assurance configuration config map.
	cm, err := utils.GetImageAssuranceConfigurationConfigMap(r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info(fmt.Sprintf("waiting for configmap '%s' to become available", rcimageassurance.ConfigurationConfigMapName))
			r.status.SetDegraded(fmt.Sprintf("waiting for configmap '%s' to become available", rcimageassurance.ConfigurationConfigMapName), "")
			return &reconcile.Result{}, nil
		}

		reqLogger.Error(err, fmt.Sprintf("failed to retrieve configmap: %s", rcimageassurance.ConfigurationConfigMapName))
		r.status.SetDegraded(fmt.Sprintf("failed to retrieve configmap: %s", rcimageassurance.ConfigurationConfigMapName), err.Error())
		return nil, err
	}

	mcr.ImageAssuranceResources = &rcimageassurance.Resources{
		ConfigurationConfigMap: cm,
		TLSSecret:              secret,
	}
	reqLogger.Info("Successfully processed resources for Image Assurance")

	if r.elasticExternal {
		cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
		if err != nil {
			if errors.IsNotFound(err) {
				reqLogger.Info("Failed to retrieve External Elasticsearch config map")
				r.status.SetDegraded("Failed to retrieve External Elasticsearch config map", err.Error())
				return &reconcile.Result{}, nil
			}
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Unable to read cloud config map", err.Error())
			return nil, err
		}

		mcr.TenantID = cloudConfig.TenantId()
	}

	return nil, nil
}
