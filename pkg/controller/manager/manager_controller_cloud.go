// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package manager

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	rcloudrbac "github.com/tigera/operator/pkg/render/cloudrbac"
	"github.com/tigera/operator/pkg/render/common/cloudrbac"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	iarender "github.com/tigera/operator/pkg/render/imageassurance"
)

var (
	CloudManagerConfigOverrideName = "cloud-manager-config"
	CloudVoltronConfigOverrideName = "cloud-voltron-config"
)

func addCloudWatch(c controller.Controller) error {
	if err := utils.AddImageAssuranceWatch(c, render.ManagerNamespace); err != nil {
		return err
	}

	if err := utils.AddCloudRBACWatch(c, render.ManagerNamespace); err != nil {
		return err
	}

	if err := utils.AddConfigMapWatch(c, CloudVoltronConfigOverrideName, common.OperatorNamespace()); err != nil {
		return err
	}

	if err := utils.AddConfigMapWatch(c, CloudManagerConfigOverrideName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %v", err)
	}

	return nil
}

// handleCloudResources returns managerCloudResources.
// It returns a non-nil reconcile.Result when it's waiting for resources to be available.
func (r *ReconcileManager) handleCloudResources(ctx context.Context, reqLogger logr.Logger) (render.ManagerCloudResources, *reconcile.Result, error) {
	mcr := render.ManagerCloudResources{
		VoltronMetricsEnabled:    true,
		VoltronInternalHttpsPort: 9444,
		ManagerExtraEnv:          map[string]string{},
	}

	result, err := r.handleImageAssuranceResources(ctx, &mcr, reqLogger)
	if err != nil {
		return mcr, nil, err
	}

	err = r.handleCloudRBACResources(ctx, &mcr, reqLogger)
	if err != nil {
		return mcr, nil, err
	}

	if err := r.cloudConfigOverride(ctx, &mcr, reqLogger); err != nil {
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
		r.status.SetDegraded(operatorv1.ResourceReadError, "failed to check for Cloud RBAC existence: %s", err, reqLogger)
		return err
	}

	// get tls secret for cloud rbac, created by the cc-management-core operator
	secret, err := utils.GetCloudRbacTLSSecret(r.client)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to retrieve secret %s", cloudrbac.TLSSecretName))
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("failed to retrieve secret %s", cloudrbac.TLSSecretName), err, reqLogger)
		return err
	} else if secret == nil {
		reqLogger.Info(fmt.Sprintf("waiting for secret '%s' to become available", cloudrbac.TLSSecretName))
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("waiting for secret '%s' to become available", cloudrbac.TLSSecretName), nil, reqLogger)
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
		r.status.SetDegraded(operatorv1.ResourceReadError, "failed to check for Image Assurance existence: %s", err, reqLogger)
		return nil, err
	}

	// get tls secret for image assurance api communication
	secret, err := utils.GetImageAssuranceTLSSecret(r.client)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to retrieve secret %s", iarender.APICertSecretName))
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve secret %s", iarender.APICertSecretName), err, reqLogger)
		return nil, err
	} else if secret == nil {
		reqLogger.Info(fmt.Sprintf("waiting for secret '%s' to become available", iarender.APICertSecretName))
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("waiting for secret '%s' to become available", iarender.APICertSecretName), nil, reqLogger)
		return &reconcile.Result{}, nil
	}

	// Get image assurance configuration config map.
	cm, err := utils.GetImageAssuranceConfigurationConfigMap(r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info(fmt.Sprintf("waiting for configmap '%s' to become available", rcimageassurance.ConfigurationConfigMapName))
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("waiting for configmap '%s' to become available", rcimageassurance.ConfigurationConfigMapName), nil, reqLogger)
			return &reconcile.Result{}, nil
		}

		reqLogger.Error(err, fmt.Sprintf("failed to retrieve configmap: %s", rcimageassurance.ConfigurationConfigMapName))
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("failed to retrieve configmap: %s", rcimageassurance.ConfigurationConfigMapName), err, reqLogger)
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
				r.status.SetDegraded(operatorv1.ResourceNotFound, "Failed to retrieve External Elasticsearch config map", err, reqLogger)
				return &reconcile.Result{}, nil
			}
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read cloud config map", err, reqLogger)
			return nil, err
		}

		mcr.TenantID = cloudConfig.TenantId()
	}

	return nil, nil
}

// cloudConfigOverride set manager and voltron renderer env override
func (r *ReconcileManager) cloudConfigOverride(ctx context.Context, mcr *render.ManagerCloudResources, reqLogger logr.Logger) error {
	var err error
	managerCfg, err := r.getConfigMapData(ctx, CloudManagerConfigOverrideName)
	if err != nil {
		return err
	}
	for key, val := range managerCfg {
		if key == "portalAPIURL" {
			// support legacy functionality where 'portalAPIURL' was a special field used to set
			// the portal url and enable support.
			mcr.ManagerExtraEnv["CNX_PORTAL_URL"] = val
			mcr.ManagerExtraEnv["ENABLE_PORTAL_SUPPORT"] = "true"
		}

		if key == "auth0OrgID" {
			// support legacy functionality where 'auth0OrgID' was a special field used to set
			// the org ID
			mcr.ManagerExtraEnv["CNX_AUTH0_ORG_ID"] = val
		}

		// special key used to control which image of manager is used
		if key == "managerImage" {
			mcr.ManagerImage = val
		}
	}

	mcr.VoltronExtraEnv, err = r.getConfigMapData(ctx, CloudVoltronConfigOverrideName)
	if err != nil {
		return err
	}

	return nil
}

func (r *ReconcileManager) getConfigMapData(ctx context.Context, name string) (map[string]string, error) {
	configMap := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: name, Namespace: common.OperatorNamespace()}
	if err := r.client.Get(ctx, key, configMap); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to read %s ConfigMap: %s", name, err.Error())
		}
		return nil, nil
	}
	return configMap.Data, nil
}
