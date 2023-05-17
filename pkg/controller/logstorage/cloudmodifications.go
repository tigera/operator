// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package logstorage

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/externalelasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
)

// esGatewayAddCloudModificationsToConfig modifies the provided *esgateway.Config to include multi-tenancy specific configuration.
func (r *ReconcileLogStorage) esGatewayAddCloudModificationsToConfig(
	c *esgateway.Config,
	esAdminUserSecret *corev1.Secret,
	reqLogger logr.Logger,
	ctx context.Context,
) (reconcile.Result, bool, error) {
	c.Cloud.EsAdminUserSecret = esAdminUserSecret
	c.Cloud.ExternalElastic = true

	cloudConfig, err := r.getCloudConfig(reqLogger, ctx)
	if cloudConfig == nil || err != nil {
		return reconcile.Result{}, false, err
	}

	c.Cloud.ExternalESDomain = cloudConfig.ExternalESDomain()
	c.Cloud.ExternalKibanaDomain = cloudConfig.ExternalKibanaDomain()

	if cloudConfig.EnableMTLS() {
		c.Cloud.ExternalCertsSecret, err = utils.GetSecret(ctx, r.client, logstorage.ExternalCertsSecret, common.OperatorNamespace())
		if err != nil {
			reqLogger.Error(err, err.Error())
			r.SetDegraded("Waiting for external Elasticsearch certs secret to be available", "")
			return reconcile.Result{}, false, err
		}
		if c.Cloud.ExternalCertsSecret == nil {
			r.SetDegraded("Waiting for external Elasticsearch certs secret to be available", "")
			return reconcile.Result{}, false, nil
		}
		c.Cloud.EnableMTLS = cloudConfig.EnableMTLS()
	}

	if cloudConfig.TenantId() != "" {
		c.Cloud.TenantId = cloudConfig.TenantId()
	}

	return reconcile.Result{}, true, nil
}

// linseedAddCloudModificationsToConfig modifies the provided *linseed.Config to include multi-tenancy specific configuration.
func (r *ReconcileLogStorage) linseedAddCloudModificationsToConfig(
	ctx context.Context,
	c *linseed.Config,
	esAdminUserSecret *corev1.Secret,
	reqLogger logr.Logger,
) (reconcile.Result, bool, error) {
	c.Cloud.EsAdminUserSecret = esAdminUserSecret
	c.Cloud.ExternalElastic = true

	cloudConfig, err := r.getCloudConfig(reqLogger, ctx)
	if cloudConfig == nil || err != nil {
		return reconcile.Result{}, false, err
	}
	c.Cloud.ExternalESDomain = cloudConfig.ExternalESDomain()

	if cloudConfig.EnableMTLS() {
		c.Cloud.ExternalCertsSecret, err = utils.GetSecret(ctx, r.client, logstorage.ExternalCertsSecret, common.OperatorNamespace())
		if err != nil {
			reqLogger.Error(err, err.Error())
			r.SetDegraded("Waiting for external Elasticsearch client certificate secret to be available", "")
			return reconcile.Result{}, false, err
		}
		if c.Cloud.ExternalCertsSecret == nil {
			r.SetDegraded("Waiting for external Elasticsearch client certificate secret to be available", "")
			return reconcile.Result{}, false, nil
		}
		c.Cloud.EnableMTLS = cloudConfig.EnableMTLS()
	}

	if cloudConfig.TenantId() != "" {
		c.Cloud.TenantId = cloudConfig.TenantId()
	}

	return reconcile.Result{}, true, nil
}

// esKubeControllersAddCloudModificationsToConfig modifies the provided *kubecontrollers.KubeControllersConfiguration to include multi-tenancy specific configuration.
func (r *ReconcileLogStorage) esKubeControllersAddCloudModificationsToConfig(
	c *kubecontrollers.KubeControllersConfiguration,
	reqLogger logr.Logger,
	ctx context.Context,
) (reconcile.Result, bool, error) {
	if r.elasticExternal {
		cloudConfig, err := r.getCloudConfig(reqLogger, ctx)
		if cloudConfig == nil || err != nil {
			return reconcile.Result{}, false, err
		}

		if cloudConfig.TenantId() != "" {
			c.TenantId = cloudConfig.TenantId()
		}
	}

	imageAssurance, err := utils.GetImageAssurance(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Error reading ImageAssurance")
		r.SetDegraded("Error reading ImageAssurance", err.Error())
		return reconcile.Result{}, false, err
	}

	c.CloudConfig = kubecontrollers.CloudConfig{
		ImageAssurance: imageAssurance,
	}

	return reconcile.Result{}, true, nil
}

// createExternalElasticsearch pre-prends the tenantId from the tigera-secure-cloud-config Config map to the clusterName
// field in the tigera-secure-elasticsearch Config map. It then creates the ExternalElasticsearch component.
func (r *ReconcileLogStorage) createExternalElasticsearch(
	install *operatorv1.InstallationSpec,
	clusterConfig *relasticsearch.ClusterConfig,
	pullSecrets []*corev1.Secret,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	ctx context.Context,
) (reconcile.Result, bool, error) {
	cloudConfig, err := r.getCloudConfig(reqLogger, ctx)
	if cloudConfig == nil || err != nil {
		return reconcile.Result{}, false, err
	}

	if cloudConfig.TenantId() != "" {
		clusterConfig.AddTenantId(cloudConfig.TenantId())
	}

	externalElasticsearch := externalelasticsearch.ExternalElasticsearch(install, clusterConfig, pullSecrets)

	if err := hdler.CreateOrUpdateOrDelete(ctx, externalElasticsearch, r.status); err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, false, err
	}

	return reconcile.Result{}, true, nil
}

// performHealthChecks hits the /es-health and /kb-health endpoints in es-gateway which in turn perform health checks on the
// external Elasticsearch and Kibana clusters. A failed health check to either of these clusters will result in the
// LogStorage Tigerastatus entry being degraded.
func (r *ReconcileLogStorage) performHealthChecks(reqLogger logr.Logger, ctx context.Context) (reconcile.Result, bool, error) {
	user, password, root, err := utils.GetClientCredentials(r.client, ctx)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error getting Operator Elasticsearch credentials", err.Error())
		return reconcile.Result{}, false, err
	}

	if r.healthCheckClient == nil {
		r.healthCheckClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root}},
		}
	}

	req, err := r.buildHealthCheckRequest("/es-health", user, password)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error building Elasticsearch health check request", err.Error())
		return reconcile.Result{}, false, err
	}

	res, err := r.healthCheckClient.Do(req)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error performing Elasticsearch health check request", err.Error())
		return reconcile.Result{}, false, err
	}

	if res.StatusCode != http.StatusOK {
		reqLogger.Info("Elasticsearch health check returned unexpected status code", "status code:", res.StatusCode)
		r.SetDegraded("Elasticsearch health check failed", "")
		return reconcile.Result{}, false, nil
	}

	req, err = r.buildHealthCheckRequest("/kb-health", user, password)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error building Kibana health check request", err.Error())
		return reconcile.Result{}, false, err
	}

	res, err = r.healthCheckClient.Do(req)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error performing Kibana health check request", err.Error())
		return reconcile.Result{}, false, err
	}

	if res.StatusCode != http.StatusOK {
		reqLogger.Info("Kibana health check returned unexpected status code", "status code:", res.StatusCode)
		r.SetDegraded("Kibana health check failed", "")
		return reconcile.Result{}, false, nil
	}

	return reconcile.Result{}, true, nil
}

func (r *ReconcileLogStorage) buildHealthCheckRequest(endpoint, user, password string) (*http.Request, error) {
	url := r.elasticsearchURL + endpoint
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(user, password)
	return req, nil
}

func (r *ReconcileLogStorage) getCloudConfig(reqLogger logr.Logger, ctx context.Context) (*cloudconfig.CloudConfig, error) {
	cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Failed to retrieve Elasticsearch Gateway config map")
			r.SetDegraded("Failed to retrieve Elasticsearch Gateway config map", err.Error())
			return nil, nil
		}
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Failed to retrieve Elasticsearch Gateway config map", err.Error())
		return nil, err
	}

	return cloudConfig, nil
}

// Deprecated.
// This adapter was created to resolve merge conflicts.
// All calls in rs controller should be updated to use r.status.SetDegraded directly.
func (r *ReconcileLogStorage) SetDegraded(message, errStr string) {
	var err error
	if errStr != "" {
		err = fmt.Errorf(errStr)
	}
	r.status.SetDegraded(operatorv1.Unknown, message, err, log.WithName(""))
}

func addMultiTenancyWatches(c controller.Controller) error {
	if err := utils.AddConfigMapWatch(c, cloudconfig.CloudConfigConfigMapName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
	}
	return nil
}
