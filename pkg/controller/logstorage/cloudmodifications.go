package logstorage

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/externalelasticsearch"
)

// esGatewayAddCloudModificationsToConfig modifies the provided *esgateway.Config to include multi-tenancy specific configuration.
func (r *ReconcileLogStorage) esGatewayAddCloudModificationsToConfig(
	c *esgateway.Config,
	esAdminUserSecret *corev1.Secret,
	reqLogger logr.Logger,
	ctx context.Context,
) (reconcile.Result, bool, error) {
	c.EsAdminUserSecret = esAdminUserSecret
	c.ExternalElastic = true

	cloudConfig, err := r.getCloudConfig(reqLogger, ctx)
	if cloudConfig == nil || err != nil {
		return reconcile.Result{}, false, err
	}

	c.ExternalESDomain = cloudConfig.ExternalESDomain()
	c.ExternalKibanaDomain = cloudConfig.ExternalKibanaDomain()

	if cloudConfig.EnableMTLS() {
		c.ExternalCertsSecret, err = utils.GetSecret(ctx, r.client, esgateway.ExternalCertsSecret, rmeta.OperatorNamespace())
		if err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Waiting for external Elasticsearch certs secret to be available", "")
			return reconcile.Result{}, false, err
		}
		if c.ExternalCertsSecret == nil {
			r.status.SetDegraded("Waiting for external Elasticsearch certs secret to be available", "")
			return reconcile.Result{}, false, nil
		}
		c.EnableMTLS = cloudConfig.EnableMTLS()
	}

	if cloudConfig.TenantId() != "" {
		c.TenantId = cloudConfig.TenantId()
	}

	return reconcile.Result{}, true, nil
}

// esKubeControllersAddCloudModificationsToConfig modifies the provided *kubecontrollers.KubeControllersConfiguration to include multi-tenancy specific configuration.
func (r *ReconcileLogStorage) esKubeControllersAddCloudModificationsToConfig(
	c *kubecontrollers.KubeControllersConfiguration,
	reqLogger logr.Logger,
	ctx context.Context,
) (reconcile.Result, bool, error) {
	cloudConfig, err := r.getCloudConfig(reqLogger, ctx)
	if cloudConfig == nil || err != nil {
		return reconcile.Result{}, false, err
	}

	if cloudConfig.TenantId() != "" {
		c.TenantId = cloudConfig.TenantId()
	}

	return reconcile.Result{}, true, nil
}

// createExternalElasticsearch pre-prends the tenantId from the tigera-secure-cloud-config Config map to the clusterName
// field in the tigera-secure-elasticsearch Config map. It then creates the ExternalElasticsearch component.
func (r *ReconcileLogStorage) createExternalElasticsearch(
	install *operatorv1.InstallationSpec,
	clusterConfig *relasticsearch.ClusterConfig,
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

	externalElasticsearch := externalelasticsearch.ExternalElasticsearch(install, clusterConfig)

	if err := hdler.CreateOrUpdateOrDelete(ctx, externalElasticsearch, r.status); err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, false, err
	}

	return reconcile.Result{}, true, nil
}

func (r *ReconcileLogStorage) getCloudConfig(reqLogger logr.Logger, ctx context.Context) (*cloudconfig.CloudConfig, error) {
	cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Failed to retrieve Elasticsearch Gateway config map")
			r.status.SetDegraded("Failed to retrieve Elasticsearch Gateway config map", err.Error())
			return nil, nil
		}
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Failed to retrieve Elasticsearch Gateway config map", err.Error())
		return nil, err
	}

	return cloudConfig, nil
}

func addMultiTenancyWatches(c controller.Controller) error {
	if err := utils.AddConfigMapWatch(c, cloudconfig.CloudConfigConfigMapName, rmeta.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
	}
	return nil
}
