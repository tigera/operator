// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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

package managedcluster

import (
	"context"
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
)

var log = logf.Log.WithName("controller_logstorage_managed")

// LogStorageManagedClusterController reconciles resources needed by managed clusters in order to
// write logs to the management cluster. It is only used on managed clusters - for management and standlone clusters,
// this controller is a no-op.
type LogStorageManagedClusterController struct {
	client        client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	clusterDomain string
}

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// Create the reconciler
	r := &LogStorageManagedClusterController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		clusterDomain: opts.ClusterDomain,
		provider:      opts.DetectedProvider,
	}

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-managedcluster-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-managedcluster-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("log-storage-managedcluster-controller failed to watch Installation resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-managedcluster-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-managedcluster-controller failed to watch ManagementClusterConnection resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, relasticsearch.PublicCertSecret, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-managedcluster-controller failed to watch Secret resource: %w", err)
	}
	if err = utils.AddSecretsWatch(c, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-managedcluster-controller failed to watch Secret resource: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-managedcluster-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (r *LogStorageManagedClusterController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)

	// First, check if this is a managed cluster. This controler can simply return if it is not.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		reqLogger.V(2).Info("Not a managed cluster, skipping reconcile")
		return reconcile.Result{}, nil
	} else if managementClusterConnection == nil {
		return reconcile.Result{}, err
	}

	reqLogger.Info("Reconciling ManagedCluster resources for log storage")

	// Make sure this is an Enterprise cluster.
	variant, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, err
	}
	if variant != operatorv1.TigeraSecureEnterprise {
		return reconcile.Result{}, nil
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		return reconcile.Result{}, err
	}
	if managementCluster != nil {
		// ManagementCluster is not supported on a managed cluster. Return an error.
		return reconcile.Result{}, fmt.Errorf("ManagementCluster is not supported on a managed cluster")
	}

	exists, err := utils.LogStorageExists(ctx, r.client)
	if err != nil {
		return reconcile.Result{}, err
	}
	if exists {
		// LogStorage is not supported on a managed cluster. Return an error.
		return reconcile.Result{}, fmt.Errorf("LogStorage is not supported on a managed cluster")
	}

	// Create the component and install it.
	cfg := &render.ManagedClusterLogStorageConfiguration{
		ClusterDomain: r.clusterDomain,
		Installation:  install,
	}
	component := render.NewManagedClusterLogStorage(cfg)
	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, managementClusterConnection)
	if err := hdler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
