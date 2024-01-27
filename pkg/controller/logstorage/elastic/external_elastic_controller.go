// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package elastic

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/controller/logstorage/initializer"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/externalelasticsearch"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type ExternalESController struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	provider      operatorv1.Provider
	clusterDomain string
	usePSP        bool
}

func AddExternalES(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}
	if !opts.ElasticExternal {
		return nil
	}

	// Create the reconciler
	r := &ExternalESController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		status:        status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageElastic, opts.KubernetesVersion),
		usePSP:        opts.UsePSP,
		clusterDomain: opts.ClusterDomain,
		provider:      opts.DetectedProvider,
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-external-es-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch Installation resource: %w", err)
	}
	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ImageSet: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, initializer.TigeraStatusLogStorageElastic); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch logstorage Tigerastatus: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, "cloud-kibana-config", common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch the ConfigMap resource: %w", err)
	}
	return nil
}

func (r *ExternalESController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

	ls := &operatorv1.LogStorage{}
	err := r.client.Get(ctx, utils.DefaultTSEEInstanceKey, ls)
	if err != nil {
		if !errors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}
	r.status.OnCRFound()

	_, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(install, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	flowShards := logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
	clusterConfig := relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)

	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
	externalElasticsearch := externalelasticsearch.ExternalElasticsearch(install, clusterConfig, pullSecrets)
	if err := hdler.CreateOrUpdateOrDelete(ctx, externalElasticsearch, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}
