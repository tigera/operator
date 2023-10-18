// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package cleanup

import (
	"context"
	"fmt"
	"strings"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	corev1 "k8s.io/api/core/v1"
	apiv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_logstorage_cleanup")

type CleanupController struct {
	client      client.Client
	scheme      *runtime.Scheme
	status      status.StatusManager
	esClientFn  utils.ElasticsearchClientCreator
	multiTenant bool
}

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.MultiTenant {
		// This controller is only meant to run alongside other multi-tenant exclusive controllers
		return nil
	}

	r := &CleanupController{
		client:      mgr.GetClient(),
		scheme:      mgr.GetScheme(),
		multiTenant: opts.MultiTenant,
		status:      status.New(mgr.GetClient(), "log-storage-cleanup", opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-cleanup-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	if err = c.Watch(&source.Kind{Type: &operatorv1.Tenant{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-cleanup-controller failed to watch Tenant resource: %w", err)
	}

	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-cleanup-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (r *CleanupController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := utils.NewNamespaceHelper(r.multiTenant, render.ElasticsearchNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling LogStorage - Cleanup")

	// Wait for Elasticsearch to be installed and available.
	elasticsearch, err := utils.GetElasticsearch(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
		return reconcile.Result{}, err
	}
	if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Clean up any stale users that may have been left behind by a previous tenant
	if err := r.cleanupStaleUsers(ctx, reqLogger); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failure occurred while cleaning up stale users", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}

func (r *CleanupController) cleanupStaleUsers(ctx context.Context, logger logr.Logger) error {
	esClient, err := r.esClientFn(r.client, ctx, relasticsearch.ElasticEndpoint())
	if err != nil {
		return fmt.Errorf("failed to connect to Elasticsearch - failed to create the Elasticsearch client")
	}

	allESUsers, err := esClient.GetUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch users from Elasticsearch")
	}

	tenants := operatorv1.TenantList{}
	err = r.client.List(ctx, &tenants)
	if err != nil {
		return fmt.Errorf("failed to fetch TenantList")
	}

	// TODO: Fetch cluster UUID and use it to filter out stale users from clusters other than our own. The exact form
	// this will take is TBD. However the cluster UUID is stored/fetched should be immutable to prevent the possibility
	// of a change in cluster-id resulting in orphaned users
	clusterIDConfigMap := corev1.ConfigMap{
		ObjectMeta: apiv1.ObjectMeta{
			Name:      "cluster-info",
			Namespace: "tigera-operator",
		},
	}
	err = r.client.Get(ctx, client.ObjectKey{Name: "cluster-info", Namespace: "tigera-operator"}, &clusterIDConfigMap)
	if err != nil {
		return fmt.Errorf("failed to fetch cluster-info configmap")
	}

	clusterID := clusterIDConfigMap.Data["cluster-id"]

	for _, user := range allESUsers {
		if strings.HasPrefix(user.Username, fmt.Sprintf("%s_%s_", utils.ElasticsearchUserNameLinseed, clusterID)) {
			active := false
			for _, t := range tenants.Items {
				if strings.Contains(user.Username, t.Spec.ID) {
					active = true
					break
				}
			}
			if !active {
				err = esClient.DeleteUser(ctx, &user)
				if err != nil {
					logger.Error(err, "Failed to delete elastic user")
				}
			}
		}
	}

	return nil
}
