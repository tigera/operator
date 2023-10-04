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

package users

import (
	"context"
	"fmt"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/crypto"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/secret"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_logstorage_users")

type UserController struct {
	client      client.Client
	scheme      *runtime.Scheme
	status      status.StatusManager
	multiTenant bool
}

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}
	if !opts.MultiTenant {
		// For now, the operator only creates users in multi-tenant mode. In single-tenant mode,
		// user creation is handled by es-kube-controllers instead.
		return nil
	}

	// Create the reconciler
	r := &UserController{
		client:      mgr.GetClient(),
		scheme:      mgr.GetScheme(),
		multiTenant: opts.MultiTenant,
		status:      status.New(mgr.GetClient(), "log-storage-users", opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-user-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenatn clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-user-controller failed to watch LogStorage resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-user-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-user-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, "log-storage-users"); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if opts.MultiTenant {
		if err = c.Watch(&source.Kind{Type: &operatorv1.Tenant{}}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-user-controller failed to watch Tenant resource: %w", err)
		}
	}

	// Watch for Elasticsearch.
	if err = c.Watch(&source.Kind{Type: &esv1.Elasticsearch{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-user-controller failed to watch Elasticsearch resource: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, eventHandler)
	if err != nil {
		return fmt.Errorf("log-storage-user-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (r *UserController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := utils.NewNamespaceHelper(r.multiTenant, render.ElasticsearchNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling LogStorage - Users")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.multiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// Check if this is a tenant-scoped request.
	tenant, tenantID, err := utils.GetTenant(ctx, r.multiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		reqLogger.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get LogStorage resource.
	logStorage := &operatorv1.LogStorage{}
	err = r.client.Get(ctx, utils.DefaultTSEEInstanceKey, logStorage)
	if err != nil {
		// Not finding the LogStorage CR is not an error, as a Managed cluster will not have this CR available but
		// there are still "LogStorage" related items that need to be set up
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	// We found the LogStorage instance (and Tenant instance if in multi-tenant mode).
	r.status.OnCRFound()

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if logStorage.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{}, nil
	}

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

	// Query any existing username and password for this Linseed instance. If one already exists, we'll simply
	// use that. Otherwise, generate a new one.
	linseedUser := utils.LinseedUser(tenantID)
	basicCreds := corev1.Secret{}
	var credentialSecrets []client.Object
	key := types.NamespacedName{Name: render.ElasticsearchLinseedUserSecret, Namespace: helper.TruthNamespace()}
	if err := r.client.Get(ctx, key, &basicCreds); err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error getting Secret %s", key), err, reqLogger)
		return reconcile.Result{}, err
	} else if errors.IsNotFound(err) {
		// Create the secret to provision into the cluster.
		basicCreds.Name = render.ElasticsearchLinseedUserSecret
		basicCreds.Namespace = helper.TruthNamespace()
		basicCreds.StringData = map[string]string{"username": linseedUser.Username, "password": crypto.GeneratePassword(16)}

		// Make sure we install the generated credentials into the truth namespace.
		credentialSecrets = append(credentialSecrets, &basicCreds)
	}
	if helper.TruthNamespace() != helper.InstallNamespace() {
		// Copy the credentials into the install namespace.
		credentialSecrets = append(credentialSecrets, secret.CopyToNamespace(helper.InstallNamespace(), &basicCreds)[0])
	}
	credentialComponent := render.NewPassthrough(credentialSecrets...)

	// In standard installs, the LogStorage owns the secret. For multi-tenant, it's owned by the tenant.
	var hdler utils.ComponentHandler
	if r.multiTenant {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, tenant)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, logStorage)
	}
	if err := hdler.CreateOrUpdateOrDelete(ctx, credentialComponent, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating Linseed user secret", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Now that the secret has been created, also provision the user in ES.
	if err := r.createLinseedLogin(ctx, tenantID, &basicCreds, reqLogger); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to create Linseed user in ES", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}

func (r *UserController) createLinseedLogin(ctx context.Context, tenantID string, secret *corev1.Secret, reqLogger logr.Logger) error {
	esClient, err := utils.NewElasticClient(r.client, ctx, relasticsearch.ElasticEndpoint())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to connect to Elasticsearch - failed to create the Elasticsearch client", err, reqLogger)
		return err
	}

	// Determine the password from the secret.
	password := secret.StringData["password"]
	if password == "" {
		password = string(secret.Data["password"])
	}
	if password == "" {
		return fmt.Errorf("unable to find password in secret")
	}

	// Create the user in ES.
	user := utils.LinseedUser(tenantID)
	user.Password = password
	if err = esClient.CreateUser(ctx, user); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to create or update Elasticsearch user", err, reqLogger)
		return err
	}

	return nil
}
