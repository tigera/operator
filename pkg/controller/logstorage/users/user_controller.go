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
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"

	corev1 "k8s.io/api/core/v1"
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

	octrl "github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/secret"
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
		return fmt.Errorf("log-storage-controller failed to watch LogStorage resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, "log-storage-users"); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if opts.MultiTenant {
		if err = c.Watch(&source.Kind{Type: &operatorv1.Tenant{}}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch Tenant resource: %w", err)
		}
	}

	return nil
}

func (r *UserController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - Users")

	var tenant *operatorv1.Tenant
	var err error
	if r.multiTenant {
		if request.Namespace == "" {
			// In multi-tenant mode, we only handle namespaced reconcile triggers.
			return reconcile.Result{}, nil
		}

		// Check if there is a manager in this namespace.
		tenant, err = utils.GetTenant(ctx, r.client, request.Namespace)
		if errors.IsNotFound(err) {
			// No tenant in this namespace. Ignore the update.
			reqLogger.Info("No Tenant in this Namespace, skip")
			return reconcile.Result{}, nil
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Get LogStorage resource.
	ls := &operatorv1.LogStorage{}
	key := utils.DefaultTSEEInstanceKey
	err = r.client.Get(ctx, key, ls)
	if err != nil {
		// Not finding the LogStorage CR is not an error, as a Managed cluster will not have this CR available but
		// there are still "LogStorage" related items that need to be set up
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}
		ls = nil
		r.status.OnCRNotFound()
	}

	// We found the LogStorage instance (and Tenant instance if in multi-tenant mode).
	r.status.OnCRFound()

	req := octrl.NewRequest(request.NamespacedName, r.multiTenant, render.ElasticsearchNamespace)
	args := ReconcileArgs{LogStorage: ls, Tenant: tenant}
	reqLogger = reqLogger.WithValues("installNS", req.InstallNamespace(), "truthNS", req.TruthNamespace())
	return r.reconcile(ctx, reqLogger, args, req)
}

type ReconcileArgs struct {
	LogStorage *operatorv1.LogStorage
	Tenant     *operatorv1.Tenant
}

func (r *UserController) reconcile(ctx context.Context, reqLogger logr.Logger, args ReconcileArgs, request octrl.Request) (reconcile.Result, error) {
	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if args.LogStorage.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	tenantID := ""
	if args.Tenant != nil {
		tenantID = args.Tenant.Spec.ID
		if tenantID == "" {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Tenant resource does not specify an ID", nil, reqLogger)
			return reconcile.Result{}, nil
		}
	}
	linseedUser := utils.LinseedUser(tenantID)

	// Query any existing username and password for this Linseed instance. If one already exists, we'll simply
	// use that. Otherwise, generate a new one.
	basicCreds := corev1.Secret{}
	credentialSecrets := []client.Object{}
	key := types.NamespacedName{Name: render.ElasticsearchLinseedUserSecret, Namespace: request.TruthNamespace()}
	if err := r.client.Get(ctx, key, &basicCreds); err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error getting Secret %s", key), err, reqLogger)
		return reconcile.Result{}, err
	} else if errors.IsNotFound(err) {
		// Create the secret to provision into the cluster.
		pw, err := randomPassword(16)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error generating Linseed password", err, reqLogger)
			return reconcile.Result{}, err
		}
		basicCreds = corev1.Secret{}
		basicCreds.Name = render.ElasticsearchLinseedUserSecret
		basicCreds.Namespace = request.TruthNamespace()
		basicCreds.StringData = map[string]string{"username": linseedUser.Username, "password": pw}

		// Make sure we install the generated credentials into the truth namespace.
		credentialSecrets = append(credentialSecrets, &basicCreds)
	}
	if request.TruthNamespace() != request.InstallNamespace() {
		// Copy the credentials into the install namespace.
		credentialSecrets = append(credentialSecrets, secret.CopyToNamespace(request.InstallNamespace(), &basicCreds)[0])
	}
	credentialComponent := render.NewPassthrough(credentialSecrets...)

	// In standard installs, the LogStorage owns the secret. For multi-tenant, it's owned by the Manager instance.
	var hdler utils.ComponentHandler
	if r.multiTenant {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, args.Tenant)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, args.LogStorage)
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
	// ES should be in ready phase when execution reaches here, apply ILM polices
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
		return fmt.Errorf("Unable to find password in secret")
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

func randomPassword(length int) (string, error) {
	byts := make([]byte, length)
	_, err := rand.Read(byts)

	return base64.URLEncoding.EncodeToString(byts), err
}
