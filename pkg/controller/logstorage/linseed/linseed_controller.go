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

package linseed

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/tigera/operator/pkg/common"
	octrl "github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	omanager "github.com/tigera/operator/pkg/controller/manager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_logstorage_linseed")

type LinseedSubController struct {
	client         client.Client
	scheme         *runtime.Scheme
	status         status.StatusManager
	clusterDomain  string
	tierWatchReady *utils.ReadyFlag
	usePSP         bool
	multiTenant    bool
}

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// Create the reconciler
	r := &LinseedSubController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		clusterDomain: opts.ClusterDomain,
		multiTenant:   opts.MultiTenant,
		status:        status.New(mgr.GetClient(), "log-storage-access", opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-access-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Network resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, "log-storage-access"); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if opts.MultiTenant {
		if err = c.Watch(&source.Kind{Type: &operatorv1.Manager{}}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch Manager resource: %w", err)
		}
	}

	// The namespace(s) we need to monitor depend upon what tenancy mode we're running in.
	// For single-tenant, everything is installed in the tigera-manager namespace.
	installNS := render.ManagerNamespace
	truthNS := common.OperatorNamespace()
	if opts.MultiTenant {
		// For multi-tenant, the manager could be installed in any number of namespaces.
		// So, we need to watch the resources we care about across all namespaces.
		installNS = ""
		truthNS = ""
	}

	// Watch all the elasticsearch user secrets.
	// TODO: In the future, we may want put this logic in the utils folder where the other watch logic is.
	if err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Object.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.Object.GetNamespace() == truthNS && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.ObjectNew.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.ObjectNew.GetNamespace() == truthNS && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Object.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.Object.GetNamespace() == truthNS && hasLabel
		},
	}); err != nil {
		return err
	}

	// Watch secrets this controller cares about.
	for _, secretName := range []string{
		render.TigeraElasticsearchGatewaySecret,
		render.TigeraLinseedSecret,
		monitor.PrometheusClientTLSSecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, truthNS); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
		}
	}

	// Catch if something modifies the resources that this controller consumes.
	if err := utils.AddServiceWatch(c, render.ElasticsearchServiceName, installNS); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}

	// Check if something modifies resources this controller creates.
	// TODO
	if err := utils.AddServiceWatch(c, esgateway.ServiceName, installNS); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, render.LinseedServiceName, installNS); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	return nil
}

func (r *LinseedSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - Linseed")

	// When running in multi-tenant mode, we need to install Linseed in tenant Namespaces. However, the LogStorage
	// resource is still cluster-scoped (since ES is a cluster-wide resource), so we need to look elsewhere to determine
	// which tenant namespaces require a Linseed instance. We use the manager API to determine the set of namespaces that should have a Linseed.
	var manager *operatorv1.Manager
	var err error
	if r.multiTenant {
		if request.Namespace == "" {
			// In multi-tenant mode, we only handle namespaced reconcile triggers.
			return reconcile.Result{}, nil
		}

		// Check if there is a manager in this namespace.
		manager, err = omanager.GetManager(ctx, r.client, request.Namespace)
		if errors.IsNotFound(err) {
			// No manager in this namespace. Ignore the update.
			reqLogger.Info("No Manager in this Namespace, skip")
			return reconcile.Result{}, nil
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Manager", err, reqLogger)
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

	// We found the LogStorage instance (and Manager instance if in multi-tenant mode).
	r.status.OnCRFound()

	req := octrl.NewRequest(request.NamespacedName, r.multiTenant, render.ElasticsearchNamespace)
	args := ReconcileArgs{LogStorage: ls, Manager: manager}
	return r.reconcile(ctx, reqLogger, args, req)
}

type ReconcileArgs struct {
	LogStorage *operatorv1.LogStorage
	Manager    *operatorv1.Manager
}

func (r *LinseedSubController) reconcile(ctx context.Context, reqLogger logr.Logger, args ReconcileArgs, request octrl.Request) (reconcile.Result, error) {
	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if args.LogStorage.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Get Installation resource.
	variant, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}
	if managementClusterConnection != nil {
		// Linseed is only relevant for management and standalone clusters. If this is a managed cluster, we can
		// simply return early.
		// TODO: Handle switch from standalone -> managed
		reqLogger.V(1).Info("Not installing Linseed on managed cluster")
		return reconcile.Result{}, nil
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(install, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving the pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Collect the certificates we need to provision Linseed. These will have been provisioned already by the ES secrets controller.
	cm, err := certificatemanager.Create(r.client, install, r.clusterDomain, request.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	linseedKeyPair, err := cm.GetKeyPair(r.client, render.TigeraLinseedSecret, request.InstallNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Linseed KeyPair", err, reqLogger)
		return reconcile.Result{}, err
	}
	tokenKeyPair, err := cm.GetKeyPair(r.client, render.TigeraLinseedTokenSecret, request.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Linseed token secret", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Prior to rendering, make sure all the upstream dependencies we need are present. If we're missing anything, we'll wait until it's ready.
	if linseedKeyPair == nil || tokenKeyPair == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for Linseed key pair(s) to exist", err, reqLogger)
		return reconcile.Result{}, nil
	}

	// Create a trusted bundle to pass to the render pacakge. The actual contents of this bundle don't matter - the ConfigMap
	// itself will be managed by the Secret controller. But, we need an interface to use as an argument to render in order
	// to configure volume mounts properly.
	trustedBundle := certificatemanagement.CreateTrustedBundle()

	var esClusterConfig *relasticsearch.ClusterConfig
	if managementClusterConnection == nil {
		flowShards := logstoragecommon.CalculateFlowShards(args.LogStorage.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
		esClusterConfig = relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, args.LogStorage.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)
	}

	cfg := &linseed.Config{
		Installation:      install,
		PullSecrets:       pullSecrets,
		Namespace:         request.InstallNamespace(),
		TrustedBundle:     trustedBundle,
		ClusterDomain:     r.clusterDomain,
		KeyPair:           linseedKeyPair,
		TokenKeyPair:      tokenKeyPair,
		UsePSP:            r.usePSP,
		ESClusterConfig:   esClusterConfig,
		ManagementCluster: managementCluster != nil,
	}
	linseedComponent := linseed.Linseed(cfg)

	if err := imageset.ApplyImageSet(ctx, r.client, variant, linseedComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	// In standard installs, the LogStorage owns Linseed. For multi-tenant, it's owned by the Manager instance.
	var hdler utils.ComponentHandler
	if r.multiTenant {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, args.Manager)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, args.LogStorage)
	}
	for _, comp := range []render.Component{linseedComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// TODO: Do we need either of these for multi-tenant systems?
	if !r.multiTenant {
		// TODO: For now, just do ESGW here since it serves a similar purpose to Linseed.
		if err := r.createESGateway(
			install,
			variant,
			pullSecrets,
			hdler,
			reqLogger,
			ctx,
			trustedBundle,
			r.usePSP,
		); err != nil {
			return reconcile.Result{}, err
		}

		// TODO: For now, install this here. It probably should have its own controller.
		if err := r.createESMetrics(
			install,
			variant,
			managementClusterConnection,
			pullSecrets,
			reqLogger,
			esClusterConfig,
			ctx,
			hdler,
			trustedBundle,
			r.usePSP,
			cm,
		); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}
