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
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
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

	// Watch all the elasticsearch user secrets in the operator namespace.
	// TODO: In the future, we may want put this logic in the utils folder where the other watch logic is.
	if err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Object.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.Object.GetNamespace() == common.OperatorNamespace() && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.ObjectNew.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.ObjectNew.GetNamespace() == common.OperatorNamespace() && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Object.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.Object.GetNamespace() == common.OperatorNamespace() && hasLabel
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
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
		}
	}

	// Catch if something modifies the resources that this controller consumes.
	if err := utils.AddServiceWatch(c, render.ElasticsearchServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}

	// Check if something modifies resources this controller creates.
	// TODO
	if err := utils.AddServiceWatch(c, esgateway.ServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, render.LinseedServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	return nil
}

func (r *LinseedSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - Linseed")

	// Get LogStorage resource.
	ls := &operatorv1.LogStorage{}
	key := utils.DefaultTSEEInstanceKey
	err := r.client.Get(ctx, key, ls)
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

	// We found the LogStorage instance.
	// TODO: Wait for defaults to be filled before continuing.
	r.status.OnCRFound()

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
	cm, err := certificatemanager.Create(r.client, install, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	linseedKeyPair, err := cm.GetKeyPair(r.client, render.TigeraLinseedSecret, render.ElasticsearchNamespace)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Linseed KeyPair", err, log)
		return reconcile.Result{}, err
	}
	tokenKeyPair, err := cm.GetKeyPair(r.client, render.TigeraLinseedTokenSecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Linseed token secret", err, log)
		return reconcile.Result{}, err
	}

	// Prior to rendering, make sure all the upstream dependencies we need are present. If we're missing anything, we'll wait until it's ready.
	if linseedKeyPair == nil || tokenKeyPair == nil {
		return reconcile.Result{}, nil
	}

	// Create a trusted bundle to pass to the render pacakge. The actual contents of this bundle don't matter - the ConfigMap
	// itself will be managed by the Secret controller. But, we need an interface to use as an argument to render in order
	// to configure volume mounts properly.
	trustedBundle := certificatemanagement.CreateTrustedBundle()

	var esClusterConfig *relasticsearch.ClusterConfig
	if managementClusterConnection == nil {
		flowShards := logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
		esClusterConfig = relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)
	}

	cfg := &linseed.Config{
		Installation:      install,
		PullSecrets:       pullSecrets,
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

	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
	for _, comp := range []render.Component{linseedComponent} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

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

	return reconcile.Result{}, nil
}
