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

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
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
	dpiAPIReady    *utils.ReadyFlag
	usePSP         bool
	multiTenant    bool
}

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// Create the reconciler
	r := &LinseedSubController{
		client:         mgr.GetClient(),
		scheme:         mgr.GetScheme(),
		clusterDomain:  opts.ClusterDomain,
		tierWatchReady: &utils.ReadyFlag{},
		dpiAPIReady:    &utils.ReadyFlag{},
		multiTenant:    opts.MultiTenant,
		status:         status.New(mgr.GetClient(), "log-storage-access", opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-access-controller", mgr, controller.Options{Reconciler: r})
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
		return fmt.Errorf("log-storage-access-controller failed to watch LogStorage resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.Installation{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch Installation resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, "log-storage-access"); err != nil {
		return fmt.Errorf("logstorage-access-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if opts.MultiTenant {
		if err = c.Watch(&source.Kind{Type: &operatorv1.Tenant{}}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-access-controller failed to watch Tenant resource: %w", err)
		}
	}

	// The namespace(s) we need to monitor depend upon what tenancy mode we're running in.
	// For single-tenant, everything is installed in the tigera-manager namespace.
	// Make a helper for determining which namespaces to use based on tenancy mode.
	helper := utils.NewNamespaceHelper(opts.MultiTenant, render.ElasticsearchNamespace, "")

	// Watch secrets this controller cares about.
	secretsToWatch := []string{
		render.TigeraElasticsearchGatewaySecret,
		render.TigeraLinseedSecret,
		render.LinseedTokenSecret,
		monitor.PrometheusClientTLSSecretName,
		render.ElasticsearchLinseedUserSecret,
	}

	// Determine namespaces to watch.
	namespacesToWatch := []string{helper.TruthNamespace(), helper.InstallNamespace()}
	if helper.TruthNamespace() == helper.InstallNamespace() {
		namespacesToWatch = []string{helper.InstallNamespace()}
	}
	for _, ns := range namespacesToWatch {
		for _, name := range secretsToWatch {
			if err := utils.AddSecretsWatch(c, name, ns); err != nil {
				return fmt.Errorf("log-storage-access-controller failed to watch Secret: %w", err)
			}
		}
	}

	// Catch if something modifies the resources that this controller consumes.
	if err := utils.AddServiceWatch(c, render.ElasticsearchServiceName, helper.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, helper.InstallNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch the Service resource: %w", err)
	}

	// Check if something modifies resources this controller creates.
	if err := utils.AddServiceWatch(c, esgateway.ServiceName, helper.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, render.LinseedServiceName, helper.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch Service resource: %w", err)
	}
	if err := utils.AddDeploymentWatch(c, render.LinseedServiceName, helper.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch Deployment resource: %w", err)
	}
	if err := utils.AddDeploymentWatch(c, esgateway.DeploymentName, helper.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch the Service resource: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to establish a connection to k8s: %w", err)
	}

	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, r.tierWatchReady)
	go utils.WaitToAddResourceWatch(c, k8sClient, log, r.dpiAPIReady, []client.Object{&v3.DeepPacketInspection{TypeMeta: metav1.TypeMeta{Kind: v3.KindDeepPacketInspection}}})

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, eventHandler)
	if err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (r *LinseedSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := utils.NewNamespaceHelper(r.multiTenant, render.ElasticsearchNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling LogStorage - Linseed")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.multiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// When running in multi-tenant mode, we need to install Linseed in tenant Namespaces. However, the LogStorage
	// resource is still cluster-scoped (since ES is a cluster-wide resource), so we need to look elsewhere to determine
	// which tenant namespaces require a Linseed instance. We use the tenant API to determine the set of namespaces that should have a Linseed.
	tenant, _, err := utils.GetTenant(ctx, r.multiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		reqLogger.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get LogStorage resource.
	logStorage := &operatorv1.LogStorage{}
	key := utils.DefaultTSEEInstanceKey
	err = r.client.Get(ctx, key, logStorage)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	}

	// We found the LogStorage instance (and Tenant instance if in multi-tenant mode).
	r.status.OnCRFound()

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if logStorage.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
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

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}
	if !r.dpiAPIReady.IsReady() {
		log.Info("Waiting for DeepPacketInspection API to be ready")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for DeepPacketInspection API to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, reqLogger)
			return reconcile.Result{}, err
		}
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

	// Wait for Elasticsearch to be installed and available.
	elasticsearch, err := utils.GetElasticsearch(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
		return reconcile.Result{}, err
	}
	if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Collect the certificates we need to provision Linseed. These will have been provisioned already by the ES secrets controller.
	opts := []certificatemanager.Option{
		certificatemanager.WithLogger(reqLogger),
		certificatemanager.WithTenant(tenant),
	}
	cm, err := certificatemanager.Create(r.client, install, r.clusterDomain, helper.TruthNamespace(), opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, helper.InstallNamespace(), r.clusterDomain)
	linseedKeyPair, err := cm.GetKeyPair(r.client, render.TigeraLinseedSecret, helper.TruthNamespace(), linseedDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Linseed KeyPair", err, reqLogger)
		return reconcile.Result{}, err
	} else if linseedKeyPair == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, fmt.Sprintf("Waiting for Linseed key pair (%s/%s) to exist", helper.TruthNamespace(), render.TigeraLinseedSecret), err, reqLogger)
		return reconcile.Result{}, nil
	}
	var tokenKeyPair certificatemanagement.KeyPairInterface
	if managementCluster != nil {
		tokenKeyPair, err = cm.GetKeyPair(r.client, render.TigeraLinseedTokenSecret, helper.TruthNamespace(), []string{render.TigeraLinseedTokenSecret})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Linseed token secret", err, reqLogger)
			return reconcile.Result{}, err
		} else if tokenKeyPair == nil {
			r.status.SetDegraded(operatorv1.ResourceNotFound, fmt.Sprintf("Waiting for Linseed key pair (%s/%s) to exist", helper.TruthNamespace(), render.TigeraLinseedTokenSecret), err, reqLogger)
			return reconcile.Result{}, nil
		}
	}

	// Query the trusted bundle from the namespace.
	trustedBundle, err := cm.LoadTrustedBundle(ctx, r.client, helper.InstallNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, reqLogger)
		return reconcile.Result{}, err
	}

	var esClusterConfig *relasticsearch.ClusterConfig
	if managementClusterConnection == nil {
		flowShards := logstoragecommon.CalculateFlowShards(logStorage.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
		esClusterConfig = relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, logStorage.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)
	}

	// Query the username and password this Linseed instance should use to authenticate with Elasticsearch.
	// For multi-tenant systems, credentials are created by the elasticsearch users controller.
	// For single-tenant system, these are created by es-kube-controllers.
	// Delay installing Linseed until available.
	// TODO: Switch single-tenant to using operator-provisioned users.
	key = types.NamespacedName{Name: render.ElasticsearchLinseedUserSecret, Namespace: helper.InstallNamespace()}
	if err = r.client.Get(ctx, key, &corev1.Secret{}); err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error getting Secret %s", key), err, reqLogger)
		return reconcile.Result{}, err
	} else if errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceNotFound, fmt.Sprintf("Waiting for Linseed credential Secret %s", key), err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	dpiList := &v3.DeepPacketInspectionList{}
	if err := r.client.List(ctx, dpiList); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve DeepPacketInspection resource", err, reqLogger)
		return reconcile.Result{}, err
	}
	hasDPIResource := len(dpiList.Items) != 0

	// Determine the namespaces to which we must bind the linseed cluster role.
	bindNamespaces, err := helper.TenantNamespaces(r.client)
	if err != nil {
		return reconcile.Result{}, err
	}

	cfg := &linseed.Config{
		Installation:      install,
		PullSecrets:       pullSecrets,
		Namespace:         helper.InstallNamespace(),
		BindNamespaces:    bindNamespaces,
		TrustedBundle:     trustedBundle,
		ClusterDomain:     r.clusterDomain,
		KeyPair:           linseedKeyPair,
		TokenKeyPair:      tokenKeyPair,
		UsePSP:            r.usePSP,
		ESClusterConfig:   esClusterConfig,
		HasDPIResource:    hasDPIResource,
		ManagementCluster: managementCluster != nil,
		Tenant:            tenant,
	}
	linseedComponent := linseed.Linseed(cfg)

	if err := imageset.ApplyImageSet(ctx, r.client, variant, linseedComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	// In standard installs, the LogStorage owns Linseed. For multi-tenant, it's owned by the Tenant instance.
	var hdler utils.ComponentHandler
	if r.multiTenant {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, tenant)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, logStorage)
	}
	if err := hdler.CreateOrUpdateOrDelete(ctx, linseedComponent, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !r.multiTenant {
		// TODO: For now, install this here. It probably should have its own controller.
		// I am not very familiar with this component - need to investigate and propose multi-tenant resolution.
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

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}
