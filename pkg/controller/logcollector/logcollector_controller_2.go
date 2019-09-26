package logcollector

import (
	"context"
	"fmt"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/elasticsearchaccess"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"time"
)

var log = logf.Log.WithName("controller_log-collector")

func init() {
	elasticsearchaccess.AddComponent("tigera-log-collector", []string{"create_index", "write"})
}

// Add creates a new LogCollector Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, provider operatorv1.Provider, tsee bool) error {
	if !tsee {
		return nil
	}
	return add(mgr, newReconciler(mgr, provider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operatorv1.Provider) reconcile.Reconciler {
	c := &ReconcileLogCollector{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		status:   status.New(mgr.GetClient(), "log-collector"),
		provider: provider,
	}

	c.status.Run()

	return c
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("log-collector-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource LogCollector
	err = c.Watch(&source.Kind{Type: &operatorv1.LogCollector{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = utils.AddLogStorageWatch(c); err != nil {
		return fmt.Errorf("log-collector-controller failed to watch LogStorage resource: %v", err)
	}

	return nil
}

// blank assignment to verify that ReconcileLogCollector implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogCollector{}

// ReconcileLogCollector reconciles a LogCollector object
type ReconcileLogCollector struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	status   *status.StatusManager
	provider operatorv1.Provider
}

// Reconcile reads that state of the cluster for a LogCollector object and makes changes based on the state read
// and what is in the LogCollector.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogCollector) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogCollector")
	ctx := context.Background()

	r.status.SetDaemonsets([]types.NamespacedName{{Name: "tigera-fluentd-node", Namespace: "tigera-log-collector"}})

	// Fetch the LogCollector instance
	instance := &operatorv1.LogCollector{}
	err := r.client.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Error(err, "Couldn't find log-collector")
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	network, err := installation.GetInstallation(context.Background(), r.client, r.provider)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	if network.Status.Variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	}

	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// Fetch monitoring stack configuration.
	logStorage, err := utils.GetLogStorage(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Waiting for LogStorage to be set", "")
			return reconcile.Result{Requeue: true}, nil
		}

		log.Error(err, "Error reading monitoring config")
		r.status.SetDegraded("Error reading logstorage config", err.Error())
		return reconcile.Result{}, err
	}

	if logStorage.Status.State != operatorv1.LogStorageStatusReady {
		reqLogger.Error(err, "Elasticsearch cluster not ready, deferring until it is state: ", logStorage.Status.State)
		r.status.SetDegraded("Elasticsearch cluster not ready", "")
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	esAccess, err := utils.ElasticsearchAccess(ctx, "tigera-log-collector-elasticsearch-access", render.LogCollectorNamespace,
		logStorage.Spec.Certificate, r.client)
	if err != nil {
		r.status.SetDegraded("Couldn't generate the resources required for elasticsearch access", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)
	if err := handler.CreateOrUpdate(ctx, render.Fluentd(esAccess, pullSecrets), r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CRD status.
	instance.Status.State = operatorv1.LogCollectorStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
