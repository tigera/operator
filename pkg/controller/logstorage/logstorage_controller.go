package logstorage

import (
	"context"
	"fmt"
	eckv1alpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1alpha1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	storagev1 "k8s.io/api/storage/v1"
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

var log = logf.Log.WithName("controller_logstorage")

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, provider operatorv1.Provider, tsee bool) error {
	if !tsee {
		return nil
	}
	return add(mgr, newReconciler(mgr, provider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operatorv1.Provider) reconcile.Reconciler {
	c := &ReconcileLogStorage{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		status:   status.New(mgr.GetClient(), "log-storage"),
		provider: provider,
	}

	c.status.Run()
	return c
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("log-storage-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource LogStorage
	err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Network resource: %v", err)
	}

	if err = c.Watch(&source.Kind{Type: &eckv1alpha1.Elasticsearch{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Elasticsearch resource: %v", err)
	}

	return nil
}

// blank assignment to verify that ReconcileLogStorage implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogStorage{}

// ReconcileLogStorage reconciles a LogStorage object
type ReconcileLogStorage struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	status   *status.StatusManager
	provider operatorv1.Provider
}

func GetLogStorage(ctx context.Context, cli client.Client) (*operatorv1.LogStorage, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// Reconcile reads that state of the cluster for a LogStorage object and makes changes based on the state read
// and what is in the LogStorage.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogStorage) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

	// This is added because we don't always render the operator statefulset
	r.status.SetStatefulSets([]types.NamespacedName{{Name: render.ECKOperatorName, Namespace: render.ECKOperatorNamespace}})

	ctx := context.Background()
	var isESReq, esExists, isOurs bool
	var err error
	// This is to stop a loop where we detects the Elasticsearch updates from the ECK operator and the ECK operator detects
	// the changes from this cluster (the update to the Elasticsearch resource here changes it, as the ECK cluster seems
	// to modify the Elasticsearch resource after this controller creates it)
	if isESReq, isOurs, esExists, err = r.isElasticsearchUpdate(ctx, request); err != nil {
		reqLogger.Error(err, "Error retrieving elasticsearch data")
		r.status.SetDegraded("Error retrieving elasticsearch data", err.Error())
		return reconcile.Result{}, err
	} else if isESReq && !isOurs {
		reqLogger.V(2).Info("not our es")
		// If this is an Elasticsearch update to the cluster we didn't create ignore it as there's nothing to update
		// from this information regarding the LogStorage resource
		return reconcile.Result{}, nil
	}

	// Fetch the LogStorage instance
	ls, err := GetLogStorage(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("LogStorage object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying LogStorage", err.Error())
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Loaded config", "config", ls)
	r.status.OnCRFound()

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

	if !isESReq || (isESReq && !esExists) {
		if ls.StorageClass() != nil {
			err := r.client.Get(ctx, client.ObjectKey{Name: ls.StorageClass().Name}, &storagev1.StorageClass{})
			if err != nil {
				r.status.SetDegraded(fmt.Sprintf("Couldn't find storage class %s", ls.StorageClass().Name), err.Error())
				return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
			}
		}

		hdler := utils.NewComponentHandler(log, r.client, r.scheme, ls)
		component, err := render.Elasticsearch(
			ls,
			r.provider == operatorv1.ProviderOpenShift,
			network.Spec.Registry,
		)
		if err != nil {
			reqLogger.Error(err, "Error rendering LogStorage")
			r.status.SetDegraded("Error rendering LogStorage", err.Error())
			return reconcile.Result{}, err
		}

		if err := hdler.CreateOrUpdate(ctx, component, r.status); err != nil {
			reqLogger.Error(err, "Error creating / update resource")
			r.status.SetDegraded("Error creating / updating resource", err.Error())
			return reconcile.Result{}, err
		}
	}

	if isOp, err := r.isElasticsearchOperational(ctx); err != nil {
		reqLogger.Error(err, "Error figuring out if elasticsearch is operational")
		r.status.SetDegraded("Error figuring out if elasticsearch is operational", err.Error())
		return reconcile.Result{}, err
	} else if !isOp {
		reqLogger.Info("waiting for elasticsearch to be operational")
		r.status.SetDegraded("waiting for elasticsearch cluster to be operational", "")
		ls.Status.State = operatorv1.LogStorageWaitingForElasticsearch
		if err := r.client.Status().Update(ctx, ls); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if err := r.createComponentUsers(ctx, ls); err != nil {

		r.status.SetDegraded("Error creating elasticsearch access components", err.Error())
		return reconcile.Result{}, err
	}

	ls.Status.State = operatorv1.LogStorageStatusReady
	if err := r.client.Status().Update(ctx, ls); err != nil {
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileLogStorage) isElasticsearchUpdate(ctx context.Context, request reconcile.Request) (bool, bool, bool, error) {
	isES := false
	isOurs := false
	exists := true

	if request.Name == render.ElasticsearchName && request.Namespace == render.ElasticsearchNamespace {
		isES = true
		isOurs = true
	}

	es := &eckv1alpha1.Elasticsearch{}
	if err := r.client.Get(ctx, request.NamespacedName, es); err != nil {
		if !errors.IsNotFound(err) {
			return false, false, false, err
		}
		exists = false
	}

	return isES, isOurs, exists, nil
}

func (r *ReconcileLogStorage) isElasticsearchOperational(ctx context.Context) (bool, error) {
	es := &eckv1alpha1.Elasticsearch{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, es); err != nil {
		return false, err
	} else if es.Status.Phase == "Operational" {
		return true, nil
	}

	return false, nil
}

func (r *ReconcileLogStorage) createComponentUsers(ctx context.Context, ls *operatorv1.LogStorage) error {
	component, err := utils.ElastisearchUsers(ctx, r.client)
	if err != nil {
		return err
	}

	hdler := utils.NewComponentHandler(log, r.client, r.scheme, ls)
	if err := hdler.CreateOrUpdate(ctx, component, r.status); err != nil {
		return err
	}

	return nil
}
