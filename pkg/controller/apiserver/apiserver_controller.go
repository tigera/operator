package apiserver

import (
	"context"
	"fmt"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_apiserver")

// Add creates a new APIServer Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, openshift bool) error {
	return add(mgr, newReconciler(mgr, openshift))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, openshift bool) reconcile.Reconciler {
	return &ReconcileAPIServer{client: mgr.GetClient(), scheme: mgr.GetScheme(), openshift: openshift}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("apiserver-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create apiserver-controller: %v", err)
	}

	// Watch for changes to primary resource APIServer
	err = c.Watch(&source.Kind{Type: &operatorv1.APIServer{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create APIServer watch", "err", err)
		return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("apiserver-controller failed to watch Tigera network resource: %v", err)
	}

	// TODO: Watch for dependent objects.

	log.V(5).Info("Controller created and Watches setup")
	return nil
}

// blank assignment to verify that ReconcileAPIServer implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAPIServer{}

// ReconcileAPIServer reconciles a APIServer object
type ReconcileAPIServer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client    client.Client
	scheme    *runtime.Scheme
	openshift bool
}

// Reconcile reads that state of the cluster for a APIServer object and makes changes based on the state read
// and what is in the APIServer.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAPIServer) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling APIServer")

	ctx := context.Background()

	// Fetch the APIServer instance
	instance := &operatorv1.APIServer{}
	err := r.client.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(5).Info("APIServer CR not found", "err", err)
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		reqLogger.V(5).Info("failed to get APIServer CR", "err", err)
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)

	network, err := utils.GetTSEENetworkConfig(r.client)
	if err != nil {
		reqLogger.V(5).Info("error getting TSEE network config", "err", err)
		return reconcile.Result{}, nil
	} else if network == nil {
		reqLogger.V(5).Info("no TSEE network config available")
		return reconcile.Result{}, nil
	}

	// Check that if the apiserver certpair secret exists that it is valid (has key and cert fields)
	// If it does not exist then this function still returns true
	tlsSecret, err := utils.ValidateCertPair(r.client,
		render.APIServerTLSSecretName,
		render.APIServerSecretKeyName,
		render.APIServerSecretCertName,
		render.APIServerNamespace)
	if err != nil {
		log.Error(err, "Checking Ready for APIServer indicates error with TLS Cert")
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		log.Error(err, "Checking Ready for APIServer indicates error with Pull secrets")
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	reqLogger.V(5).Info("rendering components")
	// Render the desired objects from the CRD and create or update them.
	component := render.APIServer(network.Spec.Registry, tlsSecret, pullSecrets, r.openshift)
	if err := handler.CreateOrUpdate(context.Background(), component); err != nil {
		return reconcile.Result{}, err
	}

	instance.Status.State = operatorv1.APIServerStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
