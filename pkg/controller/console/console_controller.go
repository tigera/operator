package console

import (
	"context"
	"time"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
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

var log = logf.Log.WithName("controller_console")

// Add creates a new Console Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, openshift bool) error {
	return add(mgr, newReconciler(mgr, openshift))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, openshift bool) reconcile.Reconciler {
	return &ReconcileConsole{client: mgr.GetClient(), scheme: mgr.GetScheme(), openshift: openshift}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("console-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Console
	err = c.Watch(&source.Kind{Type: &operatorv1.Console{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO: Watch for dependent objects.
	return nil
}

var _ reconcile.Reconciler = &ReconcileConsole{}

// ReconcileConsole reconciles a Console object
type ReconcileConsole struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client    client.Client
	scheme    *runtime.Scheme
	openshift bool
}

// GetConsole returns the default console instance with defaults populated.
func GetConsole(ctx context.Context, cli client.Client, openshift bool) (*operatorv1.Console, error) {
	// Fetch the console instance. We only support a single instance named "default".
	instance := &operatorv1.Console{}
	var defaultInstanceKey = client.ObjectKey{Name: "default"}
	err := cli.Get(ctx, defaultInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	// Populate the instance with defaults for any fields not provided by the user.
	if instance.Spec.Auth == nil {
		instance.Spec.Auth = &operatorv1.Auth{
			Type:      operatorv1.AuthTypeToken,
			Authority: "",
			ClientID:  "",
		}
	}
	return instance, nil
}

// Reconcile reads that state of the cluster for a Console object and makes changes based on the state read
// and what is in the Console.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileConsole) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Console")

	// Fetch the Console instance
	instance, err := GetConsole(context.Background(), r.client, r.openshift)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Console object not found")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	installation, err := installation.GetInstallation(context.Background(), r.client, r.openshift)
	if err != nil {
		// TODO: Handle "does not exsit" vs other errors.
		return reconcile.Result{}, err
	}
	if installation.Status.Variant != operatorv1.TigeraSecureEnterprise {
		// TODO: Watch installation so we don't need to requeue.
		reqLogger.Info("Waiting for installed variant to be Tigera Secure")
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Fetch monitoring stack configuration.
	esConfig, err := utils.GetMonitoringConfig(context.Background(), r.client)
	if err != nil {
		// TODO: Handle "does not exsit" vs other errors.
		// TODO: Watch this resource so we don't need to poll.
		reqLogger.Info("Waiting for monitoring configuration")
		return reconcile.Result{}, err
	}

	// TODO: Fetch compliance. The manager depends on compliance existing so we should check that here.
	// TODO: Fetch apiserver . The manager depends on api server running so we should check that here.

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	component := render.Console(instance, esConfig, r.openshift, installation.Spec.Registry, r.client)
	if err := handler.CreateOrUpdate(context.Background(), component); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
