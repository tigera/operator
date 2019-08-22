package console

import (
	"context"
	"fmt"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
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
	c := &ReconcileConsole{
		client:    mgr.GetClient(),
		scheme:    mgr.GetScheme(),
		openshift: openshift,
		status:    status.New(mgr.GetClient(), "console"),
	}
	c.status.Run()
	return c

}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("console-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create console-controller: %v", err)
	}

	// Watch for changes to primary resource Console
	err = c.Watch(&source.Kind{Type: &operatorv1.Console{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("console-controller failed to watch primary resource: %v", err)
	}

	err = utils.AddAPIServerWatch(c)
	if err != nil {
		return fmt.Errorf("console-controller failed to watch APIServer resource: %v", err)
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
	status    *status.StatusManager
}

// GetConsole returns the default console instance with defaults populated.
func GetConsole(ctx context.Context, cli client.Client, openshift bool) (*operatorv1.Console, error) {
	// Fetch the console instance. We only support a single instance named "default".
	instance := &operatorv1.Console{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
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
			r.status.SetDegraded("Console not found", err.Error())
			r.status.ClearAvailable()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying Console", err.Error())
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.Enable()

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded("Waiting for Tigera API server to be ready", "")
		return reconcile.Result{}, nil
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	installation, err := installation.GetInstallation(context.Background(), r.client, r.openshift)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	// Fetch monitoring stack configuration.
	monitoringConfig, err := utils.GetMonitoringConfig(context.Background(), r.client)
	if err != nil {
		// TODO: Watch this so we don't need to poll.
		if errors.IsNotFound(err) {
			reqLogger.Info("Waiting for monitoring configuration")
			r.status.SetDegraded("MonitoringConfiguration not found", err.Error())
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, err
	}
	if err := utils.ValidateMonitoringConfig(monitoringConfig); err != nil {
		log.Error(err, "Monitoring config is not valid")
		r.status.SetDegraded("MonitoringConfiguration is not valid", err.Error())
		return reconcile.Result{}, err
	}

	// Check that if the manager certpair secret exists that it is valid (has key and cert fields)
	// If it does not exist then this function returns a nil secret but no error and a self-signed
	// certificate will be generated when rendering below.
	tlsSecret, err := utils.ValidateCertPair(r.client,
		render.ManagerTlsSecretName,
		render.ManagerSecretKeyName,
		render.ManagerSecretCertName,
		render.ManagerNamespace)
	if err != nil {
		log.Error(err, "Invalid TLS Cert")
		r.status.SetDegraded("Error validating TLS certificate", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	// TODO: Fetch compliance. The manager depends on compliance existing so we should check that here.

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	component := render.Console(
		instance,
		monitoringConfig,
		tlsSecret,
		pullSecrets,
		r.openshift,
		installation.Spec.Registry,
	)
	if err := handler.CreateOrUpdate(context.Background(), component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	if r.status.IsAvailable() {
		instance.Status.Auth = instance.Spec.Auth
		if err = r.client.Status().Update(context.Background(), instance); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}
