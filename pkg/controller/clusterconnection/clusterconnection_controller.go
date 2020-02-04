package clusterconnection

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	corev1 "k8s.io/api/core/v1"
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
)

var log = logf.Log.WithName("clusterconnection_controller")

const controllerName = "clusterconnection-controller"

// Add creates a new ManagementClusterConnection Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started. This controller is meant only for enterprise users.
func Add(mgr manager.Manager, p operatorv1.Provider, enterpriseEnabled bool) error {
	if !enterpriseEnabled {
		// No need to start this controller.
		return nil
	}
	return add(mgr, newReconciler(mgr, p))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, p operatorv1.Provider) reconcile.Reconciler {
	return &ReconcileConnection{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Provider: p,
	}
}

// add adds a new controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", controllerName, err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %v", controllerName, err)
	}

	// Watch for changes to the secrets associated with the ManagementClusterConnection.
	if err = utils.AddSecretsWatch(c, render.GuardianSecretName, render.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %v", controllerName, render.GuardianSecretName, err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Network resource: %v", controllerName, err)
	}

	return nil
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileConnection{}

// ReconcileConnection reconciles a ManagementClusterConnection object
type ReconcileConnection struct {
	Client   client.Client
	Scheme   *runtime.Scheme
	Provider operatorv1.Provider
}

// Reconcile reads that state of the cluster for a ManagementClusterConnection object and makes changes based on the
// state read and what is in the ManagementClusterConnection.Spec. The Controller will requeue the Request to be
// processed again if the returned error is non-nil or Result.Requeue is true, otherwise upon completion it will
// remove the work from the queue.
func (r *ReconcileConnection) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling the management cluster connection")
	ctx := context.Background()
	result := reconcile.Result{}

	instl, err := installation.GetInstallation(context.Background(), r.Client, r.Provider)
	if err != nil {
		return result, err
	}

	// Fetch the managementClusterConnection.
	mcc := &operatorv1.ManagementClusterConnection{}
	err = r.Client.Get(ctx, utils.DefaultTSEEInstanceKey, mcc)

	if err != nil {
		if errors.IsNotFound(err) {
			// If the resource is not found, we will not return an error. Instead, the watch on the resource will
			// re-trigger the reconcile function when the situation changes.
			if instl.Spec.ClusterManagementType == operatorv1.ClusterManagementTypeManaged {
				log.Error(err, "ManagementClusterConnection is a necessary resource for Managed clusters")
			}
			return result, nil
		}
		return result, err
	}

	if instl.Spec.ClusterManagementType != operatorv1.ClusterManagementTypeManaged {
		log.Info(fmt.Sprintf("Setting up management cluster connection, even though clusterType != %v",
			operatorv1.ClusterManagementTypeManaged))
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(instl, r.Client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		return result, err
	}

	// Copy the secret from the operator namespace to the guardian namespace if it is present.
	tunnelSecret := &corev1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: render.OperatorNamespace()}, tunnelSecret)
	if err != nil {
		if !errors.IsNotFound(err) {
			return result, nil
		}
		return result, err
	}

	ch := utils.NewComponentHandler(log, r.Client, r.Scheme, mcc)
	component := render.Guardian(
		mcc.Spec.ManagementClusterAddr,
		pullSecrets,
		r.Provider == operatorv1.ProviderOpenShift,
		instl.Spec.Registry,
		tunnelSecret,
	)

	if err := ch.CreateOrUpdate(ctx, component, nil); err != nil {
		return result, err
	}

	//We should create the Guardian deployment.
	return result, nil
}
