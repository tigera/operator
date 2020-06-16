// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package clusterconnection

import (
	"context"
	"errors"
	"fmt"

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"

	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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

const controllerName = "clusterconnection-controller"

var log = logf.Log.WithName(controllerName)

// Add creates a new ManagementClusterConnection Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started. This controller is meant only for enterprise users.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnableEnterpriseControllers {
		// No need to start this controller.
		return nil
	}
	statusManager := status.New(mgr.GetClient(), "management-cluster-connection")
	return add(mgr, newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(cli client.Client, schema *runtime.Scheme, statusMgr status.StatusManager, p operatorv1.Provider) reconcile.Reconciler {
	c := &ReconcileConnection{
		Client:   cli,
		Scheme:   schema,
		Provider: p,
		status:   statusMgr,
	}
	c.status.Run()
	return c
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
	status   status.StatusManager
}

func GetClusterConnection(ctx context.Context, cli client.Client) (*operatorv1.ManagementClusterConnection, error) {
	mcc := &operatorv1.ManagementClusterConnection{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, mcc)
	return mcc, err
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

	instl, err := installation.GetInstallation(ctx, r.Client, r.Provider)
	if err != nil {
		return result, err
	}

	// Fetch the managementClusterConnection.
	mcc, err := GetClusterConnection(ctx, r.Client)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// If the resource is not found, we will not return an error. Instead, the watch on the resource will
			// re-trigger the reconcile function when the situation changes.
			if instl.Spec.ClusterManagementType == operatorv1.ClusterManagementTypeManaged {
				log.Error(err, "ManagementClusterConnection is a necessary resource for Managed clusters")
			}
			r.status.OnCRNotFound()
			return result, nil
		}
		r.status.SetDegraded("Error querying ManagementClusterConnection", err.Error())
		return result, err
	}
	log.V(2).Info("Loaded ManagementClusterConnection config", "config", mcc)
	r.status.OnCRFound()

	if instl.Spec.ClusterManagementType != operatorv1.ClusterManagementTypeManaged {
		err = errors.New(fmt.Sprintf("Cannot establish tunnel unless Installation.clusterManagementType = %v",
			operatorv1.ClusterManagementTypeManaged))
		log.Error(err, "")
		r.status.SetDegraded(err.Error(), err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(instl, r.Client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return result, err
	}

	// Copy the secret from the operator namespace to the guardian namespace if it is present.
	tunnelSecret := &corev1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: render.OperatorNamespace()}, tunnelSecret)
	if err != nil {
		r.status.SetDegraded("Error copying secrets to the guardian namespace", err.Error())
		if !k8serrors.IsNotFound(err) {
			return result, nil
		}
		return result, err
	}

	ch := utils.NewComponentHandler(log, r.Client, r.Scheme, mcc)
	component := render.Guardian(
		mcc.Spec.ManagementClusterAddr,
		pullSecrets,
		r.Provider == operatorv1.ProviderOpenShift,
		instl,
		tunnelSecret,
	)

	if err := ch.CreateOrUpdate(ctx, component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return result, err
	}

	r.status.ClearDegraded()

	//We should create the Guardian deployment.
	return result, nil
}
