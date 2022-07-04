// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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
	"fmt"
	"time"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	controllerName = "clusterconnection-controller"
	ResourceName   = "management-cluster-connection"
)

var log = logf.Log.WithName(controllerName)

// Add creates a new ManagementClusterConnection Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started. This controller is meant only for enterprise users.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	statusManager := status.New(mgr.GetClient(), "management-cluster-connection", opts.KubernetesVersion)
	return add(mgr, newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, opts))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(cli client.Client, schema *runtime.Scheme, statusMgr status.StatusManager, p operatorv1.Provider, opts options.AddOptions) reconcile.Reconciler {
	c := &ReconcileConnection{
		Client:        cli,
		Scheme:        schema,
		Provider:      p,
		status:        statusMgr,
		clusterDomain: opts.ClusterDomain,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// add adds a new controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	// Watch for changes to primary resource ManagementCluster
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	// Watch for changes to the secrets associated with the ManagementClusterConnection.
	if err = utils.AddSecretsWatch(c, render.GuardianSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.GuardianSecretName, err)
	}

	// Watch for changes to the secrets associated with the PacketCapture APIs.
	if err = utils.AddSecretsWatch(c, render.PacketCaptureCertSecret, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.PacketCaptureCertSecret, err)
	}
	// Watch for changes to the secrets associated with Prometheus.
	if err = utils.AddSecretsWatch(c, render.PrometheusTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.PrometheusTLSSecretName, err)
	}

	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, certificatemanagement.CASecretName, err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Network resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("clusterconnection-controller failed to watch management-cluster-connection Tigerastatus: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileConnection{}

// ReconcileConnection reconciles a ManagementClusterConnection object
type ReconcileConnection struct {
	Client        client.Client
	Scheme        *runtime.Scheme
	Provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
}

// Reconcile reads that state of the cluster for a ManagementClusterConnection object and makes changes based on the
// state read and what is in the ManagementClusterConnection.Spec. The Controller will requeue the Request to be
// processed again if the returned error is non-nil or Result.Requeue is true, otherwise upon completion it will
// remove the work from the queue.
func (r *ReconcileConnection) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling the management cluster connection")
	result := reconcile.Result{}

	variant, instl, err := utils.GetInstallation(ctx, r.Client)
	if err != nil {
		return result, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.Client)
	if err != nil {
		r.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch the managementClusterConnection.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.Client)
	if err != nil {
		r.SetDegraded(operatorv1.ResourceReadError, "Error querying ManagementClusterConnection", err, reqLogger)
		return result, err
	} else if managementClusterConnection == nil {
		r.status.OnCRNotFound()
		return result, nil
	}
	//Set the meta info in the tigerastatus like observedGenerations
	if managementClusterConnection != nil {
		defer r.status.SetMetaData(&managementClusterConnection.ObjectMeta)
	}

	// Changes for updating managementClusterConnection status conditions
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.Client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		managementClusterConnection.Status.Conditions = status.UpdateStatusCondition(managementClusterConnection.Status.Conditions, ts.Status.Conditions)
		if err := r.Client.Status().Update(ctx, managementClusterConnection); err != nil {
			log.WithValues("reason", err).Info("Failed to create managementClusterConnection status conditions.")
			return reconcile.Result{}, err
		}
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, err
	}

	log.V(2).Info("Loaded ManagementClusterConnection config", "config", managementClusterConnection)
	r.status.OnCRFound()

	pullSecrets, err := utils.GetNetworkingPullSecrets(instl, r.Client)
	if err != nil {
		r.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return result, err
	}

	certificateManager, err := certificatemanager.Create(r.Client, instl, r.clusterDomain)
	if err != nil {
		r.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Copy the secret from the operator namespace to the guardian namespace if it is present.
	tunnelSecret := &corev1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()}, tunnelSecret)
	if err != nil {
		r.SetDegraded(operatorv1.ResourceReadError, "Error retrieving secrets from guardian namespace", err, reqLogger)
		if !k8serrors.IsNotFound(err) {
			return result, nil
		}
		return result, err
	}

	trustedCertBundle := certificateManager.CreateTrustedBundle()
	for _, secretName := range []string{render.PacketCaptureCertSecret, render.PrometheusTLSSecretName} {
		secret, err := certificateManager.GetCertificate(r.Client, secretName, common.OperatorNamespace())
		if err != nil {
			r.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve %s", secretName), err, reqLogger)
			return reconcile.Result{}, err
		} else if secret == nil {
			reqLogger.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secretName))
			r.status.SetDegraded(string(operatorv1.ResourceNotReady), fmt.Sprintf("Waiting for secret '%s' to become available", secretName))
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		}
		trustedCertBundle.AddCertificates(secret)
	}

	ch := utils.NewComponentHandler(log, r.Client, r.Scheme, managementClusterConnection)
	guardianCfg := &render.GuardianConfiguration{
		URL:               managementClusterConnection.Spec.ManagementClusterAddr,
		PullSecrets:       pullSecrets,
		Openshift:         r.Provider == operatorv1.ProviderOpenShift,
		Installation:      instl,
		TunnelSecret:      tunnelSecret,
		TrustedCertBundle: trustedCertBundle,
	}
	component := render.Guardian(guardianCfg)

	if err = imageset.ApplyImageSet(ctx, r.Client, variant, component); err != nil {
		r.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return result, err
	}

	r.status.ClearDegraded()

	//We should create the Guardian deployment.
	return result, nil
}
func (r *ReconcileConnection) SetDegraded(reason operatorv1.TigeraStatusReason, message string, err error, log logr.Logger) {
	log.WithValues(string(reason), message).Error(err, string(reason))
	errormsg := ""
	if err != nil {
		errormsg = err.Error()
	}
	r.status.SetDegraded(string(reason), fmt.Sprintf("%s - Error: %s", message, errormsg))
}
