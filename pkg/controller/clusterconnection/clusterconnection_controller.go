// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"

	operatorv1 "github.com/tigera/operator/api/v1"
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

const controllerName = "clusterconnection-controller"

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
		Client:   cli,
		Scheme:   schema,
		Provider: p,
		status:   statusMgr,
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
	// Watch for changes to the secrets associated with the PacketCapture APIs.
	if err = utils.AddSecretsWatch(c, render.PrometheusTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.PrometheusTLSSecretName, err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Network resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
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
		log.Error(err, "Error reading ManagementCluster")
		r.status.SetDegraded("Error reading ManagementCluster", err.Error())
		return reconcile.Result{}, err
	}

	// Fetch the managementClusterConnection.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.Client)
	if err != nil {
		r.status.SetDegraded("Error querying ManagementClusterConnection", err.Error())
		return result, err
	} else if managementClusterConnection == nil {
		r.status.OnCRNotFound()
		return result, nil
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		log.Error(err, "")
		r.status.SetDegraded(err.Error(), "")
		return reconcile.Result{}, err
	}

	log.V(2).Info("Loaded ManagementClusterConnection config", "config", managementClusterConnection)
	r.status.OnCRFound()

	pullSecrets, err := utils.GetNetworkingPullSecrets(instl, r.Client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return result, err
	}

	// Copy the secret from the operator namespace to the guardian namespace if it is present.
	tunnelSecret := &corev1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()}, tunnelSecret)
	if err != nil {
		r.status.SetDegraded("Error retrieving secrets from guardian namespace", err.Error())
		if !k8serrors.IsNotFound(err) {
			return result, nil
		}
		return result, err
	}

	var packetCaptureServerCertSecret *corev1.Secret
	packetCaptureServerCertSecret, err = utils.ValidateCertPair(r.Client,
		common.OperatorNamespace(),
		render.PacketCaptureCertSecret,
		"", // We don't need the key.
		corev1.TLSCertKey,
	)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to retrieve %s", render.PacketCaptureCertSecret))
		r.status.SetDegraded(fmt.Sprintf("Failed to retrieve %s", render.PacketCaptureCertSecret), err.Error())
		return reconcile.Result{}, err
	} else if packetCaptureServerCertSecret == nil {
		reqLogger.Info(fmt.Sprintf("Waiting for secret '%s' to become available", render.PacketCaptureCertSecret))
		r.status.SetDegraded(fmt.Sprintf("Waiting for secret '%s' to become available", render.PacketCaptureCertSecret), "")
		return reconcile.Result{}, nil
	}

	prometheusCertSecret, err := utils.ValidateCertPair(r.Client,
		common.OperatorNamespace(),
		render.PrometheusTLSSecretName,
		"", // We don't need the key.
		corev1.TLSCertKey,
	)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("failed to retrieve %s", render.PrometheusTLSSecretName))
		r.status.SetDegraded(fmt.Sprintf("Failed to retrieve %s", render.PrometheusTLSSecretName), err.Error())
		return reconcile.Result{}, err
	} else if prometheusCertSecret == nil {
		reqLogger.Info(fmt.Sprintf("Waiting for secret '%s' to become available", render.PrometheusTLSSecretName))
		r.status.SetDegraded(fmt.Sprintf("Waiting for secret '%s' to become available", render.PrometheusTLSSecretName), "")
		return reconcile.Result{}, nil
	}

	ch := utils.NewComponentHandler(log, r.Client, r.Scheme, managementClusterConnection)
	guardianCfg := &render.GuardianConfiguration{
		URL:                  managementClusterConnection.Spec.ManagementClusterAddr,
		PullSecrets:          pullSecrets,
		Openshift:            r.Provider == operatorv1.ProviderOpenShift,
		Installation:         instl,
		TunnelSecret:         tunnelSecret,
		PacketCaptureSecret:  packetCaptureServerCertSecret,
		PrometheusCertSecret: prometheusCertSecret,
	}
	component := render.Guardian(guardianCfg)

	if err = imageset.ApplyImageSet(ctx, r.Client, variant, component); err != nil {
		log.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return result, err
	}

	r.status.ClearDegraded()

	//We should create the Guardian deployment.
	return result, nil
}
