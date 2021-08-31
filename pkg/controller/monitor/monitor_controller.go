// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package monitor

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
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

	"github.com/go-logr/logr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/monitor"
)

var log = logf.Log.WithName("controller_monitor")

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	var prometheusReady = &utils.ReadyFlag{}

	// Create the reconciler
	reconciler := newReconciler(mgr, opts, prometheusReady)

	// Create a new controller
	controller, err := controller.New("monitor-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create monitor-controller: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	go waitToAddPrometheusWatch(controller, k8sClient, log, prometheusReady)

	return add(mgr, controller)
}

func newReconciler(mgr manager.Manager, opts options.AddOptions, prometheusReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileMonitor{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "monitor", opts.KubernetesVersion),
		prometheusReady: prometheusReady,
	}

	r.status.AddStatefulSets([]types.NamespacedName{
		{Namespace: common.TigeraPrometheusNamespace, Name: fmt.Sprintf("alertmanager-%s", monitor.CalicoNodeAlertmanager)},
		{Namespace: common.TigeraPrometheusNamespace, Name: fmt.Sprintf("prometheus-%s", monitor.CalicoNodePrometheus)},
	})

	r.status.Run(opts.ShutdownContext)
	return r
}

func add(mgr manager.Manager, c controller.Controller) error {
	var err error

	// watch for primary resource changes
	if err = c.Watch(&source.Kind{Type: &operatorv1.Monitor{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("monitor-controller failed to watch primary resource: %w", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("monitor-controller failed to watch Installation resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("monitor-controller failed to watch ImageSet: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileMonitor implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileMonitor{}

type ReconcileMonitor struct {
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	prometheusReady *utils.ReadyFlag
}

func (r *ReconcileMonitor) getMonitor(ctx context.Context) (*operatorv1.Monitor, error) {
	instance := &operatorv1.Monitor{}
	err := r.client.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (r *ReconcileMonitor) setDegraded(reqLogger logr.Logger, err error, msg string) {
	reqLogger.Error(err, msg)
	r.status.SetDegraded(msg, err.Error())
}

func (r *ReconcileMonitor) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Monitor")

	instance, err := r.getMonitor(ctx)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.setDegraded(reqLogger, err, "Failed to query Monitor")
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	variant, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.setDegraded(reqLogger, err, "Installation not found")
			return reconcile.Result{}, err
		}
		r.setDegraded(reqLogger, err, "Failed to query Installation")
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(install, r.client)
	if err != nil {
		r.setDegraded(reqLogger, err, "Error retrieving pull secrets")
		return reconcile.Result{}, err
	}

	if !r.prometheusReady.IsReady() {
		err = fmt.Errorf("waiting for Prometheus resources")
		r.setDegraded(reqLogger, err, "Waiting for Prometheus resources to be ready")
		return reconcile.Result{}, err
	}

	// checks for an existing configmap
	tigeraPrometheusAPIConfigMap, err := r.getTigeraPrometheusAPIConfigMap()

	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("No ConfigMap found, a default one will be created.")
		} else {
			r.setDegraded(reqLogger, err, "Internal error attempting to retrieve ConfigMap")
			return reconcile.Result{}, err
		}
	}

	// Create a component handler to manage the rendered component.
	hdler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// render prometheus components
	alertmanagerConfigSecret, err := r.getAlertmanagerConfigSecret(ctx)
	if err != nil {
		r.setDegraded(reqLogger, err, "Error retrieving Alertmanager configuration secret")
		return reconcile.Result{}, err
	}
	component := monitor.Monitor(install, pullSecrets, alertmanagerConfigSecret)

	// renders tigera prometheus api
	tigeraPrometheusApi, err := monitor.TigeraPrometheusAPI(install, pullSecrets, tigeraPrometheusAPIConfigMap)

	if err != nil {
		return reconcile.Result{}, err
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component, tigeraPrometheusApi); err != nil {
		r.setDegraded(reqLogger, err, "Error with images from ImageSet")
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.setDegraded(reqLogger, err, "Error creating / updating resource")
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, tigeraPrometheusApi, r.status); err != nil {
		r.setDegraded(reqLogger, err, "Error creating / updating tigera-prometheus-api")
		return reconcile.Result{}, err
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	instance.Status.State = operatorv1.TigeraStatusReady
	if err := r.client.Status().Update(ctx, instance); err != nil {
		r.setDegraded(reqLogger, err, fmt.Sprintf("Error updating the monitor status %s", operatorv1.TigeraStatusReady))
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// getTigeraPrometheusAPIConfigMap attempts to retrieve an existing ConfigMap for tigera-prometheus-api
func (r *ReconcileMonitor) getTigeraPrometheusAPIConfigMap() (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      monitor.TigeraPrometheusAPIName,
		Namespace: common.OperatorNamespace(),
	}

	if err := r.client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		return nil, err
	}
	return cm, nil
}

// getAlertmanagerConfigSecret attempts to retrieve Alertmanager configuration secret from either the Tigera Operator
// namespace or the Tigera Prometheus namespace.
func (r *ReconcileMonitor) getAlertmanagerConfigSecret(ctx context.Context) (*corev1.Secret, error) {
	// Previous to this change, a customer was expected to deploy the Alertmanager configuration secret
	// in the tigera-prometheus namespace directly. Now that this secret is managed by the Operator,
	// the customer must deploy this secret in the tigera-operator namespace. The Operator then copies
	// the secret from the tigera-operator namespace to the tigera-prometheus namespace.
	//
	// For new installation:
	//   A new secret will be created in the tigera-operator namespace and then copied to the tigera-prometheus namespace.
	//
	// To handle upgrades:
	//   The tigera-prometheus secret will be copied back to the tigera-operator namespace in case of any changes from the user.
	//
	// Tigera Operator will then watch for secret changes in the tigera-operator namespace and overwrite
	// any changes for this secret in the tigera-prometheus namespace.
	//
	// TODO Add logic for future Alertmanager manager configuration upgrades.

	secret, err := utils.GetSecret(ctx, r.client, monitor.AlertmanagerConfigSecret, common.OperatorNamespace())
	if err != nil {
		return nil, err
	}
	if secret != nil {
		return secret, nil
	}

	secret, err = utils.GetSecret(ctx, r.client, monitor.AlertmanagerConfigSecret, common.TigeraPrometheusNamespace)
	if err != nil {
		return nil, err
	}
	if secret != nil {
		return rsecret.CopyToNamespace(common.OperatorNamespace(), secret)[0], nil
	}

	return nil, nil
}
