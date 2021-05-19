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

package monitoring

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
)

var log = logf.Log.WithName("controller_monitoring")

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}
	return add(mgr, newReconciler(mgr, opts))
}

func newReconciler(mgr manager.Manager, opts options.AddOptions) reconcile.Reconciler {
	r := &ReconcileMonitoring{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: opts.DetectedProvider,
		status:   status.New(mgr.GetClient(), "monitoring", opts.KubernetesVersion),
	}
	r.status.Run()
	return r
}

func add(mgr manager.Manager, r reconcile.Reconciler) error {
	c, err := controller.New("monitoring-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create monitoring-controller: %w", err)
	}

	// watch for primary resource changes
	if err = c.Watch(&source.Kind{Type: &operatorv1.Monitoring{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch primary resource: %w", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch Installation resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch ImageSet: %w", err)
	}

	// watch for prometheus resource changes
	if err = utils.AddAlertmanagerWatch(c); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch Alertmanager resource: %w", err)
	}

	if err = utils.AddPrometheusWatch(c); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch Prometheus resource: %w", err)
	}

	if err = utils.AddPodMonitorWatch(c); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch PodMonitor resource: %w", err)
	}

	if err = utils.AddPrometheusRuleWatch(c); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch PrometheusRule resource: %w", err)
	}

	if err = utils.AddServiceMonitorCalicoNodeWatch(c); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch ServiceMonitor calico-node-monitor resource: %w", err)
	}

	if err = utils.AddServiceMonitorElasticsearchWatch(c); err != nil {
		return fmt.Errorf("monitoring-controller failed to watch ServiceMonitor elasticsearch-metrics resource: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileMonitoring implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileMonitoring{}

type ReconcileMonitoring struct {
	client   client.Client
	scheme   *runtime.Scheme
	provider operatorv1.Provider
	status   status.StatusManager
}

func getMonitoring(ctx context.Context, cli client.Client) (*operatorv1.Monitoring, error) {
	instance := &operatorv1.Monitoring{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (r *ReconcileMonitoring) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Monitoring")

	instance, err := getMonitoring(ctx, r.client)
	if err != nil {
		if !errors.IsNotFound(err) {
			r.status.SetDegraded("An error occurred while querying Monitoring", err.Error())
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
	} else {
		r.status.OnCRFound()
	}

	variant, install, err := installation.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("An error occurred while querying Installation", err.Error())
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// render prometheus components
	component := render.Monitoring(install)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err := handler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	r.status.ClearDegraded()

	if instance != nil {
		instance.Status.State = operatorv1.TigeraStatusReady
		if err := r.client.Status().Update(ctx, instance); err != nil {
			reqLogger.Error(err, fmt.Sprintf("Error updating the monitoring status %s", operatorv1.TigeraStatusReady))
			r.status.SetDegraded(fmt.Sprintf("Error updating the monitoring status %s", operatorv1.TigeraStatusReady), err.Error())
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}
