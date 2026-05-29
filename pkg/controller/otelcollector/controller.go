// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package otelcollector

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/common/validation"
	otelvalidation "github.com/tigera/operator/pkg/common/validation/otelcollector"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render/otelcollector"
)

const (
	controllerName = "otel-collector-controller"
	ResourceName   = "otel-collector"
)

var log = logf.Log.WithName(controllerName)

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	statusManager := status.New(mgr.GetClient(), ResourceName, opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts)

	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	if err = c.WatchObject(&operatorv1.OpenTelemetryCollector{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("%s failed to watch TigeraStatus: %w", controllerName, err)
	}

	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to create periodic reconcile watch: %w", controllerName, err)
	}

	return nil
}

func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	opts options.ControllerOptions,
) *Reconciler {
	r := &Reconciler{
		cli:    cli,
		scheme: schema,
		status: statusMgr,
		opts:   opts,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	cli    client.Client
	scheme *runtime.Scheme
	status status.StatusManager
	opts   options.ControllerOptions
}

func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling OpenTelemetryCollector")

	instance, err := utils.GetIfExists[operatorv1.OpenTelemetryCollector](ctx, utils.DefaultEnterpriseInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying OpenTelemetryCollector CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if instance == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}
	r.status.OnCRFound()
	defer r.status.SetMetaData(&instance.ObjectMeta)

	variant, installationSpec, err := utils.GetInstallationSpec(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	} else if installationSpec == nil {
		return reconcile.Result{}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}
	if !utils.IsFeatureActive(license, common.OTelCollectorFeature) {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	if instance.Spec.OpenTelemetryCollectorDeployment != nil {
		if err := validation.ValidateReplicatedPodResourceOverrides(
			instance.Spec.OpenTelemetryCollectorDeployment,
			otelvalidation.ValidateOTelCollectorDeploymentContainer,
			validation.NoContainersDefined,
		); err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid deployment overrides", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	cfg := &otelcollector.Configuration{
		PullSecrets:            pullSecrets,
		OpenShift:              r.opts.DetectedProvider.IsOpenShift(),
		Installation:           installationSpec,
		OpenTelemetryCollector: instance,
	}

	component := otelcollector.OTelCollector(cfg)

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, instance)
	if err = imageset.ApplyImageSet(ctx, r.cli, variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	return reconcile.Result{}, nil
}
