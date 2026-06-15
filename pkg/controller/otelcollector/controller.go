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
	"github.com/tigera/operator/pkg/common/validation"
	otelvalidation "github.com/tigera/operator/pkg/common/validation/otelcollector"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/render/otelcollector"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	controllerName = "log-collector-otel-controller"
	ResourceName   = "log-collector-otel"
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

	if err = c.WatchObject(&operatorv1.LogCollector{}, &handler.EnqueueRequestForObject{}); err != nil {
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
	reqLogger.V(2).Info("Reconciling OTelCollector")

	logCollector, err := utils.GetIfExists[operatorv1.LogCollector](ctx, utils.DefaultEnterpriseInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying LogCollector CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if logCollector == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	if logCollector.Spec.OTelCollector == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	r.status.OnCRFound()
	defer r.status.SetMetaData(&logCollector.ObjectMeta)

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

	if logCollector.Spec.OTelCollector.OTelCollectorStatefulSet != nil {
		if err := validation.ValidateReplicatedPodResourceOverrides(
			logCollector.Spec.OTelCollector.OTelCollectorStatefulSet,
			otelvalidation.ValidateOTelCollectorStatefulSetContainer,
			validation.NoContainersDefined,
		); err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid statefulSet overrides", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	var clientTLSSecret certificatemanagement.KeyPairInterface
	var trustedBundle certificatemanagement.TrustedBundleRO
	metricsEnabled := logCollector.Spec.OTelCollector.Metrics != nil &&
		logCollector.Spec.OTelCollector.Metrics.Enabled != nil &&
		*logCollector.Spec.OTelCollector.Metrics.Enabled == operatorv1.OTelMetricsEnable

	if metricsEnabled {
		certMgr, err := certificatemanager.Create(r.cli, installationSpec, r.opts.ClusterDomain, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
			return reconcile.Result{}, err
		}

		clientTLSSecret, err = certMgr.GetOrCreateKeyPair(r.cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}

		trustedBundle = certMgr.CreateTrustedBundle()
		certMgr.AddToStatusManager(r.status, otelcollector.OTelCollectorNamespace)
	}

	cfg := &otelcollector.Configuration{
		PullSecrets:       pullSecrets,
		OpenShift:         r.opts.DetectedProvider.IsOpenShift(),
		Installation:      installationSpec,
		OTelCollector:     logCollector.Spec.OTelCollector,
		ClientTLSSecret:   clientTLSSecret,
		TrustedCertBundle: trustedBundle,
	}

	component := otelcollector.OTelCollector(cfg)

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, logCollector)
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
