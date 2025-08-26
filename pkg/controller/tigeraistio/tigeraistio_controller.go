// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package tigeraistio

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	renderistio "github.com/tigera/operator/pkg/render/tigeraistio"
)

var (
	// blank assignment to verify that ReconcileTigeraIstio implements reconcile.Reconciler
	_ reconcile.Reconciler = &ReconcileTigeraIstio{}

	log = logf.Log.WithName("controller_tigeraistio")
)

// Add creates a new TigeraIstio Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
//
// Start Watches within the Add function for any resources that this controller creates or monitors. This will trigger
// calls to Reconcile() when an instance of one of the watched resources is modified.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	r := newReconciler(mgr, opts)

	c, err := ctrlruntime.NewController("tigeraistio-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create tigeraistio-controller: %w", err)
	}

	// Watch for changes to primary resource TigeraIstio
	err = c.WatchObject(&operatorv1.TigeraIstio{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create TigeraIstio watch", "err", err)
		return fmt.Errorf("tigeraistio-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("tigeraistio-controller failed to watch Tigera network resource: %v", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) *ReconcileTigeraIstio {
	r := &ReconcileTigeraIstio{
		Client:              mgr.GetClient(),
		scheme:              mgr.GetScheme(),
		provider:            opts.DetectedProvider,
		enterpriseCRDsExist: opts.EnterpriseCRDExists,
		status:              status.New(mgr.GetClient(), "tigeraistio", opts.KubernetesVersion),
		clusterDomain:       opts.ClusterDomain,
		multiTenant:         opts.MultiTenant,
	}

	r.status.Run(opts.ShutdownContext)
	return r
}

// ReconcileTigeraIstio reconciles a TigeraIstio object
type ReconcileTigeraIstio struct {
	client.Client
	scheme              *runtime.Scheme
	provider            operatorv1.Provider
	enterpriseCRDsExist bool
	status              status.StatusManager
	clusterDomain       string
	multiTenant         bool
}

// Reconcile reads that state of the cluster for a TigeraIstio object and makes changes based on the state read
// and what is in the TigeraIstio.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileTigeraIstio) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling TigeraIstio")

	// Get the GatewayAPI CR.
	tigeraIstio, msg, err := GetTigeraIstio(ctx, r)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("TigeraIstio object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for TigeraIstio CR: "+msg, err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&tigeraIstio.ObjectMeta)

	// Here starts to deploy Istio Ambient mode for Calico
	// It depends of Gateway API CRDs, so we need to ensure they are installed.
	newStatus := tigeraIstio.DeepCopy()
	newStatus.Status.IstioStatus = "Deploying"
	defer func() {
		if tigeraIstio.Status.IstioStatus == newStatus.Status.IstioStatus {
			return
		}
		if err = r.Status().Patch(ctx, newStatus, client.MergeFrom(tigeraIstio.DeepCopy())); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error updating TigeraIstio status", err, log)
		}
	}()

	// Get the Installation, for private registry and pull secret config.
	variant, installation, err := utils.GetInstallation(ctx, r)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if variant == "" {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Installation Variant to be set", nil, reqLogger)
		return reconcile.Result{Requeue: true}, nil
	}

	// Get the Kubernetes Gateway API CRDs.
	essentialCRDs, optionalCRDs := render.GatewayAPIK8sCRDs(installation.KubernetesProvider)

	// Produce Helm templates for TigeraIstio
	baseOpts := map[string]interface{}{
		"global": map[string]interface{}{
			"istioNamespace": render.TigeraIstioNamespace,
		},
	}
	istiodOpts := map[string]interface{}{
		"global": map[string]interface{}{
			"istioNamespace":         render.TigeraIstioNamespace,
			"operatorManageWebhooks": true,
		},
		"profile": "ambient",
	}
	cniOpts := map[string]interface{}{
		"global": map[string]interface{}{
			"istioNamespace": render.TigeraIstioNamespace,
		},
		"profile": "ambient",
	}
	if installation.KubernetesProvider == operatorv1.ProviderGKE {
		cniOpts["global"].(map[string]interface{})["platform"] = "gke"
	}
	ztunnelOpts := map[string]interface{}{
		"global": map[string]interface{}{
			"istioNamespace": render.TigeraIstioNamespace,
		},
	}
	resources, err := renderistio.GetResources(render.TigeraIstioNamespace, render.TigeraIstioReleaseName, baseOpts,
		istiodOpts, cniOpts, ztunnelOpts)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering Helm templates", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Check CRDs are present and only create it if not
	essentialCRDs = append(essentialCRDs, resources.CRDs...)
	handler := utils.NewComponentHandler(log, r, r.scheme, nil)
	handler.SetCreateOnly()
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(essentialCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering essential Tigera Istio CRDs", err, log)
		return reconcile.Result{}, err
	}
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(optionalCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		reqLogger.Info("Could not render all optional Tigera Istio CRDs", "err", err)
	}

	// Render non-CRD resources for TigeraIstio support
	istioComponent := render.TigeraIstioComponent(&render.TigeraIstioConfig{
		Installation: installation,
		TigeraIstio:  tigeraIstio,
		Resources:    resources,
	})

	// XXX: Append images

	// Deploy Istio components
	err = utils.NewComponentHandler(log, r, r.scheme, tigeraIstio).CreateOrUpdateOrDelete(ctx, istioComponent, r.status)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering TigeraIstio resources", err, log)
		return reconcile.Result{}, err
	}

	// Check all components are ready
	istiodDep := &appsv1.Deployment{}
	if err = r.Get(ctx, client.ObjectKey{Namespace: render.TigeraIstioNamespace,
		Name: render.TigeraIstioIstiodDeploymentName}, istiodDep); err != nil {

		r.status.SetDegraded(operatorv1.ResourceNotReady, "Istiod deployment not found", err, log)
		return reconcile.Result{}, err
	}
	if istiodDep.Status.ReadyReplicas != *istiodDep.Spec.Replicas {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Istiod deployment not ready", nil, log)
		return reconcile.Result{RequeueAfter: time.Second * 5}, nil
	}

	istioCniDs := &appsv1.DaemonSet{}
	if err = r.Get(ctx, client.ObjectKey{Namespace: render.TigeraIstioNamespace,
		Name: render.TigeraIstioCNIDaemonSetName}, istioCniDs); err != nil {

		r.status.SetDegraded(operatorv1.ResourceNotReady, "Istio CNI daemonset not found", err, log)
		return reconcile.Result{}, err
	}
	if istioCniDs.Status.NumberReady != istioCniDs.Status.DesiredNumberScheduled {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Istio CNI daemonset not ready", nil, log)
		return reconcile.Result{RequeueAfter: time.Second * 5}, nil
	}

	ztunnelDs := &appsv1.DaemonSet{}
	if err = r.Get(ctx, client.ObjectKey{Namespace: render.TigeraIstioNamespace,
		Name: render.TigeraIstioZTunnelDaemonSetName}, ztunnelDs); err != nil {

		r.status.SetDegraded(operatorv1.ResourceNotReady, "ZTunnel daemonset not found", err, log)
		return reconcile.Result{}, err
	}
	if ztunnelDs.Status.NumberReady != ztunnelDs.Status.DesiredNumberScheduled {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "ZTunnel daemonset not ready", nil, log)
		return reconcile.Result{RequeueAfter: time.Second * 5}, nil
	}

	newStatus.Status.IstioStatus = "Ready"

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	// Update the status of the TigeraIstio instance and StatusManager.
	return reconcile.Result{RequeueAfter: utils.PeriodicReconcileTime}, nil
}

// GetTigeraIstio finds the correct TigeraIstio resource and returns a message and error in the case of an error.
func GetTigeraIstio(ctx context.Context, client client.Client) (*operatorv1.TigeraIstio, string, error) {
	// Fetch the TigeraIstio resource.  Look for "default" first.
	resource := &operatorv1.TigeraIstio{}
	err := client.Get(ctx, utils.DefaultInstanceKey, resource)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Sprintf("failed to get TigeraIstio '%s'", utils.DefaultInstanceKey), err
		}

		// Default resource doesn't exist. Check for the legacy (enterprise only) CR.
		err = client.Get(ctx, utils.DefaultTSEEInstanceKey, resource)
		if err != nil {
			return nil, fmt.Sprintf("failed to get TigeraIstio '%s'", utils.DefaultTSEEInstanceKey), err
		}
	} else {
		// Assert there is no legacy "tigera-secure" resource present.
		err = client.Get(ctx, utils.DefaultTSEEInstanceKey, resource)
		if err == nil {
			return nil,
				"Duplicate configuration detected",
				fmt.Errorf("multiple TigeraIstio CRs provided. To fix, run \"kubectl delete gatewayapi %s\"", utils.DefaultTSEEInstanceKey)
		}
	}
	return resource, "", nil
}
