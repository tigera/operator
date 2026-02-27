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

package waypoint

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	// IstioWaypointClassName is the GatewayClass name used by Istio waypoints.
	IstioWaypointClassName = "istio-waypoint"

	// WaypointPullSecretLabel is the label applied to secrets copied by this controller
	// for tracking and cleanup purposes.
	WaypointPullSecretLabel = "operator.tigera.io/istio-waypoint-pull-secret"
)

var log = logf.Log.WithName("controller_istio_waypoint")

// Add creates the waypoint pull secrets controller and adds it to the Manager.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	r := &ReconcileWaypointSecrets{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
	}

	c, err := ctrlruntime.NewController("istio-waypoint-secrets-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create istio-waypoint-secrets-controller: %w", err)
	}

	// Watch Gateway resources, filtering for istio-waypoint class only.
	err = c.WatchObject(&gapi.Gateway{}, &handler.EnqueueRequestForObject{}, predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			gw, ok := e.Object.(*gapi.Gateway)
			return ok && string(gw.Spec.GatewayClassName) == IstioWaypointClassName
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			gw, ok := e.ObjectNew.(*gapi.Gateway)
			return ok && string(gw.Spec.GatewayClassName) == IstioWaypointClassName
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			gw, ok := e.Object.(*gapi.Gateway)
			return ok && string(gw.Spec.GatewayClassName) == IstioWaypointClassName
		},
		GenericFunc: func(e event.GenericEvent) bool {
			gw, ok := e.Object.(*gapi.Gateway)
			return ok && string(gw.Spec.GatewayClassName) == IstioWaypointClassName
		},
	})
	if err != nil {
		return fmt.Errorf("istio-waypoint-secrets-controller failed to watch Gateway resource: %w", err)
	}

	// Watch Istio CR for pull secret config changes.
	err = c.WatchObject(&operatorv1.Istio{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("istio-waypoint-secrets-controller failed to watch Istio resource: %w", err)
	}

	// Watch Installation for pull secret changes.
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("istio-waypoint-secrets-controller failed to watch Installation resource: %w", err)
	}

	// Periodic reconcile as a backstop.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("istio-waypoint-secrets-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// ReconcileWaypointSecrets copies pull secrets to namespaces that contain
// istio-waypoint Gateways so that waypoint pods can pull images from private registries.
type ReconcileWaypointSecrets struct {
	client.Client
	scheme *runtime.Scheme
}

func (r *ReconcileWaypointSecrets) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling waypoint pull secrets")

	// Get the Istio CR - if not found or being deleted, clean up all secrets.
	instance := &operatorv1.Istio{}
	err := r.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(1).Info("Istio CR not found, cleaning up all waypoint pull secrets")
			return reconcile.Result{}, r.cleanupAllSecrets(ctx)
		}
		return reconcile.Result{}, err
	}
	if !instance.DeletionTimestamp.IsZero() {
		reqLogger.V(1).Info("Istio CR being deleted, cleaning up all waypoint pull secrets")
		return reconcile.Result{}, r.cleanupAllSecrets(ctx)
	}

	// Get Installation and pull secrets.
	_, installation, err := utils.GetInstallation(ctx, r)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(1).Info("Installation not found")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r)
	if err != nil {
		return reconcile.Result{}, err
	}

	// If no pull secrets configured, clean up any previously copied secrets.
	if len(pullSecrets) == 0 {
		reqLogger.V(1).Info("No pull secrets configured, cleaning up waypoint pull secrets")
		return reconcile.Result{}, r.cleanupAllSecrets(ctx)
	}

	// List all Gateway resources and filter for istio-waypoint class.
	gatewayList := &gapi.GatewayList{}
	if err := r.List(ctx, gatewayList); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list Gateways: %w", err)
	}

	// Build set of target namespaces (deduplicated).
	targetNamespaces := map[string]bool{}
	for i := range gatewayList.Items {
		gw := &gatewayList.Items[i]
		if string(gw.Spec.GatewayClassName) == IstioWaypointClassName {
			targetNamespaces[gw.Namespace] = true
		}
	}

	// For each target namespace, copy pull secrets and apply the tracking label.
	for ns := range targetNamespaces {
		copied := secret.CopyToNamespace(ns, pullSecrets...)
		var objs []client.Object
		for _, s := range copied {
			if s.Labels == nil {
				s.Labels = map[string]string{}
			}
			s.Labels[WaypointPullSecretLabel] = "true"
			objs = append(objs, s)
		}

		hdlr := utils.NewComponentHandler(log, r, r.scheme, nil)
		component := render.NewPassthrough(objs, nil)
		if err := hdlr.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create/update pull secrets in namespace %s: %w", ns, err)
		}
	}

	// Clean up stale secrets from namespaces that no longer have waypoints.
	if err := r.cleanupStaleSecrets(ctx, targetNamespaces); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// cleanupAllSecrets removes all secrets created by this controller.
func (r *ReconcileWaypointSecrets) cleanupAllSecrets(ctx context.Context) error {
	return r.cleanupStaleSecrets(ctx, nil)
}

// cleanupStaleSecrets removes tracking-labeled secrets from namespaces not in the active set.
func (r *ReconcileWaypointSecrets) cleanupStaleSecrets(ctx context.Context, activeNamespaces map[string]bool) error {
	secretList := &corev1.SecretList{}
	if err := r.List(ctx, secretList, client.MatchingLabels{WaypointPullSecretLabel: "true"}); err != nil {
		return fmt.Errorf("failed to list waypoint pull secrets: %w", err)
	}

	for i := range secretList.Items {
		s := &secretList.Items[i]
		if !activeNamespaces[s.Namespace] {
			if err := r.Delete(ctx, s); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete stale pull secret %s/%s: %w", s.Namespace, s.Name, err)
			}
		}
	}

	return nil
}
