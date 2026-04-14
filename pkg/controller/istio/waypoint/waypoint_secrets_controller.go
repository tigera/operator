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
	"k8s.io/apimachinery/pkg/types"
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
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	// IstioWaypointClassName is the GatewayClass name used by Istio waypoints.
	IstioWaypointClassName = "istio-waypoint"

	// WaypointPullSecretLabel labels secrets copied by this controller. We use a label rather
	// than owner references because the controller needs to efficiently find and clean up its
	// managed secrets during reconciliation — for example, when pull secrets are removed from
	// Installation or when the Istio CR is deleted. A label selector provides a simple,
	// cross-namespace query that covers all cleanup scenarios, whereas owner references would
	// only automate Gateway-deletion cleanup via Kubernetes garbage collection.
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

	// Determine which secrets need to exist (toCreate) based on current state,
	// and which existing secrets are stale (toDelete).
	var toCreate []client.Object
	var toDelete []client.Object

	// Get the Istio CR - if not found or being deleted, all existing secrets are stale.
	instance := &operatorv1.Istio{}
	err := r.Get(ctx, utils.DefaultInstanceKey, instance)
	istioActive := err == nil && instance.DeletionTimestamp.IsZero()
	if err != nil && !errors.IsNotFound(err) {
		return reconcile.Result{}, err
	}

	// Build the desired set of secrets if Istio is active.
	targetNamespaces := map[string]bool{}
	if istioActive {
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

		// List all Gateway resources and filter for istio-waypoint class.
		gatewayList := &gapi.GatewayList{}
		if err := r.List(ctx, gatewayList); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to list Gateways: %w", err)
		}

		for i := range gatewayList.Items {
			gw := &gatewayList.Items[i]
			if string(gw.Spec.GatewayClassName) == IstioWaypointClassName &&
				gw.Namespace != common.OperatorNamespace() {
				targetNamespaces[gw.Namespace] = true
			}
		}

		// Build desired secrets for each target namespace.
		for ns := range targetNamespaces {
			copied := secret.CopyToNamespace(ns, pullSecrets...)
			for _, s := range copied {
				if s.Labels == nil {
					s.Labels = map[string]string{}
				}
				s.Labels[WaypointPullSecretLabel] = "true"
				toCreate = append(toCreate, s)
			}
		}
	}

	// Build the desired set keyed on (namespace, name) so that renamed or removed
	// secrets are correctly detected as stale.
	desiredSecrets := map[types.NamespacedName]bool{}
	for _, obj := range toCreate {
		desiredSecrets[types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}] = true
	}

	// List all existing secrets managed by this controller and mark stale ones for deletion.
	existingSecrets := &corev1.SecretList{}
	if err := r.List(ctx, existingSecrets, client.MatchingLabels{WaypointPullSecretLabel: "true"}); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list waypoint pull secrets: %w", err)
	}
	for i := range existingSecrets.Items {
		s := &existingSecrets.Items[i]
		key := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}
		if !desiredSecrets[key] {
			toDelete = append(toDelete, s)
		}
	}

	// Use a single passthrough component to handle both creation and deletion.
	hdlr := utils.NewComponentHandler(log, r, r.scheme, nil)
	component := render.NewPassthrough(toCreate, toDelete)
	if err := hdlr.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to reconcile waypoint pull secrets: %w", err)
	}

	return reconcile.Result{}, nil
}
