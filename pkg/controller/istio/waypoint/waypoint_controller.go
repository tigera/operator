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

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// WaypointPullSecretLabel identifies the pull secret copies and tigera-operator-secrets
	// RoleBindings created by this controller. Cleanup follows the egress gateway pattern:
	// the objects carry an owner reference to the Istio CR and are removed by Kubernetes
	// garbage collection when the CR is deleted. Objects stranded while the CR still exists
	// (a namespace losing its last waypoint Gateway, or a pull secret being renamed in
	// Installation) are not yet cleaned up — that gap is shared with the egress gateway and
	// will be addressed for both together; the label marks the objects for that work.
	WaypointPullSecretLabel = "operator.tigera.io/istio-waypoint-pull-secret"

	// legacyGatewayNamespace is the pre-namespaced gateway-API install namespace, kept in
	// sync with the const of the same name in the gatewayapi controller.
	legacyGatewayNamespace = "tigera-gateway"
)

// reservedNamespace returns true for namespaces whose pull secrets and
// tigera-operator-secrets RoleBinding this controller must not manage: the operator
// namespace holds the source secrets, calico-system's are managed by the installation
// controller, and tigera-gateway's are actively torn down by the gateway-API controller's
// legacy cleanup, which would fight copies created here.
func reservedNamespace(ns string) bool {
	switch ns {
	case common.OperatorNamespace(), common.CalicoNamespace, legacyGatewayNamespace:
		return true
	}
	return false
}

var log = logf.Log.WithName("controller_istio_waypoint")

// Add creates the waypoint controller and adds it to the Manager. The
// controller reconciles the per-Gateway state the Istio feature needs beyond
// istiod's own rendering: it copies Installation pull secrets into namespaces
// that contain istio-waypoint Gateways (together with a tigera-operator-secrets
// RoleBinding that grants the operator permission to manage secrets there), and
// deletes the resource sets istiod strands when a Gateway's
// spec.gatewayClassName changes.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	gatewayWatchReady := &utils.ReadyFlag{}

	r := &ReconcileWaypoint{
		Client:            mgr.GetClient(),
		scheme:            mgr.GetScheme(),
		gatewayWatchReady: gatewayWatchReady,
	}

	c, err := ctrlruntime.NewController("istio-waypoint-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create istio-waypoint-controller: %w", err)
	}

	// Defer the Gateway watch — the Gateway API CRD may not be installed yet.
	// The Istio reconciler creates it during reconciliation, so we use a background
	// goroutine that retries until the CRD appears.
	gatewayObj := &gapi.Gateway{
		TypeMeta: metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
	}
	go utils.WaitToAddResourceWatch(c, opts.K8sClientset, log, gatewayWatchReady, []client.Object{gatewayObj}, predicate.Funcs{
		// Any create can matter: a waypoint-class Gateway needs pull secrets,
		// and when the informer syncs at operator startup every Gateway is
		// replayed as a create — the sweep uses those to catch class flips
		// that happened while the operator was down.
		CreateFunc: func(e event.CreateEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			old, okOld := e.ObjectOld.(*gapi.Gateway)
			curr, okNew := e.ObjectNew.(*gapi.Gateway)
			if !okOld || !okNew {
				return false
			}
			// A class change strands the resource set istiod rendered for the
			// previous class, and moves pull secrets in or out of scope.
			if old.Spec.GatewayClassName != curr.Spec.GatewayClassName {
				return true
			}
			// Other updates only matter for waypoint Gateways, which drive
			// pull-secret placement.
			return string(curr.Spec.GatewayClassName) == IstioWaypointClassName
		},
		// The resource sets istiod rendered are removed by Kubernetes garbage
		// collection via owner references. A waypoint Gateway delete currently
		// triggers no cleanup of that namespace's pull secret copies (they are
		// only GC'd with the Istio CR, matching the egress gateway pattern);
		// the watch is kept so the planned cleanup work has the events it needs.
		DeleteFunc: func(e event.DeleteEvent) bool {
			gw, ok := e.Object.(*gapi.Gateway)
			return ok && string(gw.Spec.GatewayClassName) == IstioWaypointClassName
		},
		GenericFunc: func(e event.GenericEvent) bool {
			gw, ok := e.Object.(*gapi.Gateway)
			return ok && string(gw.Spec.GatewayClassName) == IstioWaypointClassName
		},
	})

	// Watch the Istio CR for pull secret config changes and feature enablement.
	err = c.WatchObject(&operatorv1.Istio{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to watch Istio resource: %w", err)
	}

	// Watch Installation for pull secret changes.
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to watch Installation resource: %w", err)
	}

	// Watch secrets in the operator namespace: the Installation pull secrets live there, and
	// changes to their contents must propagate to the copies in waypoint namespaces. The pull
	// secret names are user-defined in Installation, so watch the whole namespace.
	if err = utils.AddSecretsWatch(c, "", common.OperatorNamespace()); err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to watch secrets in the operator namespace: %w", err)
	}

	// Periodic reconcile as a backstop.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// ReconcileWaypoint reconciles the per-Gateway state the Istio feature needs
// beyond istiod's own rendering: it copies pull secrets (and the
// tigera-operator-secrets RoleBinding needed to manage them) to namespaces
// that contain istio-waypoint Gateways so waypoint pods can pull images from
// private registries, and deletes istiod-managed gateway resources that were
// rendered for a GatewayClass their owning Gateway no longer uses.
type ReconcileWaypoint struct {
	client.Client
	scheme *runtime.Scheme

	gatewayWatchReady *utils.ReadyFlag
}

func (r *ReconcileWaypoint) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling waypoint gateway resources")

	// Get the Istio CR - if not found or being deleted, the feature is
	// inactive: copied pull secrets and RoleBindings are garbage collected via
	// their owner reference to the CR, and istiod's gateway resources belong to
	// a mesh the operator does not manage and must not be touched.
	instance := &operatorv1.Istio{}
	err := r.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil && !errors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	istioActive := err == nil && instance.DeletionTimestamp.IsZero()
	if !istioActive || !r.gatewayWatchReady.IsReady() {
		return reconcile.Result{}, nil
	}

	toCreate, err := r.pullSecretResources(ctx, reqLogger)
	if err != nil {
		return reconcile.Result{}, err
	}

	toDelete, err := r.staleGatewaySets(ctx, reqLogger)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Pass the Istio CR as the owner: created objects carry an owner reference to it
	// (merged with any other owners, such as an egress gateway CR sharing the namespace,
	// via the multiple-owners label) and are garbage collected when the CR is deleted —
	// the same pattern the egress gateway uses with its CRs.
	hdlr := utils.NewComponentHandler(log, r, r.scheme, instance)
	component := render.NewPassthrough(toCreate, toDelete)
	if err := hdlr.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to reconcile waypoint gateway resources: %w", err)
	}

	return reconcile.Result{}, nil
}

// pullSecretResources returns the objects each waypoint namespace needs so its pods can
// pull images from private registries: a tigera-operator-secrets RoleBinding granting the
// operator permission to write secrets in the namespace, followed by copies of the
// Installation pull secrets. Cleanup mirrors the egress gateway pattern: the objects are
// owned by the Istio CR and garbage collected when it is deleted. Objects stranded while
// the CR still exists (a removed Gateway, a renamed pull secret) are not yet cleaned up.
func (r *ReconcileWaypoint) pullSecretResources(ctx context.Context, reqLogger logr.Logger) ([]client.Object, error) {
	_, installationSpec, err := utils.GetInstallationSpec(ctx, r)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(1).Info("Installation not found")
			return nil, nil
		}
		return nil, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r)
	if err != nil {
		return nil, err
	}
	if len(pullSecrets) == 0 {
		return nil, nil
	}

	// List all Gateway resources and filter for istio-waypoint class, skipping the
	// reserved namespaces whose pull secrets and RoleBinding other controllers manage.
	gatewayList := &gapi.GatewayList{}
	if err := r.List(ctx, gatewayList); err != nil {
		return nil, fmt.Errorf("failed to list Gateways: %w", err)
	}

	targetNamespaces := map[string]bool{}
	for i := range gatewayList.Items {
		gw := &gatewayList.Items[i]
		if string(gw.Spec.GatewayClassName) == IstioWaypointClassName && !reservedNamespace(gw.Namespace) {
			targetNamespaces[gw.Namespace] = true
		}
	}

	// Build the objects for each target namespace. The RoleBinding comes first: it grants
	// the operator permission to write secrets in the namespace, so it must exist before
	// the secret copies are created. Both carry MultipleOwnersLabel so the component
	// handler merges owner references with any other owners (e.g. an egress gateway CR
	// sharing the namespace) rather than replacing them.
	var objs []client.Object
	for ns := range targetNamespaces {
		rb := render.CreateOperatorSecretsRoleBinding(ns)
		rb.Labels = common.MapExistsOrInitialize(rb.Labels)
		rb.Labels[WaypointPullSecretLabel] = "true"
		rb.Labels[common.MultipleOwnersLabel] = "true"
		objs = append(objs, rb)

		copied := secret.CopyToNamespace(ns, pullSecrets...)
		for _, s := range copied {
			if s.Labels == nil {
				s.Labels = map[string]string{}
			}
			s.Labels[WaypointPullSecretLabel] = "true"
			s.Labels[common.MultipleOwnersLabel] = "true"
			objs = append(objs, s)
		}
	}

	return objs, nil
}
