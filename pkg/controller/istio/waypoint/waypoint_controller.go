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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"github.com/tigera/operator/pkg/render/gatewayapi"
)

const (
	// IstioWaypointClassName is the GatewayClass name used by Istio waypoints.
	IstioWaypointClassName = "istio-waypoint"

	// WaypointPullSecretLabel labels secrets copied by this controller, and the
	// tigera-operator-secrets RoleBindings it creates alongside them. The label drives
	// cleanup: a label selector is a simple cross-namespace query that finds every managed
	// copy when pull secrets change or the Istio CR is deleted — something owner references
	// alone could not do, since GC only fires on owner deletion. The controller additionally
	// stamps an Istio owner reference on these objects as a garbage-collection safety net for
	// namespaces shared with the gateway API feature (see Reconcile).
	WaypointPullSecretLabel = "operator.tigera.io/istio-waypoint-pull-secret"
)

var log = logf.Log.WithName("controller_istio_waypoint")

// Add creates the waypoint controller and adds it to the Manager. The
// controller reconciles the per-Gateway state the Istio feature needs beyond
// istiod's own rendering: it copies Installation pull secrets into namespaces
// that contain istio-waypoint Gateways, and deletes the resource sets istiod
// strands when a Gateway's spec.gatewayClassName changes.
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
		// Deletes only affect pull secrets: the resource sets istiod rendered
		// are removed by Kubernetes garbage collection via owner references.
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

	// Watch all secrets in the operator namespace so pull-secret rotations reconcile the
	// per-namespace copies immediately.
	if err = utils.AddSecretsWatch(c, "", common.OperatorNamespace()); err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to watch secrets: %w", err)
	}

	// Periodic reconcile as a backstop.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// ReconcileWaypoint reconciles the per-Gateway state the Istio feature needs
// beyond istiod's own rendering: it copies pull secrets to namespaces that
// contain istio-waypoint Gateways so waypoint pods can pull images from
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
	// inactive: copied pull secrets are stale, and istiod's gateway resources
	// belong to a mesh the operator does not manage and must not be touched.
	instance := &operatorv1.Istio{}
	err := r.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil && !errors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	istioActive := err == nil && instance.DeletionTimestamp.IsZero()
	gatewaysVisible := istioActive && r.gatewayWatchReady.IsReady()

	toCreate, toDelete, err := r.pullSecretChanges(ctx, instance, istioActive, reqLogger)
	if err != nil {
		return reconcile.Result{}, err
	}

	if gatewaysVisible {
		stale, err := r.staleGatewaySets(ctx, reqLogger)
		if err != nil {
			return reconcile.Result{}, err
		}
		toDelete = append(toDelete, stale...)
	}

	// Use a single passthrough component to handle both creation and deletion.
	hdlr := utils.NewComponentHandler(log, r, r.scheme, nil)
	component := render.NewPassthrough(toCreate, toDelete)
	if err := hdlr.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to reconcile waypoint gateway resources: %w", err)
	}

	return reconcile.Result{}, nil
}

// pullSecretChanges determines which pull-secret copies and
// tigera-operator-secrets need to exist based on the namespaces that contain
// istio-waypoint Gateways, and which existing ones are stale. When istioActive
// is false no copies are desired, so every existing copy is returned as stale.
func (r *ReconcileWaypoint) pullSecretChanges(ctx context.Context, instance *operatorv1.Istio, istioActive bool, reqLogger logr.Logger) (toCreate, toDelete []client.Object, err error) {
	// When Istio is active, own the shared pull-secret copies and RoleBindings with a
	// reference to the (cluster-scoped) Istio CR. This is a safety net against premature
	// garbage collection: in a namespace shared with the gateway API feature, that controller
	// stamps its own Gateway owner reference on the same objects, and deleting the last such
	// Gateway would otherwise let Kubernetes GC remove a copy the waypoint still needs. The
	// reference coexists with other features' references via the MultipleOwnersLabel merge;
	// the label-based cleanup below still removes objects only this controller owns.
	var istioOwner *metav1.OwnerReference
	if istioActive {
		istioOwner = &metav1.OwnerReference{
			APIVersion: operatorv1.GroupVersion.String(),
			Kind:       "Istio",
			Name:       instance.Name,
			UID:        instance.UID,
		}
	}

	// Build the desired set of secrets if Istio is active.
	var pullSecrets []*corev1.Secret
	targetNamespaces := map[string]bool{}
	if istioActive {
		_, installationSpec, err := utils.GetInstallationSpec(ctx, r)
		if err != nil {
			if errors.IsNotFound(err) {
				reqLogger.V(1).Info("Installation not found")
				return nil, nil, nil
			}
			return nil, nil, err
		}

		pullSecrets, err = utils.GetInstallationPullSecrets(installationSpec, r)
		if err != nil {
			return nil, nil, err
		}
	}

	// Copies are desired only in namespaces that contain istio-waypoint Gateways, so the
	// Gateway list is needed only when there are pull secrets to copy. With none configured
	// the desired state is empty regardless of Gateways, and cleanup below proceeds.
	if len(pullSecrets) > 0 {
		// If the Gateway watch isn't established yet, the desired state is unknown — bail
		// out rather than treat every existing copy as stale. Gateway events after the
		// watch syncs (or the periodic reconcile) will trigger the next pass.
		if !r.gatewayWatchReady.IsReady() {
			reqLogger.V(1).Info("Waiting for Gateway watch to be established")
			return nil, nil, nil
		}

		// List all Gateway resources and filter for istio-waypoint class.
		gatewayList := &gapi.GatewayList{}
		if err := r.List(ctx, gatewayList); err != nil {
			return nil, nil, fmt.Errorf("failed to list Gateways: %w", err)
		}

		for _, gw := range gatewayList.Items {
			if string(gw.Spec.GatewayClassName) == IstioWaypointClassName && !reservedNamespace(gw.Namespace) {
				targetNamespaces[gw.Namespace] = true
			}
		}
	}

	// List all existing secrets managed by this controller.
	existingSecrets := &corev1.SecretList{}
	if err := r.List(ctx, existingSecrets, client.MatchingLabels{WaypointPullSecretLabel: "true"}); err != nil {
		return nil, nil, fmt.Errorf("failed to list waypoint pull secrets: %w", err)
	}

	// Build desired secrets for each target namespace, keyed on (namespace, name) so that
	// renamed or removed secrets are correctly detected as stale. Each copy carries an Istio
	// owner reference (the GC safety net) and the MultipleOwnersLabel, which tells the
	// component handler to merge — rather than replace — owner references, preserving any that
	// another feature (e.g. egress gateway) holds on a shared copy.
	var desiredSecretObjs []client.Object
	desiredSecrets := map[types.NamespacedName]bool{}
	for ns := range targetNamespaces {
		copied := secret.CopyToNamespace(ns, pullSecrets...)
		for _, s := range copied {
			if s.Labels == nil {
				s.Labels = map[string]string{}
			}
			s.Labels[WaypointPullSecretLabel] = "true"
			s.Labels[common.MultipleOwnersLabel] = "true"
			if istioOwner != nil {
				s.OwnerReferences = append(s.OwnerReferences, *istioOwner)
			}
			desiredSecretObjs = append(desiredSecretObjs, s)
			desiredSecrets[types.NamespacedName{Namespace: s.Namespace, Name: s.Name}] = true
		}
	}

	// Cleanup skips terminating namespaces: the namespace deletion removes the copies and
	// RoleBindings itself, and a terminating namespace rejects the RoleBinding creation that
	// authorizes this controller's secret deletes, so attempting cleanup there can only fail.
	terminatingNS := map[string]bool{}
	nsTerminating := func(ns string) (bool, error) {
		if t, ok := terminatingNS[ns]; ok {
			return t, nil
		}
		n := &corev1.Namespace{}
		if err := r.Get(ctx, types.NamespacedName{Name: ns}, n); err != nil {
			if errors.IsNotFound(err) {
				// Already gone, along with everything in it.
				terminatingNS[ns] = true
				return true, nil
			}
			return false, err
		}
		t := !n.DeletionTimestamp.IsZero()
		terminatingNS[ns] = t
		return t, nil
	}

	// Mark stale secrets for deletion. A copy that a different feature also owns (a foreign
	// owner reference — gateway API's Gateway, egress gateway's EgressGateway) is left for the
	// Kubernetes GC once those owners are gone; this controller's own Istio owner reference
	// does not count. Copies this controller solely owns are deleted here.
	staleSecretNamespaces := map[string]bool{}
	for _, s := range existingSecrets.Items {
		if reservedNamespace(s.Namespace) {
			continue
		}
		key := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}
		if desiredSecrets[key] || hasForeignOwnerRef(s.OwnerReferences) {
			continue
		}
		if terminating, err := nsTerminating(s.Namespace); err != nil {
			return nil, nil, err
		} else if terminating {
			continue
		}
		toDelete = append(toDelete, &s)
		staleSecretNamespaces[s.Namespace] = true
	}

	// Ensure that a RoleBinding exists in every namespace we're about to write
	// secrets in: namespaces that need copies (targetNamespaces), plus
	// namespaces where stale copies are being deleted.
	rbEnsure := map[string]bool{}
	for ns := range targetNamespaces {
		rbEnsure[ns] = true
	}
	for ns := range staleSecretNamespaces {
		rbEnsure[ns] = true
	}

	// RoleBindings first: objects are created in order, so each namespace's binding exists
	// before its secrets are written.
	rbCreated := map[string]bool{}
	for ns := range rbEnsure {
		rb := &rbacv1.RoleBinding{}
		err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: render.TigeraOperatorSecrets}, rb)
		switch {
		case errors.IsNotFound(err):
			rbCreated[ns] = true
			toCreate = append(toCreate, waypointOperatorSecretsRoleBinding(ns, istioOwner))
		case err != nil:
			return nil, nil, err
		case rb.Labels[WaypointPullSecretLabel] == "true":
			// Ours from an earlier reconcile; keep it reconciled to the desired shape.
			toCreate = append(toCreate, waypointOperatorSecretsRoleBinding(ns, istioOwner))
		}
	}
	toCreate = append(toCreate, desiredSecretObjs...)

	// Mark stale RoleBindings for deletion, after the stale secrets: deletes are processed
	// in order, so the binding outlives the secret deletions it authorizes. Only bindings
	// managed by this controller are candidates — those carrying its label, plus the ones
	// created above solely to authorize stale secret deletion, which are removed again in
	// this same reconcile.
	existingRBs := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, existingRBs, client.MatchingLabels{WaypointPullSecretLabel: "true"}); err != nil {
		return nil, nil, fmt.Errorf("failed to list waypoint RoleBindings: %w", err)
	}
	staleRBCandidates := map[string]bool{}
	for ns := range rbCreated {
		staleRBCandidates[ns] = true
	}
	for _, rb := range existingRBs.Items {
		if rb.Name != render.TigeraOperatorSecrets {
			continue
		}
		if hasForeignOwnerRef(rb.OwnerReferences) {
			// Another controller (e.g. gateway API or egress gateway) also relies on this
			// binding and owns it; leave it for the Kubernetes GC when its owners are gone.
			// This controller's own Istio owner reference does not count.
			continue
		}
		staleRBCandidates[rb.Namespace] = true
	}
	for ns := range staleRBCandidates {
		if targetNamespaces[ns] || reservedNamespace(ns) {
			continue
		}
		if terminating, err := nsTerminating(ns); err != nil {
			return nil, nil, err
		} else if terminating {
			continue
		}
		toDelete = append(toDelete, render.CreateOperatorSecretsRoleBinding(ns))
	}

	return toCreate, toDelete, nil
}

// reservedNamespace reports whether ns is a namespace whose pull secrets and
// tigera-operator-secrets RoleBinding are managed by other controllers or the install
// manifests — this controller never writes or deletes anything there. In particular, the
// gateway API controller's legacy teardown explicitly deletes both from the legacy gateway
// namespace on every reconcile, so writing copies there would fight it indefinitely.
func reservedNamespace(ns string) bool {
	return ns == common.OperatorNamespace() || ns == common.CalicoNamespace || ns == gatewayapi.LegacyGatewayNamespace
}

// waypointOperatorSecretsRoleBinding returns the RoleBinding granting the operator's
// ServiceAccount the tigera-operator-secrets ClusterRole in the given namespace. The
// MultipleOwnersLabel instructs the component handler to merge owner references, preserving
// those other controllers (e.g. gateway API, egress gateway) may hold on a shared binding;
// owner, when non-nil, is this controller's Istio owner reference (the GC safety net).
func waypointOperatorSecretsRoleBinding(namespace string, owner *metav1.OwnerReference) *rbacv1.RoleBinding {
	rb := render.CreateOperatorSecretsRoleBinding(namespace)
	rb.Labels = map[string]string{
		WaypointPullSecretLabel:    "true",
		common.MultipleOwnersLabel: "true",
	}
	if owner != nil {
		rb.OwnerReferences = append(rb.OwnerReferences, *owner)
	}
	return rb
}

// hasForeignOwnerRef reports whether refs contains an owner reference belonging to a feature
// other than this controller — anything that is not the Istio CR. Such an owner (gateway
// API's Gateway, egress gateway's EgressGateway) means another feature still relies on the
// shared object, so this controller leaves its removal to the Kubernetes garbage collector
// rather than deleting it directly.
func hasForeignOwnerRef(refs []metav1.OwnerReference) bool {
	for _, ref := range refs {
		if ref.Kind == "Istio" && ref.APIVersion == operatorv1.GroupVersion.String() {
			continue
		}
		return true
	}
	return false
}
