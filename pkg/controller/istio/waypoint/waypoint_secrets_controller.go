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
)

const (
	// IstioWaypointClassName is the GatewayClass name used by Istio waypoints.
	IstioWaypointClassName = "istio-waypoint"

	// WaypointPullSecretLabel labels secrets copied by this controller, and the
	// tigera-operator-secrets RoleBindings it creates alongside them. We use a label rather
	// than owner references because the controller needs to efficiently find and clean up its
	// managed resources during reconciliation — for example, when pull secrets are removed from
	// Installation or when the Istio CR is deleted. A label selector provides a simple,
	// cross-namespace query that covers all cleanup scenarios, whereas owner references would
	// only automate Gateway-deletion cleanup via Kubernetes garbage collection.
	WaypointPullSecretLabel = "operator.tigera.io/istio-waypoint-pull-secret"

	// legacyGatewayNamespace is the namespace used by the legacy (pre-namespaced) gateway API
	// install. The gateway API controller's legacy teardown explicitly deletes the
	// tigera-operator-secrets RoleBinding and pull secret copies there on every reconcile,
	// so writing copies into it would fight that controller indefinitely.
	legacyGatewayNamespace = "tigera-gateway"
)

var log = logf.Log.WithName("controller_istio_waypoint")

// Add creates the waypoint pull secrets controller and adds it to the Manager.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	gatewayWatchReady := &utils.ReadyFlag{}

	r := &ReconcileWaypointSecrets{
		Client:            mgr.GetClient(),
		scheme:            mgr.GetScheme(),
		gatewayWatchReady: gatewayWatchReady,
	}

	c, err := ctrlruntime.NewController("istio-waypoint-secrets-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create istio-waypoint-secrets-controller: %w", err)
	}

	// Defer the Gateway watch — the Gateway API CRD may not be installed yet.
	// The Istio reconciler creates it during reconciliation, so we use a background
	// goroutine that retries until the CRD appears.
	gatewayObj := &gapi.Gateway{
		TypeMeta: metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
	}
	go utils.WaitToAddResourceWatch(c, opts.K8sClientset, log, gatewayWatchReady, []client.Object{gatewayObj}, predicate.Funcs{
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

	gatewayWatchReady *utils.ReadyFlag
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

	// If Istio is active but the Gateway watch isn't established yet, the desired state is
	// unknown — bail out rather than treat every existing copy as stale. Gateway events after
	// the watch syncs (or the periodic reconcile) will trigger the next pass.
	if istioActive && !r.gatewayWatchReady.IsReady() {
		reqLogger.V(1).Info("Waiting for Gateway watch to be established")
		return reconcile.Result{}, nil
	}

	// Build the desired set of secrets if Istio is active.
	var pullSecrets []*corev1.Secret
	targetNamespaces := map[string]bool{}
	if istioActive {
		_, installationSpec, err := utils.GetInstallationSpec(ctx, r)
		if err != nil {
			if errors.IsNotFound(err) {
				reqLogger.V(1).Info("Installation not found")
				return reconcile.Result{}, nil
			}
			return reconcile.Result{}, err
		}

		pullSecrets, err = utils.GetInstallationPullSecrets(installationSpec, r)
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
			if string(gw.Spec.GatewayClassName) == IstioWaypointClassName && !reservedNamespace(gw.Namespace) {
				targetNamespaces[gw.Namespace] = true
			}
		}
	}

	// List all existing secrets managed by this controller.
	existingSecrets := &corev1.SecretList{}
	if err := r.List(ctx, existingSecrets, client.MatchingLabels{WaypointPullSecretLabel: "true"}); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list waypoint pull secrets: %w", err)
	}

	// Build desired secrets for each target namespace, keyed on (namespace, name) so that
	// renamed or removed secrets are correctly detected as stale. A copy may be shared with
	// another feature that copies the same pull secret into the same namespace (e.g. egress
	// gateway); the MultipleOwnersLabel instructs the component handler to preserve the owner
	// references that feature holds on the shared copy.
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
			desiredSecretObjs = append(desiredSecretObjs, s)
			desiredSecrets[types.NamespacedName{Namespace: s.Namespace, Name: s.Name}] = true
		}
	}

	// Mark stale secrets for deletion. A stale copy carrying owner references is still in
	// use by another feature (this controller never sets owner references on its copies),
	// so it is left for the Kubernetes GC once its owners are gone.
	for i := range existingSecrets.Items {
		s := &existingSecrets.Items[i]
		if reservedNamespace(s.Namespace) {
			continue
		}
		key := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}
		if desiredSecrets[key] || len(s.OwnerReferences) > 0 {
			continue
		}
		toDelete = append(toDelete, s)
	}

	// The operator has no cluster-wide permission to write secrets; the tigera-operator-secrets
	// ClusterRole grants writes only in namespaces where a RoleBinding binds it to the operator's
	// ServiceAccount. Ensure that binding exists in every namespace we're about to write secrets
	// in: namespaces that need copies (rbDesired), plus namespaces where stale copies are being
	// deleted (there the binding is created and then removed in the same reconcile, after the
	// secret deletions it authorizes).
	rbDesired := map[string]bool{}
	if len(pullSecrets) > 0 {
		for ns := range targetNamespaces {
			rbDesired[ns] = true
		}
	}
	rbEnsure := map[string]bool{}
	for ns := range rbDesired {
		rbEnsure[ns] = true
	}
	for _, obj := range toDelete {
		rbEnsure[obj.GetNamespace()] = true
	}

	// RoleBindings first: objects are created in order, so each namespace's binding
	// exists before its secrets are written.
	for ns := range rbEnsure {
		toCreate = append(toCreate, waypointOperatorSecretsRoleBinding(ns))
	}
	toCreate = append(toCreate, desiredSecretObjs...)

	// Mark stale RoleBindings for deletion, after the stale secrets: deletes are processed
	// in order, so the binding outlives the secret deletions it authorizes. Stale means the
	// namespace no longer needs copies — bindings created above solely to authorize stale
	// secret deletion are removed in this same reconcile.
	existingRBs := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, existingRBs, client.MatchingLabels{WaypointPullSecretLabel: "true"}); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list waypoint RoleBindings: %w", err)
	}
	staleRBCandidates := map[string]bool{}
	for ns := range rbEnsure {
		staleRBCandidates[ns] = true
	}
	for i := range existingRBs.Items {
		if existingRBs.Items[i].Name == render.TigeraOperatorSecrets {
			staleRBCandidates[existingRBs.Items[i].Namespace] = true
		}
	}
	for ns := range staleRBCandidates {
		if rbDesired[ns] || reservedNamespace(ns) {
			continue
		}
		if coOwned, err := r.roleBindingCoOwned(ctx, ns); err != nil {
			return reconcile.Result{}, err
		} else if coOwned {
			// Another controller (e.g. gateway API or egress gateway) also relies on this
			// binding and owns it; leave it for the Kubernetes GC when its owners are gone.
			continue
		}
		toDelete = append(toDelete, render.CreateOperatorSecretsRoleBinding(ns))
	}

	// Use a single passthrough component to handle both creation and deletion.
	hdlr := utils.NewComponentHandler(log, r, r.scheme, nil)
	component := render.NewPassthrough(toCreate, toDelete)
	if err := hdlr.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to reconcile waypoint pull secrets: %w", err)
	}

	return reconcile.Result{}, nil
}

// reservedNamespace reports whether ns is a namespace whose pull secrets and
// tigera-operator-secrets RoleBinding are managed by other controllers or the install
// manifests — this controller never writes or deletes anything there.
func reservedNamespace(ns string) bool {
	return ns == common.OperatorNamespace() || ns == common.CalicoNamespace || ns == legacyGatewayNamespace
}

// waypointOperatorSecretsRoleBinding returns the RoleBinding granting the operator's
// ServiceAccount the tigera-operator-secrets ClusterRole in the given namespace. The
// MultipleOwnersLabel instructs the component handler to preserve owner references that
// other controllers (e.g. gateway API, egress gateway) may hold on a shared binding.
func waypointOperatorSecretsRoleBinding(namespace string) *rbacv1.RoleBinding {
	rb := render.CreateOperatorSecretsRoleBinding(namespace)
	rb.Labels = map[string]string{
		WaypointPullSecretLabel:    "true",
		common.MultipleOwnersLabel: "true",
	}
	return rb
}

// roleBindingCoOwned reports whether the tigera-operator-secrets RoleBinding in the given
// namespace carries owner references, i.e. is also managed by another controller. Checked
// against the live object because bindings created by other features (e.g. egress gateway)
// may not carry this controller's label.
func (r *ReconcileWaypointSecrets) roleBindingCoOwned(ctx context.Context, namespace string) (bool, error) {
	rb := &rbacv1.RoleBinding{}
	err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: render.TigeraOperatorSecrets}, rb)
	if errors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(rb.OwnerReferences) > 0, nil
}
