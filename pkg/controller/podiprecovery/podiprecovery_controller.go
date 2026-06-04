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

// Package podiprecovery contains a small controller that watches Kubernetes
// Nodes for host-IP changes (the address set the kubelet would put in
// `status.podIPs` for a hostNetwork pod: InternalIP-preferred, ExternalIP
// fallback) and deletes operator-managed host-networked pods whose
// status.podIPs no longer matches that set.
//
// This works around an upstream Kubernetes behavior
// (https://github.com/kubernetes/kubernetes/issues/93897) where status.podIPs
// is immutable for hostNetwork pods once set. When a node's IP changes
// (e.g. after a KubeVirt VM reboot pulls a new DHCP lease), existing
// hostNetwork pods keep their stale IPs in their status, the Kubernetes
// EndpointSlice controller advertises the stale IPs, and Felix can't reach
// Typha. Only deleting and recreating the pod causes the kubelet to populate
// status.podIPs from the current node IP.
//
// Operator-managed pods are identified by the
// common.HostNetworkedPodLabel label, which each render package applies to
// its hostNetwork pod templates. The controller additionally verifies
// spec.hostNetwork == true on each candidate as a safety net before
// deleting.
package podiprecovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
)

var log = logf.Log.WithName("controller_podiprecovery")

// podNodeNameIndex is the field-index registered in cmd/main.go that lets
// us list pods by their `spec.nodeName` with a server-side field selector.
const podNodeNameIndex = "spec.nodeName"

// Add wires the controller into the manager.
func Add(mgr manager.Manager, _ options.ControllerOptions) error {
	r := &Reconciler{
		client: mgr.GetClient(),
	}

	c, err := ctrlruntime.NewController("podiprecovery-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create podiprecovery-controller: %w", err)
	}

	// Watch Node objects. Only enqueue reconciliations when the set of
	// host IPs (what the kubelet would put in status.podIPs) has changed —
	// that is the only signal that interests us, and it avoids spurious
	// reconciles for routine kubelet heartbeats.
	if err := c.WatchObject(&corev1.Node{}, &handler.EnqueueRequestForObject{}, hostIPsChangedPredicate()); err != nil {
		return fmt.Errorf("podiprecovery-controller failed to watch Nodes: %w", err)
	}

	return nil
}

// hostIPsChangedPredicate filters Node events so reconciles only fire when
// the node's host IPs change (including initial set / removal). New nodes
// are reconciled once to handle the case where pods are scheduled before the
// Node's status is populated.
func hostIPsChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldNode, oldOK := e.ObjectOld.(*corev1.Node)
			newNode, newOK := e.ObjectNew.(*corev1.Node)
			if !oldOK || !newOK {
				return false
			}
			return !nodeHostIPSet(oldNode.Status.Addresses).Equal(nodeHostIPSet(newNode.Status.Addresses))
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}
}

// nodeHostIPSet returns the set of addresses that the kubelet would use to
// populate `status.podIPs` for a hostNetwork pod scheduled on this node.
//
// This mirrors upstream `k8s.io/kubernetes/pkg/util/node.GetNodeHostIPs`:
// InternalIPs are preferred; ExternalIPs are returned only when the node
// has no InternalIP at all. The upstream helper isn't importable from
// outside k8s.io/kubernetes, so we reimplement the few lines we need
// rather than vendor the package.
//
// In any cluster with normally-provisioned nodes the InternalIP branch
// always wins — but mirroring the kubelet's selection logic keeps our
// comparison faithful in the edge case where a node only has an ExternalIP.
func nodeHostIPSet(addrs []corev1.NodeAddress) sets.Set[string] {
	internal := sets.New[string]()
	external := sets.New[string]()
	for _, a := range addrs {
		switch a.Type {
		case corev1.NodeInternalIP:
			internal.Insert(a.Address)
		case corev1.NodeExternalIP:
			external.Insert(a.Address)
		}
	}
	if internal.Len() > 0 {
		return internal
	}
	return external
}

// Reconciler implements reconcile.Reconciler.
type Reconciler struct {
	client client.Client
}

var _ reconcile.Reconciler = &Reconciler{}

// Reconcile is called for a Node when its host IPs change (or on initial
// creation). It lists operator-managed pods on the node and deletes any
// host-networked pod whose status.podIPs doesn't include any of the node's
// current host IPs (InternalIP-preferred, ExternalIP fallback).
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.WithValues("node", req.Name)

	// Gate on Installation: if Calico hasn't been installed yet, the
	// operator-managed pods we'd act on don't exist. Bail out silently.
	if _, _, err := utils.GetInstallationSpec(ctx, r.client); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to read Installation: %w", err)
	}

	node := &corev1.Node{}
	if err := r.client.Get(ctx, req.NamespacedName, node); err != nil {
		if apierrors.IsNotFound(err) {
			// Node is gone — Kubernetes garbage collection will clean up
			// the pods that ran on it. Nothing to do here.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get Node %q: %w", req.Name, err)
	}

	nodeIPs := nodeHostIPSet(node.Status.Addresses)
	if nodeIPs.Len() == 0 {
		// Nothing to compare against; bail out to avoid deleting pods
		// based on a transient empty status.
		logger.V(1).Info("Node has no host IPs reported; skipping pod IP check")
		return ctrl.Result{}, nil
	}

	// List operator-managed hostNetwork pods on this node. The label is
	// applied at render time across all hostNetwork workloads; the field
	// selector narrows by node server-side using the index registered in
	// cmd/main.go.
	var pl corev1.PodList
	if err := r.client.List(ctx, &pl,
		client.MatchingLabels{common.HostNetworkedPodLabel: "true"},
		client.MatchingFields{podNodeNameIndex: node.Name},
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list pods on node %q: %w", node.Name, err)
	}

	var firstErr error
	deleted := 0
	for _, pod := range pl.Items {
		if !pod.Spec.HostNetwork {
			// Safety check: only delete hostNetwork pods. A non-hostNetwork
			// pod that happens to carry our label has a CNI-assigned IP
			// that legitimately differs from the node's IP.
			continue
		}
		if len(pod.Status.PodIPs) == 0 {
			// Pod hasn't been status-populated yet (e.g. Pending, kubelet
			// has not admitted it). The kubelet will set the correct IPs on
			// admission; deleting now would just race that.
			continue
		}
		if podIPMatchesNode(&pod, nodeIPs) {
			continue
		}

		podIPs := make([]string, 0, len(pod.Status.PodIPs))
		for _, pip := range pod.Status.PodIPs {
			podIPs = append(podIPs, pip.IP)
		}
		logger.Info("Host networked Pod has stale IP, recreate",
			"pod", pod.Name, "namespace", pod.Namespace,
			"podIPs", podIPs, "nodeHostIPs", nodeIPs.UnsortedList())

		if delErr := r.client.Delete(ctx, &pod); delErr != nil && !apierrors.IsNotFound(delErr) {
			logger.Error(delErr, "Failed to delete pod with stale IP", "pod", pod.Name, "namespace", pod.Namespace)
			if firstErr == nil {
				firstErr = delErr
			}
			continue
		}
		deleted++
	}

	if deleted > 0 {
		logger.Info("Deleted stale-IP pods on node", "count", deleted)
	}
	return ctrl.Result{}, firstErr
}

// podIPMatchesNode returns true if any of the pod's reported IPs is in
// the node's host-IP set (see nodeHostIPSet for selection semantics).
func podIPMatchesNode(pod *corev1.Pod, nodeIPs sets.Set[string]) bool {
	for _, pip := range pod.Status.PodIPs {
		if nodeIPs.Has(pip.IP) {
			return true
		}
	}
	return false
}
