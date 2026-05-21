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
// Nodes for InternalIP changes and deletes operator-managed host-networked
// pods whose status.podIPs no longer matches the node's current InternalIP.
//
// This works around an upstream Kubernetes behavior
// (https://github.com/kubernetes/kubernetes/issues/93897) where status.podIPs
// is immutable for hostNetwork pods once set. When a node's IP changes
// (e.g. after a KubeVirt VM reboot pulls a new DHCP lease), existing
// hostNetwork pods keep their stale IPs in their status, the Kubernetes
// EndpointSlice controller advertises the stale IPs, and Felix can't reach
// Typha. Only deleting and recreating the pod causes the kubelet to populate
// status.podIPs from the current node IP.
package podiprecovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	"github.com/tigera/operator/pkg/render/webhooks"
)

var log = logf.Log.WithName("controller_podiprecovery")

// targetLabelSelectors is the set of label selectors identifying
// operator-managed pods that are (or may be) host-networked. The controller
// applies a per-pod hostNetwork check before deleting, so non-hostNetwork
// pods that happen to match are left alone.
var targetLabelSelectors = []labels.Selector{
	labels.SelectorFromSet(labels.Set{render.AppLabelName: render.TyphaK8sAppName}),
	labels.SelectorFromSet(labels.Set{render.AppLabelName: render.CalicoNodeObjectName}),
	labels.SelectorFromSet(labels.Set{render.AppLabelName: render.WindowsNodeObjectName}),
	labels.SelectorFromSet(labels.Set{render.AppLabelName: dpi.DeepPacketInspectionName}),
	labels.SelectorFromSet(labels.Set{render.AppLabelName: applicationlayer.ApplicationLayerDaemonsetName}),
	labels.SelectorFromSet(labels.Set{"apiserver": "true"}),
	labels.SelectorFromSet(labels.Set{render.AppLabelName: webhooks.WebhooksName}),
}

// Add wires the controller into the manager.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	r := &Reconciler{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
	}

	c, err := ctrlruntime.NewController("podiprecovery-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create podiprecovery-controller: %w", err)
	}

	// Watch Node objects. Only enqueue reconciliations when the set of
	// InternalIPs has changed — that is the only signal that interests us,
	// and it avoids spurious reconciles for routine kubelet heartbeats.
	if err := c.WatchObject(&corev1.Node{}, &handler.EnqueueRequestForObject{}, internalIPChangedPredicate()); err != nil {
		return fmt.Errorf("podiprecovery-controller failed to watch Nodes: %w", err)
	}

	return nil
}

// internalIPChangedPredicate filters Node events so reconciles only fire when
// the node's InternalIPs change (including initial set / removal). New nodes
// are reconciled once to handle the case where pods are scheduled before the
// Node's status is populated.
func internalIPChangedPredicate() predicate.Predicate {
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
			return !sameInternalIPs(oldNode.Status.Addresses, newNode.Status.Addresses)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}
}

// sameInternalIPs returns true when both slices contain the same set of
// NodeInternalIP addresses (order-independent).
func sameInternalIPs(a, b []corev1.NodeAddress) bool {
	aIPs := internalIPSet(a)
	bIPs := internalIPSet(b)
	if len(aIPs) != len(bIPs) {
		return false
	}
	for ip := range aIPs {
		if !bIPs[ip] {
			return false
		}
	}
	return true
}

func internalIPSet(addrs []corev1.NodeAddress) map[string]bool {
	out := map[string]bool{}
	for _, a := range addrs {
		if a.Type == corev1.NodeInternalIP {
			out[a.Address] = true
		}
	}
	return out
}

// Reconciler implements reconcile.Reconciler.
type Reconciler struct {
	client client.Client
	scheme *runtime.Scheme
}

var _ reconcile.Reconciler = &Reconciler{}

// Reconcile is called for a Node when its InternalIPs change (or on initial
// creation). It lists operator-managed pods on the node and deletes any
// host-networked pod whose status.podIPs doesn't include any of the node's
// current InternalIPs.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.WithValues("node", req.Name)

	node := &corev1.Node{}
	if err := r.client.Get(ctx, req.NamespacedName, node); err != nil {
		if apierrors.IsNotFound(err) {
			// Node is gone — Kubernetes garbage collection will clean up
			// the pods that ran on it. Nothing to do here.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get Node %q: %w", req.Name, err)
	}

	nodeIPs := internalIPSet(node.Status.Addresses)
	if len(nodeIPs) == 0 {
		// Nothing to compare against; bail out to avoid deleting pods
		// based on a transient empty status.
		logger.V(1).Info("Node has no InternalIPs reported; skipping pod IP check")
		return ctrl.Result{}, nil
	}

	// List operator-managed pods running on this node. We list once per
	// label selector and filter by spec.nodeName on the client side. The
	// pod list is small enough that this is cheap.
	pods, err := r.listOperatorManagedPodsOnNode(ctx, node.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list pods on node %q: %w", node.Name, err)
	}

	var firstErr error
	deleted := 0
	for i := range pods {
		pod := &pods[i]
		if !pod.Spec.HostNetwork {
			// Safety check: only delete hostNetwork pods. A non-hostNetwork
			// pod that happens to match our labels has a CNI-assigned IP
			// that legitimately differs from the node's IP.
			continue
		}
		if len(pod.Status.PodIPs) == 0 && pod.Status.PodIP == "" {
			// Pod hasn't been status-populated yet (e.g. Pending, kubelet
			// has not admitted it). The kubelet will set the correct IPs on
			// admission; deleting now would just race that.
			continue
		}
		if podIPMatchesNode(pod, nodeIPs) {
			continue
		}

		podIPs := make([]string, 0, len(pod.Status.PodIPs))
		for _, pip := range pod.Status.PodIPs {
			podIPs = append(podIPs, pip.IP)
		}
		logger.Info("Deleting pod with stale IP after node IP change so its controller can recreate it with the current IP",
			"pod", pod.Name, "namespace", pod.Namespace,
			"podIPs", podIPs, "nodeInternalIPs", keys(nodeIPs))

		if delErr := r.client.Delete(ctx, pod); delErr != nil && !apierrors.IsNotFound(delErr) {
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

// listOperatorManagedPodsOnNode lists pods on the given node that match any
// of the operator's host-networked-workload label selectors.
func (r *Reconciler) listOperatorManagedPodsOnNode(ctx context.Context, nodeName string) ([]corev1.Pod, error) {
	seen := map[string]struct{}{}
	var out []corev1.Pod
	for _, sel := range targetLabelSelectors {
		var pl corev1.PodList
		if err := r.client.List(ctx, &pl, &client.ListOptions{LabelSelector: sel}); err != nil {
			return nil, fmt.Errorf("listing pods with selector %q: %w", sel.String(), err)
		}
		for i := range pl.Items {
			pod := &pl.Items[i]
			if pod.Spec.NodeName != nodeName {
				continue
			}
			key := pod.Namespace + "/" + pod.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, *pod)
		}
	}
	return out, nil
}

// podIPMatchesNode returns true if any of the pod's reported IPs is also
// listed as an InternalIP on the node.
func podIPMatchesNode(pod *corev1.Pod, nodeIPs map[string]bool) bool {
	for _, pip := range pod.Status.PodIPs {
		if nodeIPs[pip.IP] {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
