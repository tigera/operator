// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"
)

var typhaLog = logf.Log.WithName("typha_autoscaler")

const (
	defaultTyphaAutoscalerSyncPeriod = 10 * time.Second

	hepCreatedLabelKey   = "projectcalico.org/created-by"
	hepCreatedLabelValue = "calico-kube-controllers"
)

// typhaAutoscaler periodically lists the nodes and, if needed, scales the Typha deployment up/down.
// Number of replicas should be at least (1 typha for every 200 nodes) + 1 but the number of typhas
// cannot exceed the number of nodes+masters.
type typhaAutoscaler struct {
	client         kubernetes.Interface
	syncPeriod     time.Duration
	statusManager  status.StatusManager
	triggerRunChan chan chan error
	isDegradedChan chan chan bool
	indexInformer  cache.SharedIndexInformer
	typhaInformer  cache.Controller
	typhaIndexer   cache.Store
	nonClusterHost bool

	// Number of currently running replicas.
	activeReplicas int32
}

type typhaAutoscalerOption func(*typhaAutoscaler)

// typhaAutoscalerOptionPeriod is an option that sets a custom sync period for the Typha autoscaler.
func typhaAutoscalerOptionPeriod(syncPeriod time.Duration) typhaAutoscalerOption {
	return func(t *typhaAutoscaler) {
		t.syncPeriod = syncPeriod
	}
}

// typhaAutoScalerOptionNonclusterHost is an option that sets the Typha autoscaler to for non-cluster host.
func typhaAutoscalerOptionNonclusterHost(nonClusterHost bool) typhaAutoscalerOption {
	return func(t *typhaAutoscaler) {
		t.nonClusterHost = nonClusterHost
	}
}

// newTyphaAutoscaler creates a new Typha autoscaler, optionally applying any options to the default autoscaler instance.
// The default sync period is 10 seconds.
func newTyphaAutoscaler(cs kubernetes.Interface, indexInformer cache.SharedIndexInformer, typhaListWatch cache.ListerWatcher, statusManager status.StatusManager, options ...typhaAutoscalerOption) *typhaAutoscaler {
	ta := &typhaAutoscaler{
		client:         cs,
		statusManager:  statusManager,
		syncPeriod:     defaultTyphaAutoscalerSyncPeriod,
		triggerRunChan: make(chan chan error),
		isDegradedChan: make(chan chan bool),
		indexInformer:  indexInformer,
	}

	// Configure an informer to monitor the active replicas.
	typhaHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if d, ok := obj.(*appsv1.Deployment); ok {
				if d.Spec.Replicas != nil {
					ta.activeReplicas = *d.Spec.Replicas
				}
			}
		},
		UpdateFunc: func(old, obj interface{}) {
			if d, ok := obj.(*appsv1.Deployment); ok {
				if d.Spec.Replicas != nil {
					ta.activeReplicas = *d.Spec.Replicas
				}
			}
		},
	}
	ta.typhaIndexer, ta.typhaInformer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: typhaListWatch,
		ObjectType:    &appsv1.Deployment{},
		ResyncPeriod:  0,
		Handler:       typhaHandlers,
		Indexers:      cache.Indexers{},
	})

	for _, option := range options {
		option(ta)
	}
	return ta
}

// start starts the Typha autoscaler, updating the Typha deployment's replica count every sync period. The triggerRunChan
// can be used to trigger an auto scale run immediately, while the isDegradedChan can be used to get the degraded status
// of the last run. The triggerRun and isDegraded functions should be used instead of instead of access these channels directly.
func (t *typhaAutoscaler) start(ctx context.Context) {
	go func() {
		degraded := false
		ticker := time.NewTicker(t.syncPeriod)
		defer ticker.Stop()
		typhaLog.Info("Starting typha autoscaler", "syncPeriod", t.syncPeriod)

		// Start the informer.
		go t.typhaInformer.Run(ctx.Done())
		// Wait for the informers to sync.
		for !t.indexInformer.HasSynced() || !t.typhaInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}

		// Autoscale on start up then do it again every tick.
		if err := t.autoscaleReplicas(); err != nil {
			degraded = true
			typhaLog.Error(err, "Failed to autoscale typha")
			t.statusManager.SetDegraded(operator.ResourceScalingError, fmt.Sprintf("Failed to autoscale typha - %s", err.Error()), nil, log)
		}

		for {
			select {
			case <-ticker.C:
				if err := t.autoscaleReplicas(); err != nil {
					degraded = true
					typhaLog.Error(err, "Failed to autoscale typha")

					// Since this run was triggered by the ticker we need to degrade the tigera status now.
					t.statusManager.SetDegraded(operator.ResourceScalingError, fmt.Sprintf("Failed to autoscale typha - %s", err.Error()), nil, log)
				} else {
					degraded = false
				}

				// Check for host-networked pods with stale IPs (e.g., after a node
				// IP change) and delete them so they get recreated with the correct
				// IP. Typha is checked first; if any Typha pod was deleted this
				// cycle, calico-node deletions are skipped to give the new Typha a
				// clean window to come up before churning calico-node pods that
				// depend on it.
				typhaBatch := t.resolveTyphaMaxUnavailable()
				deletedTypha := t.deleteStaleHostNetworkPods(
					"calico-typha",
					fmt.Sprintf("%s=%s", render.AppLabelName, render.TyphaK8sAppName),
					typhaBatch,
				) > 0
				if !deletedTypha {
					// Linux and Windows DaemonSets are paced independently of each
					// other.
					linuxBatch := t.resolveDaemonSetMaxUnavailable(render.CalicoNodeObjectName)
					t.deleteStaleHostNetworkPods(
						"calico-node",
						fmt.Sprintf("%s=%s", render.AppLabelName, render.CalicoNodeObjectName),
						linuxBatch,
					)
					windowsBatch := t.resolveDaemonSetMaxUnavailable(render.WindowsNodeObjectName)
					t.deleteStaleHostNetworkPods(
						"calico-node-windows",
						fmt.Sprintf("%s=%s", render.AppLabelName, render.WindowsNodeObjectName),
						windowsBatch,
					)
				}
			case errCh := <-t.triggerRunChan:
				if err := t.autoscaleReplicas(); err != nil {
					degraded = true

					// Return the error so the "caller" can decided what to do with the error
					errCh <- err
				} else {
					degraded = false
				}

				close(errCh)

				ticker.Stop()
				ticker = time.NewTicker(t.syncPeriod)
			case boolCh := <-t.isDegradedChan:
				boolCh <- degraded
				close(boolCh)
			case <-ctx.Done():
				typhaLog.Info("typha autoscaler shutting down")
				return
			}
		}
	}()
}

func (t *typhaAutoscaler) triggerRun() error {
	errChan := make(chan error)
	t.triggerRunChan <- errChan

	return <-errChan
}

// isDegraded checks if the last run autoscale run failed and returns true if it did and false otherwise.
func (t *typhaAutoscaler) isDegraded() bool {
	boolChan := make(chan bool)
	t.isDegradedChan <- boolChan

	return <-boolChan
}

// autoscaleReplicas calculates the number of typha pods that should be running and scales the typha deployment accordingly
func (t *typhaAutoscaler) autoscaleReplicas() error {
	var expectedReplicas int
	if t.nonClusterHost {
		heps := t.getHostEndpointCounts()
		expectedReplicas = common.GetExpectedTyphaScale(heps)
	} else {
		allSchedulableNodes, linuxNodes := t.getNodeCounts()
		typhaLog.V(5).Info("Number of nodes to consider for typha autoscaling", "all", allSchedulableNodes, "linux", linuxNodes)
		expectedReplicas = common.GetExpectedTyphaScale(allSchedulableNodes)
		if linuxNodes < expectedReplicas {
			return fmt.Errorf("not enough linux nodes to schedule typha pods on, require %d and have %d", expectedReplicas, linuxNodes)
		}
	}

	typhaLog.V(5).Info("Checking if we need to scale typha", "expectedReplicas", expectedReplicas, "currentReplicas", t.activeReplicas)
	if int32(expectedReplicas) != t.activeReplicas {
		err := t.updateReplicas(int32(expectedReplicas))
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("could not scale Typha deployment: %w", err)
		}
	}

	return nil
}

// updateReplicas updates the Typha deployment to the expected replicas if the current replica count differs.
func (t *typhaAutoscaler) updateReplicas(expectedReplicas int32) error {
	name := common.TyphaDeploymentName
	if t.nonClusterHost {
		name += render.TyphaNonClusterHostSuffix
	}
	typha, err := t.client.AppsV1().Deployments(common.CalicoNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// The replicas field defaults to 1. We need this in case spec.Replicas is nil.
	var prevReplicas int32
	prevReplicas = 1
	if typha.Spec.Replicas != nil {
		prevReplicas = *typha.Spec.Replicas
	}

	if prevReplicas == expectedReplicas {
		return nil
	}

	typhaLog.Info(fmt.Sprintf("Updating typha replicas from %d to %d", prevReplicas, expectedReplicas))
	typha.Spec.Replicas = &expectedReplicas
	_, err = t.client.AppsV1().Deployments(common.CalicoNamespace).Update(context.Background(), typha, metav1.UpdateOptions{})
	return err
}

// getNodeCounts returns the number of all the schedulable nodes and the number of the schedulable linux nodes. The linux
// node count is needed because typha pods can only be scheduled on linux nodes, however, nodes of other os types (i.e. windows)
// still need to use typha.
func (t *typhaAutoscaler) getNodeCounts() (int, int) {
	linuxNodes := 0
	schedulable := 0
	for _, obj := range t.indexInformer.GetIndexer().List() {
		n := obj.(*v1.Node)
		if n.Spec.Unschedulable {
			continue
		}

		if _, ok := n.Labels["kubernetes.azure.com/cluster"]; ok && n.Labels["type"] == "virtual-kubelet" {
			// in AKS, there is a feature called 'virtual-nodes' which represent azure's container service as a node in the kubernetes cluster.
			// virtual-nodes have many limitations, and are tainted to prevent pods from running on them.
			// calico-node isn't run there as they don't support hostNetwork or host volume mounts.
			// as such, we shouldn't consider virtual-nodes in the count towards how many typha pods should be run.
			// furthermore, typha can't run on virtual-nodes as it is hostnetworked, so we don't want it's desired
			// replica count to include it.
			continue
		}

		schedulable++
		if n.Labels["kubernetes.io/os"] == "linux" {
			linuxNodes++
		}
	}
	return schedulable, linuxNodes
}

// deleteStaleHostNetworkPods lists pods matching labelSelector in the
// calico-system namespace and compares each pod's status.podIPs against the
// current InternalIP of the node the pod is running on. If the IPs don't match
// (stale pod IP after a node IP change), up to maxBatch pods are deleted so the
// owning controller (Deployment / DaemonSet) recreates them with the correct IP.
//
// This is necessary because Kubernetes does not update status.podIPs for
// existing hostNetwork pods when the node's IP changes — it is explicitly
// immutable in the kubelet:
// https://github.com/kubernetes/kubernetes/issues/93897.
//
// Returns the number of pods deleted in this call.
//
// workloadName is used only for logging.
func (t *typhaAutoscaler) deleteStaleHostNetworkPods(workloadName, labelSelector string, maxBatch int) int {
	if t.nonClusterHost {
		return 0
	}
	if maxBatch < 1 {
		maxBatch = 1
	}

	pods, err := t.client.CoreV1().Pods(common.CalicoNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		typhaLog.V(5).Info("Failed to list pods for stale IP check", "workload", workloadName, "error", err)
		return 0
	}

	// Build a map of node name → InternalIP from the informer cache.
	nodeInternalIPs := map[string]string{}
	for _, obj := range t.indexInformer.GetIndexer().List() {
		n := obj.(*v1.Node)
		for _, addr := range n.Status.Addresses {
			if addr.Type == v1.NodeInternalIP {
				nodeInternalIPs[n.Name] = addr.Address
				break
			}
		}
	}

	deleted := 0
	for i := range pods.Items {
		if deleted >= maxBatch {
			break
		}
		pod := &pods.Items[i]
		if pod.Spec.NodeName == "" {
			continue
		}
		nodeIP, ok := nodeInternalIPs[pod.Spec.NodeName]
		if !ok {
			continue
		}

		// Check if any of the pod's IPs match the node's current InternalIP.
		match := false
		for _, podIP := range pod.Status.PodIPs {
			if podIP.IP == nodeIP {
				match = true
				break
			}
		}
		if match {
			continue
		}

		// Pod IP is stale — delete the pod so the owning controller recreates
		// it with the correct IP.
		podIPs := make([]string, len(pod.Status.PodIPs))
		for j, pip := range pod.Status.PodIPs {
			podIPs[j] = pip.IP
		}
		typhaLog.Info("Pod has stale IP after node IP change; deleting pod so it gets recreated with the correct IP",
			"workload", workloadName, "pod", pod.Name, "node", pod.Spec.NodeName,
			"podIPs", podIPs, "nodeInternalIP", nodeIP)
		if err := t.client.CoreV1().Pods(common.CalicoNamespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{}); err != nil {
			typhaLog.Error(err, "Failed to delete pod with stale IP", "workload", workloadName, "pod", pod.Name)
			continue
		}
		deleted++
	}
	return deleted
}

// resolveTyphaMaxUnavailable reads the maxUnavailable value from the Typha
// PodDisruptionBudget and resolves it to an absolute pod count using the
// current Typha replica count. Returns 1 if the PDB doesn't exist, doesn't
// have maxUnavailable set, or if the resolved value is < 1 (so progress
// is always guaranteed).
func (t *typhaAutoscaler) resolveTyphaMaxUnavailable() int {
	const fallback = 1
	pdb, err := t.client.PolicyV1().PodDisruptionBudgets(common.CalicoNamespace).Get(
		context.Background(), common.TyphaDeploymentName, metav1.GetOptions{},
	)
	if err != nil || pdb.Spec.MaxUnavailable == nil {
		return fallback
	}
	replicas := int(t.activeReplicas)
	if replicas <= 0 {
		// activeReplicas is populated by the informer; fall back to fetching
		// the deployment if it hasn't been observed yet.
		typha, err := t.client.AppsV1().Deployments(common.CalicoNamespace).Get(
			context.Background(), common.TyphaDeploymentName, metav1.GetOptions{},
		)
		if err == nil && typha.Spec.Replicas != nil {
			replicas = int(*typha.Spec.Replicas)
		}
	}
	if replicas < 1 {
		return fallback
	}
	val, err := intstr.GetScaledValueFromIntOrPercent(pdb.Spec.MaxUnavailable, replicas, true)
	if err != nil || val < 1 {
		return fallback
	}
	return val
}

// resolveDaemonSetMaxUnavailable reads the maxUnavailable value from the named
// DaemonSet's update strategy and resolves it to an absolute pod count using
// the desired DaemonSet pod count. Returns 1 if the DaemonSet doesn't exist,
// doesn't have a RollingUpdate strategy, or if the resolved value is < 1.
func (t *typhaAutoscaler) resolveDaemonSetMaxUnavailable(name string) int {
	const fallback = 1
	ds, err := t.client.AppsV1().DaemonSets(common.CalicoNamespace).Get(
		context.Background(), name, metav1.GetOptions{},
	)
	if err != nil {
		return fallback
	}
	if ds.Spec.UpdateStrategy.RollingUpdate == nil ||
		ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable == nil {
		return fallback
	}
	desired := int(ds.Status.DesiredNumberScheduled)
	if desired < 1 {
		return fallback
	}
	val, err := intstr.GetScaledValueFromIntOrPercent(
		ds.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable, desired, true,
	)
	if err != nil || val < 1 {
		return fallback
	}
	return val
}

// getHostEndpointCounts returns the number of host endpoints in the cluster that are not created by the kube-controllers.
func (t *typhaAutoscaler) getHostEndpointCounts() int {
	heps := 0
	for _, obj := range t.indexInformer.GetIndexer().List() {
		// Exclude auto host endpoints that are created by calico-kube-controllers.
		hep := obj.(*v3.HostEndpoint)
		if _, ok := hep.Labels[hepCreatedLabelKey]; ok && hep.Labels[hepCreatedLabelKey] == hepCreatedLabelValue {
			continue
		}

		heps++
	}
	return heps
}
