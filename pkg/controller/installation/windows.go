// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
	"encoding/json"
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	windowsLog = logf.Log.WithName("windows_upgrader")

	// This taint is applied to nodes upgrading Calico Windows.
	calicoWindowsUpgradingTaint = &v1.Taint{
		Key:    common.CalicoWindowsUpgradeTaintKey,
		Effect: v1.TaintEffectNoSchedule,
	}
)

// calicoWindowsUpgrader helps manage the upgrade of Calico Windows nodes.
// It works in conjunction with the CalicoUpdate service running on each node.
type calicoWindowsUpgrader struct {
	clientset            kubernetes.Interface
	client               client.Client
	statusManager        status.StatusManager
	nodeInformer         cache.Controller
	nodeIndexer          cache.Indexer
	nodesToUpgrade       []*corev1.Node
	nodesUpgrading       []*corev1.Node
	nodesFinishedUpgrade []*corev1.Node
}

func (w *calicoWindowsUpgrader) hasPendingUpgrades() bool {
	return len(w.nodesToUpgrade)+len(w.nodesUpgrading) > 0
}

// newCalicoWindowsUpgrader creates a Calico Windows upgrader.
func newCalicoWindowsUpgrader(cs kubernetes.Interface, c client.Client, windowsNodeListWatch cache.ListerWatcher, statusManager status.StatusManager) *calicoWindowsUpgrader {
	w := &calicoWindowsUpgrader{
		clientset:     cs,
		client:        c,
		statusManager: statusManager,
	}

	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) {},
		UpdateFunc: func(oldObj, newObj interface{}) {},
		DeleteFunc: func(obj interface{}) {},
	}
	w.nodeIndexer, w.nodeInformer = cache.NewIndexerInformer(windowsNodeListWatch, &corev1.Node{}, 0, handlers, cache.Indexers{})

	return w
}

func (w *calicoWindowsUpgrader) upgradeWindowsNodes(expectedProduct operatorv1.ProductVariant) error {
	expectedVersion := common.WindowsLatestVersionString(expectedProduct)
	windowsLog.V(1).Info(fmt.Sprintf("Expected version: %v", expectedVersion))

	err := w.getNodesToUpgrade(expectedVersion)
	if err != nil {
		return fmt.Errorf("Error getting windows nodes: %w", err)
	}

	err = w.processUpgrades(context.Background(), expectedVersion)
	if err != nil {
		return fmt.Errorf("Error processing windows nodes: %w", err)
	}

	return nil
}

// getNodesToUpgrade checks the given nodes one by one and determines whether
// it an upgrade should be triggered or whether an upgrade has been detected as
// completed.
func (w *calicoWindowsUpgrader) getNodesToUpgrade(expectedVersion string) error {
	nodesToUpgrade := []*corev1.Node{}
	nodesFinishedUpgraded := []*corev1.Node{}
	nodesUpgrading := []*corev1.Node{}

	for _, obj := range w.nodeIndexer.List() {
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
		}

		windowsLog.V(1).Info(fmt.Sprintf("Processing node %v", node.Name))
		exists, version := common.GetWindowsNodeVersion(node)
		// If the version annotation doesn't exist, the node does not support
		// upgrades.
		if !exists {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v doesn't have the version annotation, ignoring it", node.Name))
			continue
		}

		if version != expectedVersion {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v doesn't have the latest version. version=%v, expectedVersion=%v", node.Name, version, expectedVersion))
			// If the version is outdated and the node does not yet have the upgrade
			// label, we need to add the label to trigger the upgrade.
			if _, exists := node.Labels[common.CalicoWindowsUpgradeScriptLabel]; !exists {
				windowsLog.V(1).Info(fmt.Sprintf("Node %v doesn't have the upgrade label, going to add it", node.Name))
				nodesToUpgrade = append(nodesToUpgrade, node)
			} else {
				// If the version is outdated but it already has the upgrade label
				// we do nothing since we're waiting for the node service to finish
				// working.
				nodesUpgrading = append(nodesUpgrading, node)
			}
		} else {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v has the latest version", node.Name))
			// If the node has the latest version and it still has the upgrade
			// script label, then it has just finished upgrading and needs the label
			// removed. If it does not have the label, it's already upgraded and
			// nothing needs to be done.
			if _, exists := node.Labels[common.CalicoWindowsUpgradeScriptLabel]; exists {
				windowsLog.V(1).Info(fmt.Sprintf("Node %v still has the upgrade label, removing it", node.Name))
				nodesFinishedUpgraded = append(nodesFinishedUpgraded, node)
			}
		}
	}

	w.nodesToUpgrade = nodesToUpgrade
	w.nodesUpgrading = nodesUpgrading
	w.nodesFinishedUpgrade = nodesFinishedUpgraded

	windowsLog.V(1).Info(fmt.Sprintf("nodesToUpgrade=%v, nodesUpgrading=%v, nodesFinishedUpgrade=%v", len(w.nodesToUpgrade), len(w.nodesUpgrading), len(w.nodesFinishedUpgrade)))
	return nil
}

func (w *calicoWindowsUpgrader) startUpgrade(ctx context.Context, node *corev1.Node, expectedVersion string) error {
	windowsLog.Info(fmt.Sprintf("Starting Calico Windows upgrade on node %v", node.Name))
	if err := addTaint(ctx, w.clientset, node.Name, calicoWindowsUpgradingTaint); err != nil {
		return fmt.Errorf("Unable to add taint to node %v: %w", node.Name, err)
	}

	if err := common.AddNodeLabel(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradeScriptLabel, common.CalicoWindowsUpgradeScript); err != nil {
		return fmt.Errorf("Unable to remove label from node %v: %w", node.Name, err)
	}

	w.statusManager.AddWindowsNodeUpgrade(node.Name, expectedVersion)
	return nil
}

func (w *calicoWindowsUpgrader) finishUpgrade(ctx context.Context, node *corev1.Node) error {
	windowsLog.Info(fmt.Sprintf("Finishing upgrade on upgraded node %v", node.Name))
	if err := common.RemoveNodeLabel(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradeScriptLabel); err != nil {
		return fmt.Errorf("Unable to remove label from node: %w", err)
	}

	if err := removeTaint(ctx, w.clientset, node.Name, calicoWindowsUpgradingTaint); err != nil {
		return fmt.Errorf("Unable to clear taint from node %v: %w", node.Name, err)
	}

	w.statusManager.RemoveWindowsNodeUpgrade(node.Name)
	return nil
}

func (w *calicoWindowsUpgrader) processUpgrades(ctx context.Context, expectedVersion string) error {
	for _, n := range w.nodesToUpgrade {
		if err := w.startUpgrade(ctx, n, expectedVersion); err != nil {
			return fmt.Errorf("Unable to start upgrade on node %v: %w", n.Name, err)
		}
	}

	// For nodes already upgrading, ensure the status is correct
	for _, n := range w.nodesUpgrading {
		windowsLog.V(1).Info(fmt.Sprintf("Reconciling node upgrades in progress %v", n.Name))
		w.statusManager.AddWindowsNodeUpgrade(n.Name, expectedVersion)
	}

	for _, n := range w.nodesFinishedUpgrade {
		if err := w.finishUpgrade(ctx, n); err != nil {
			return fmt.Errorf("Unable to finish upgrade on node %v: %w", n.Name, err)
		}
	}

	return nil
}

func (w *calicoWindowsUpgrader) start() {
	stopCh := make(chan struct{})
	go w.nodeInformer.Run(stopCh)
	for !w.nodeInformer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}
}

type objPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// addTaint applies a taint to a node.
func addTaint(ctx context.Context, client kubernetes.Interface, nodeName string, taint *corev1.Taint) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := true

		for _, t := range node.Spec.Taints {
			if t.MatchTaint(taint) {
				needUpdate = false
				break
			}
		}

		if needUpdate {
			newTaints := node.DeepCopy().Spec.Taints
			newTaints = append(newTaints, *taint)

			p := []objPatch{
				// Test that the taints didn't change. If this test fails the entire
				// patch fails.
				{
					Op:    "test",
					Path:  "/spec/taints",
					Value: node.Spec.Taints,
				},
				// Add the new taints.
				{
					Op:    "add",
					Path:  "/spec/taints",
					Value: newTaints,
				},
			}

			patchBytes, err := json.Marshal(p)
			if err != nil {
				return false, err
			}

			_, err = client.CoreV1().Nodes().Patch(ctx, node.Name, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
			if err == nil {
				return true, nil
			}
			if !apierrors.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

// removeTaint clears a taint from a node.
func removeTaint(ctx context.Context, client kubernetes.Interface, nodeName string, taint *corev1.Taint) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		var needUpdate bool
		var taintIndex int

		for i, t := range node.Spec.Taints {
			if t.MatchTaint(taint) {
				taintIndex = i
				needUpdate = true
				break
			}
		}

		if needUpdate {
			p := []objPatch{
				// Test that the taint to remove didn't change. If this test fails the entire
				// patch fails.
				{
					Op:    "test",
					Path:  fmt.Sprintf("/spec/taints/%d", taintIndex),
					Value: node.Spec.Taints[taintIndex],
				},
				// Remove the taint.
				{
					Op:   "remove",
					Path: fmt.Sprintf("/spec/taints/%d", taintIndex),
				},
			}

			patchBytes, err := json.Marshal(p)
			if err != nil {
				return false, err
			}

			_, err = client.CoreV1().Nodes().Patch(ctx, node.Name, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
			if err == nil {
				return true, nil
			}
			if !apierrors.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}
