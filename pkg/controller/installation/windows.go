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
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	windowsLog = logf.Log.WithName("windows_upgrader")
)

// calicoWindowsUpgrader helps manage the upgrade of Calico Windows nodes.
// It works in conjunction with the CalicoUpdate service running on each node.
type calicoWindowsUpgrader struct {
	clientset       kubernetes.Interface
	client          client.Client
	statusManager   status.StatusManager
	version         string
	nodeInformer    cache.Controller
	nodeIndexer     cache.Indexer
	pendingUpgrades bool
}

func (w *calicoWindowsUpgrader) hasPendingUpgrades() bool {
	return w.pendingUpgrades
}

// newCalicoWindowsUpgrader creates a Calico Windows upgrader.
func newCalicoWindowsUpgrader(cs kubernetes.Interface, c client.Client, statusManager status.StatusManager) *calicoWindowsUpgrader {
	w := &calicoWindowsUpgrader{
		clientset:     cs,
		client:        c,
		statusManager: statusManager,
	}

	windowsNodeListWatch := cache.NewFilteredListWatchFromClient(cs.CoreV1().RESTClient(), "nodes", "", func(options *metav1.ListOptions) {
		options.LabelSelector = fmt.Sprintf("%s=%s", corev1.LabelOSStable, "windows")
	})
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
	nodesToUpgrade, nodesUpgrading, nodesUpgraded, err := w.getNodesToUpgrade(expectedVersion)
	if err != nil {
		return fmt.Errorf("Could not get windows nodes: %w", err)
	}

	err = w.processUpgrades(context.Background(), expectedVersion, nodesToUpgrade, nodesUpgrading, nodesUpgraded)
	if err != nil {
		return fmt.Errorf("Could not process windows nodes: %w", err)
	}

	return nil
}

// getNodesToUpgrade checks the given nodes one by one and determines whether
// it an upgrade should be triggered or whether an upgrade has been detected as
// completed.
func (w *calicoWindowsUpgrader) getNodesToUpgrade(expectedVersion string) ([]*corev1.Node, []*corev1.Node, []*corev1.Node, error) {
	nodesToUpgrade := []*corev1.Node{}
	nodesUpgraded := []*corev1.Node{}
	nodesUpgrading := []*corev1.Node{}

	for _, obj := range w.nodeIndexer.List() {
		node, ok := obj.(*corev1.Node)
		if !ok {
			return nil, nil, nil, fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
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
			windowsLog.Info(fmt.Sprintf("Node %v doesn't have the latest version. version=%v, expectedVersion=%v", node.Name, version, expectedVersion))
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
				nodesUpgraded = append(nodesUpgraded, node)
			}
		}
	}

	windowsLog.V(1).Info(fmt.Sprintf("nodesUpgraded=%v, nodesUpgrading=%v, nodesToUpgrade=%v", len(nodesUpgraded), len(nodesUpgrading), len(nodesToUpgrade)))
	w.pendingUpgrades = len(nodesToUpgrade)+len(nodesUpgrading) > 0

	return nodesToUpgrade, nodesUpgrading, nodesUpgraded, nil
}

func (w *calicoWindowsUpgrader) processUpgrades(ctx context.Context, expectedVersion string, nodesToUpgrade []*corev1.Node, nodesUpgrading []*corev1.Node, nodesUpgraded []*corev1.Node) error {
	// Add upgrade label to nodes that need to be upgraded.
	for _, n := range nodesToUpgrade {
		log.Info(fmt.Sprintf("Triggering upgrade on node %v", n.Name))

		if err := common.AddNodeLabel(ctx, w.clientset, n.Name, common.CalicoWindowsUpgradeScriptLabel, common.CalicoWindowsUpgradeScript); err != nil {
			return fmt.Errorf("Unable to patch node: %w", err)
		}

		w.statusManager.AddWindowsNodeUpgrade(n.Name, expectedVersion)
	}

	// For nodes already upgrading, ensure the status is correct
	for _, n := range nodesUpgrading {
		log.Info(fmt.Sprintf("Reconciling node upgrades in progress %v", n.Name))

		w.statusManager.AddWindowsNodeUpgrade(n.Name, expectedVersion)
	}

	// Remove upgrade label from nodes that are already upgraded.
	for _, n := range nodesUpgraded {
		log.Info(fmt.Sprintf("Removing upgrade label from upgraded node %v", n.Name))

		if err := common.RemoveNodeLabel(ctx, w.clientset, n.Name, common.CalicoWindowsUpgradeScriptLabel); err != nil {
			return fmt.Errorf("Unable to patch node: %w", err)
		}
		w.statusManager.RemoveWindowsNodeUpgrade(n.Name)
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
