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

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	nodeutils "github.com/tigera/operator/pkg/controller/node"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	windowsLog = logf.Log.WithName("windows_upgrader")

	defaultMaxUnavailable = intstr.FromInt(1)
)

type CalicoWindowsUpgrader interface {
	SetInstallationParams(variant operatorv1.ProductVariant, maxUnavailable *intstr.IntOrString)
	HasPendingUpgrades() bool
	UpgradeWindowsNodes() error
	Start(ctx context.Context)
}

// calicoWindowsUpgrader helps manage the upgrade of Calico Windows nodes.
// It works in conjunction with the CalicoUpgrade service running on each node.
type calicoWindowsUpgrader struct {
	clientset            kubernetes.Interface
	client               client.Client
	statusManager        status.StatusManager
	reconcileRequestChan chan utils.ReconcileRequest
	triggerSyncChan      chan struct{}
	nodeIndexer          cache.Indexer
	nodesToUpgrade       map[string]*corev1.Node
	nodesUpgrading       map[string]*corev1.Node
	nodesFinishedUpgrade map[string]*corev1.Node
	maxUnavailable       *intstr.IntOrString
	expectedVersion      string
	expectedVariant      operatorv1.ProductVariant
	syncPeriod           time.Duration
	mutex                *sync.Mutex
	needSync             bool
	installChanged       bool
}

func (w *calicoWindowsUpgrader) HasPendingUpgrades() bool {
	return len(w.nodesToUpgrade)+len(w.nodesUpgrading) > 0
}

type calicoWindowsUpgraderOption func(*calicoWindowsUpgrader)

// calicoWindowsUpraderSyncPeriod sets the sync period for the
// calicoWindowsUpgrader.
func calicoWindowsUpgraderSyncPeriod(syncPeriod time.Duration) calicoWindowsUpgraderOption {
	return func(w *calicoWindowsUpgrader) {
		w.syncPeriod = syncPeriod
	}
}

// NewCalicoWindowsUpgrader creates a Calico Windows upgrader.
func NewCalicoWindowsUpgrader(cs kubernetes.Interface, c client.Client, indexer cache.Indexer, statusManager status.StatusManager, requestChan chan utils.ReconcileRequest, options ...calicoWindowsUpgraderOption) CalicoWindowsUpgrader {
	w := &calicoWindowsUpgrader{
		clientset:            cs,
		client:               c,
		statusManager:        statusManager,
		reconcileRequestChan: requestChan,
		triggerSyncChan:      make(chan struct{}),
		nodeIndexer:          indexer,
		maxUnavailable:       &defaultMaxUnavailable,
		syncPeriod:           10 * time.Second,
		mutex:                &sync.Mutex{},
		needSync:             true,
	}

	for _, o := range options {
		o(w)
	}
	return w
}

func (w *calicoWindowsUpgrader) SetInstallationParams(newVariant operatorv1.ProductVariant, newMaxUnavailable *intstr.IntOrString) {
	w.mutex.Lock()
	defer func() {
		w.mutex.Unlock()
		w.triggerSyncChan <- struct{}{}
	}()

	if newMaxUnavailable == nil {
		newMaxUnavailable = &defaultMaxUnavailable
	}

	// Check whether the variant or maxUnavailable has changed. If so, we should
	// require a sync before an upgrade.
	w.installChanged = false
	if w.expectedVariant != newVariant || newMaxUnavailable.Type != w.maxUnavailable.Type || newMaxUnavailable.IntVal != w.maxUnavailable.IntVal || newMaxUnavailable.StrVal != w.maxUnavailable.StrVal {
		w.needSync = true
		w.installChanged = true
	}

	newVersion := common.WindowsLatestVersionString(newVariant)
	windowsLog.V(1).Info(fmt.Sprintf("Setting installation params. Variant: old=%v, new=%v. Version: old=%v, new=%v. MaxUnavailable: old=%v, new=%v",
		w.expectedVariant, newVariant, w.expectedVersion, newVersion, w.maxUnavailable.String(), newMaxUnavailable.String()))

	w.maxUnavailable = newMaxUnavailable
	w.expectedVariant = newVariant
	w.expectedVersion = newVersion
}

func (w *calicoWindowsUpgrader) sync() (bool, error) {
	w.mutex.Lock()
	windowsLog.V(1).Info("Syncing")
	defer w.mutex.Unlock()

	// Only do the sync if we've set the installation variant and version.
	if w.expectedVersion == "" {
		windowsLog.V(1).Info("Skipping sync since installation params not set yet")
		w.needSync = true
		return false, nil
	}

	// For now, do nothing if the upgrade version is Enterprise since current
	// Enterprise versions do not support the upgrade.
	// This prevents a user from accidentally triggering an
	// in-place upgrade from Calico v3.21.0 to Enterprise v3.10.x. That upgrade
	// would fail since the calico windows upgrade is will only be supported in
	// Enterprise v3.11+
	// TODO: remove this once Enterprise v3.11.0 is released.
	//if w.expectedVariant == operatorv1.TigeraSecureEnterprise {
	//	windowsLog.V(1).Info("Enterprise upgrades for Windows are not currently supported, skipping remainder of sync")
	//	w.needSync = false
	//	return false, nil
	//}

	// Sync the Windows nodes' upgrade status.
	nodesChanged, err := w.syncNodesToUpgrade()
	if err != nil {
		w.statusManager.SetDegraded("Failed to sync Windows nodes", err.Error())
		// If the sync failed, we should require the sync happens again before
		// the upgrade runs.
		w.needSync = true
		return false, err
	}

	// The sync completed, the upgrade can now run.
	w.needSync = false
	return nodesChanged || w.installChanged, nil
}

// UpgradeWindowsNodes upgrades the Calico for Windows installation on outdated
// nodes. For upgrades from Calico -> Calico Enterprise, upgrades happen
// immediately. For other upgrades, the installation's
// NodeUpdateStrategy.RollingUpdate.MaxUnavailable value is respected.
func (w *calicoWindowsUpgrader) UpgradeWindowsNodes() error {
	w.mutex.Lock()
	windowsLog.V(1).Info("Upgrading windows nodes")
	defer func() {
		w.mutex.Unlock()
		w.triggerSyncChan <- struct{}{}
	}()

	// Skip the upgrade processing if we need a sync first.
	if w.needSync {
		windowsLog.V(1).Info("Sync needed before upgrade, returning")
		return nil
	}

	// For now, do nothing if the upgrade version is Enterprise since current
	// Enterprise versions do not support the upgrade.
	// This prevents a user from accidentally triggering an
	// in-place upgrade from Calico v3.21.0 to Enterprise v3.10.x. That upgrade
	// would fail since the calico windows upgrade is will only be supported in
	// Enterprise v3.11+
	// TODO: remove this once Enterprise v3.11.0 is released.
	//if w.expectedVariant == operatorv1.TigeraSecureEnterprise {
	//	windowsLog.V(1).Info("Enterprise upgrades for Windows are not currently supported")
	//	return nil
	//}

	// Get the total # of windows nodes we can have upgrading using the
	// maxUnavailable value, if the node upgrade strategy was respected.
	numWindowsNodes := len(w.nodesToUpgrade) + len(w.nodesUpgrading) + len(w.nodesFinishedUpgrade)
	maxUnavailable, err := intstr.GetValueFromIntOrPercent(w.maxUnavailable, numWindowsNodes, false)
	if err != nil {
		return fmt.Errorf("Invalid maxUnavailable value: %w", err)
	}

	// Trigger the upgrade of the subset of upgradable nodes.
	nodesToUpgrade := w.getMaxNodesToUpgrade(maxUnavailable)
	windowsLog.V(1).Info(fmt.Sprintf("Total Windows nodes=%v, maxUnavailable=%v, nodesToUpgrade=%v", numWindowsNodes, maxUnavailable, len(nodesToUpgrade)))
	for _, n := range nodesToUpgrade {
		if err := w.startUpgrade(context.Background(), n); err != nil {
			return fmt.Errorf("Unable to start upgrade on node %v: %w", n.Name, err)
		}
	}

	// For nodes already upgrading, ensure the status is correct
	for _, n := range w.nodesUpgrading {
		windowsLog.V(1).Info(fmt.Sprintf("Reconciling node upgrades in progress %v", n.Name))
		_, currentVersion := common.GetWindowsNodeVersion(n)
		w.statusManager.AddWindowsNodeUpgrade(n.Name, currentVersion, w.expectedVersion)
	}

	for _, n := range w.nodesFinishedUpgrade {
		if err := w.finishUpgrade(context.Background(), n); err != nil {
			return fmt.Errorf("Unable to finish upgrade on node %v: %w", n.Name, err)
		}
	}

	// After an upgrade has run, a sync must occur before the upgrade is run
	// again.
	w.needSync = true
	//w.triggerSyncChan <- struct{}{}
	return nil
}

// getMaxNodesToUpgrade returns a list of nodes to upgrade, which is a subset of
// the input list of nodes to upgrade. The list of nodes to upgrade is filtered
// depending on the upgrade type and the value of
// installation.spec.nodeUpdateStrategy.rollingUpdate.maxUnavailable.
func (w *calicoWindowsUpgrader) getMaxNodesToUpgrade(maxUnavailable int) []*corev1.Node {
	// Figure out how many of the nodes already upgrading count towards
	// maxUnavailable. We do not apply maxUnavailable to OS -> Enterprise
	// upgrades so discount those.
	count := 0
	for _, node := range w.nodesUpgrading {
		// Version should exist on the node but skip it if it doesn't.
		exists, currentVersion := common.GetWindowsNodeVersion(node)
		if !exists {
			windowsLog.Info(fmt.Sprintf("Node %v is missing version annotation, skipping", node.Name))
			continue
		}

		// If the upgrade is from OS -> Enterprise, we trigger the upgrade
		// immediately.
		if strings.HasPrefix(currentVersion, "Calico") && strings.HasPrefix(w.expectedVersion, "Enterprise") {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v is upgrading from OS -> Enterprise, do not count towards upgrading count", node.Name))
			continue
		}
		windowsLog.V(1).Info(fmt.Sprintf("Node %v is already upgrading and counts towards limit", node.Name))
		count++
	}

	upgradeOStoEnt := []*corev1.Node{}
	upgradeRest := []*corev1.Node{}
	for _, node := range w.nodesToUpgrade {
		// Version should exist on the node but skip it if it doesn't.
		exists, currentVersion := common.GetWindowsNodeVersion(node)
		if !exists {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v is missing version annotation, skipping", node.Name))
			continue
		}

		// If the upgrade is from OS -> Enterprise, we trigger the upgrade
		// immediately.
		if strings.HasPrefix(currentVersion, "Calico") && strings.HasPrefix(w.expectedVersion, "Enterprise") {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v needs to be upgraded from OS -> Enterprise, adding to toUpgrade", node.Name))
			upgradeOStoEnt = append(upgradeOStoEnt, node)
			continue
		}

		// If the number of upgrading nodes (subject to maxUnavailable) is less
		// than maxUnavailable, then add it to the list.
		if count < maxUnavailable {
			windowsLog.V(1).Info(fmt.Sprintf("nodesAlreadyUpgrading(%v) < maxUnavailable(%v), adding node %v", count, maxUnavailable, node.Name))
			upgradeRest = append(upgradeRest, node)
			count++
		}
	}

	return append(upgradeOStoEnt, upgradeRest...)
}

// syncNodesToUpgrade gets the nodes to upgrade, nodes upgrading, and nodes
// finished upgrading and compares the upgrade state of those nodes with the
// previous state of those nodes. The current state of the nodes
// to-upgrade/upgrading/finished-upgrading is cached to be used for the next
// run. In addition to any error, this function returns true if the upgrade
// status has changed.
func (w *calicoWindowsUpgrader) syncNodesToUpgrade() (bool, error) {
	currNodesToUpgrade := make(map[string]*corev1.Node)
	currNodesFinishedUpgrade := make(map[string]*corev1.Node)
	currNodesUpgrading := make(map[string]*corev1.Node)

	for _, obj := range w.nodeIndexer.List() {
		node, ok := obj.(*corev1.Node)
		if !ok {
			return false, fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
		}

		if node.Labels[corev1.LabelOSStable] != "windows" {
			continue
		}

		windowsLog.V(1).Info(fmt.Sprintf("Processing node %v", node.Name))
		exists, version := common.GetWindowsNodeVersion(node)
		// If the version annotation doesn't exist, something is wrong with the
		// Calico Windows node or it needs to be upgraded manually to
		// a version supported by the calicoWindowsUpgrader.
		if !exists {
			return false, fmt.Errorf("Node %v does not have the version annotation, it might be unhealthy or it might be running an unsupported Calico version.", node.Name)
		}

		if version != w.expectedVersion {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v doesn't have the latest version. version=%v, expectedVersion=%v", node.Name, version, w.expectedVersion))
			// If the version is outdated and the node does not yet have the upgrade
			// label, we need to add the label to trigger the upgrade.
			if _, exists := node.Labels[common.CalicoWindowsUpgradeScriptLabel]; !exists {
				windowsLog.V(1).Info(fmt.Sprintf("Node %v doesn't have the upgrade label", node.Name))
				currNodesToUpgrade[node.Name] = node
			} else {
				// If the version is outdated but it already has the upgrade label
				// we do nothing since we're waiting for the node service to finish
				// working.
				currNodesUpgrading[node.Name] = node
			}
		} else {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v has the latest version", node.Name))
			// If the node has the latest version and it still has the upgrade
			// script label, then it has just finished upgrading and needs the label
			// removed. If it does not have the label, it's already upgraded and
			// nothing needs to be done.
			if _, exists := node.Labels[common.CalicoWindowsUpgradeScriptLabel]; exists {
				windowsLog.V(1).Info(fmt.Sprintf("Node %v has finished the upgrade", node.Name))
				currNodesFinishedUpgrade[node.Name] = node
			}
		}
	}

	// Save copy of previous node upgrade status values.
	prevNodesToUpgrade := make(map[string]*corev1.Node)
	prevNodesUpgrading := make(map[string]*corev1.Node)
	prevNodesFinishedUpgrade := make(map[string]*corev1.Node)

	for k, v := range w.nodesToUpgrade {
		prevNodesToUpgrade[k] = v
	}
	for k, v := range w.nodesUpgrading {
		prevNodesUpgrading[k] = v
	}
	for k, v := range w.nodesFinishedUpgrade {
		prevNodesFinishedUpgrade[k] = v
	}

	// Cache the current node upgrade status values.
	w.nodesToUpgrade = currNodesToUpgrade
	w.nodesUpgrading = currNodesUpgrading
	w.nodesFinishedUpgrade = currNodesFinishedUpgrade

	windowsLog.V(1).Info(
		fmt.Sprintf(
			"toUpgrade: old=%v, new=%v. upgrading: old=%v, new=%v. finished: old=%v, new=%v",
			len(prevNodesToUpgrade), len(currNodesToUpgrade), len(prevNodesUpgrading), len(currNodesUpgrading), len(prevNodesFinishedUpgrade), len(currNodesFinishedUpgrade)))

	// Check if the length of the node upgrade status values differ. If so,
	// a sync is needed.
	if len(prevNodesToUpgrade) != len(currNodesToUpgrade) || len(prevNodesUpgrading) != len(currNodesUpgrading) || len(prevNodesFinishedUpgrade) != len(currNodesFinishedUpgrade) {
		windowsLog.V(1).Info("Node upgrade status has changed, slice len differs")
		return true, nil
	}

	// Check if nodes to upgrade have changed since last sync.
	for nodeName, oldNode := range prevNodesToUpgrade {
		newNode, ok := currNodesToUpgrade[nodeName]
		if !ok {
			windowsLog.V(1).Info(fmt.Sprintf("node %v not in current nodes", nodeName))
			return true, nil
		}
		if w.hasNodeUpgradeStateChanged(oldNode, newNode) {
			return true, nil
		}
	}
	// Check if nodes upgrading have changed since last sync.
	for nodeName, oldNode := range prevNodesUpgrading {
		newNode, ok := currNodesUpgrading[nodeName]
		if !ok {
			return true, nil
		}
		if w.hasNodeUpgradeStateChanged(oldNode, newNode) {
			return true, nil
		}
	}
	// Check if nodes finished upgrade have changed since last sync.
	for nodeName, oldNode := range prevNodesFinishedUpgrade {
		newNode, ok := currNodesFinishedUpgrade[nodeName]
		if !ok {
			return true, nil
		}
		if w.hasNodeUpgradeStateChanged(oldNode, newNode) {
			return true, nil
		}
	}

	return false, nil
}

// hasNodeUpgradeStateChanged checks the old and new versions of a node and
// determines whether either the upgrade label or version annotation has
// changed.
func (w *calicoWindowsUpgrader) hasNodeUpgradeStateChanged(old *corev1.Node, new *corev1.Node) bool {
	// We already validate that the version annotation exists.
	_, oldVersion := common.GetWindowsNodeVersion(old)
	_, newVersion := common.GetWindowsNodeVersion(new)

	oldUpgradeLabel := old.Labels[common.CalicoWindowsUpgradeScriptLabel]
	newUpgradeLabel := new.Labels[common.CalicoWindowsUpgradeScriptLabel]

	windowsLog.V(1).Info(fmt.Sprintf("node=%v. version: old=%v, new=%v. label: old=%v, new=%v", old.Name, oldVersion, newVersion, oldUpgradeLabel, newUpgradeLabel))

	if oldVersion != newVersion || oldUpgradeLabel != newUpgradeLabel {
		return true
	}
	return false
}

func (w *calicoWindowsUpgrader) startUpgrade(ctx context.Context, node *corev1.Node) error {
	windowsLog.Info(fmt.Sprintf("Starting Calico Windows upgrade on node %v", node.Name))
	if err := addTaint(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradingTaint); err != nil {
		return fmt.Errorf("Unable to add taint to node %v: %w", node.Name, err)
	}

	if err := nodeutils.AddNodeLabel(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradeScriptLabel, common.CalicoWindowsUpgradeScript); err != nil {
		return fmt.Errorf("Unable to remove label from node %v: %w", node.Name, err)
	}

	_, currentVersion := common.GetWindowsNodeVersion(node)
	w.statusManager.AddWindowsNodeUpgrade(node.Name, currentVersion, w.expectedVersion)
	return nil
}

func (w *calicoWindowsUpgrader) finishUpgrade(ctx context.Context, node *corev1.Node) error {
	windowsLog.Info(fmt.Sprintf("Finishing upgrade on upgraded node %v", node.Name))
	if err := removeTaint(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradingTaint); err != nil {
		return fmt.Errorf("Unable to clear taint from node %v: %w", node.Name, err)
	}

	if err := nodeutils.RemoveNodeLabel(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradeScriptLabel); err != nil {
		return fmt.Errorf("Unable to remove label from node: %w", err)
	}

	w.statusManager.RemoveWindowsNodeUpgrade(node.Name)
	return nil
}

func (w *calicoWindowsUpgrader) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(w.syncPeriod)
		defer ticker.Stop()
		for {
			needsReconcile, err := w.sync()
			if err == nil {
				// If the upgrade status of the nodes has changed since the last
				// sync, then try to queue up a reconcile.
				if needsReconcile {
					windowsLog.V(1).Info("Node upgrade status has changed, triggering reconcile")
					request := utils.ReconcileRequest{
						Context:    context.Background(),
						Request:    reconcile.Request{},
						ResultChan: make(chan utils.ReconcileResult),
					}

					select {
					case w.reconcileRequestChan <- request:
					default:
						// If the reconcile request chan is blocked just drop
						// the reconcile request since we know there is already
						// one queued up.
						windowsLog.V(1).Info("Dropping reconcile request")
					}
				}
			} else {
				windowsLog.Error(err, "Failed to sync Calico Windows upgrader")
			}

			select {
			case <-ticker.C:
			case <-w.triggerSyncChan:
				windowsLog.V(1).Info("Triggering sync")
			case <-ctx.Done():
				windowsLog.Info("Stopping sync loop")
				return
			}
		}
	}()
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
