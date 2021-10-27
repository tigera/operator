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
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	nodeutils "github.com/tigera/operator/pkg/controller/utils/node"

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
)

var (
	windowsLog = logf.Log.WithName("windows_upgrader")

	defaultMaxUnavailable = 1
)

type CalicoWindowsUpgrader interface {
	UpdateConfig(install *operatorv1.InstallationSpec)
	Start(ctx context.Context)
}

// calicoWindowsUpgrader helps manage the upgrade of Calico Windows nodes.
// It works in conjunction with the CalicoUpgrade service running on each node.
type calicoWindowsUpgrader struct {
	clientset     kubernetes.Interface
	client        client.Client
	statusManager status.StatusManager
	nodeIndexer   cache.SharedIndexInformer
	syncPeriod    time.Duration
	installChan   chan *operatorv1.InstallationSpec
	install       *operatorv1.InstallationSpec
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
func NewCalicoWindowsUpgrader(cs kubernetes.Interface, c client.Client, indexer cache.SharedIndexInformer, statusManager status.StatusManager, options ...calicoWindowsUpgraderOption) CalicoWindowsUpgrader {
	w := &calicoWindowsUpgrader{
		clientset:     cs,
		client:        c,
		statusManager: statusManager,
		nodeIndexer:   indexer,
		syncPeriod:    10 * time.Second,
		installChan:   make(chan *operatorv1.InstallationSpec, 100),
	}

	for _, o := range options {
		o(w)
	}
	return w
}

// UpdateConfig updates the calicoWindowsUpgrader's installation config.
func (w *calicoWindowsUpgrader) UpdateConfig(install *operatorv1.InstallationSpec) {
	w.installChan <- install
}

// getNodeUpgradeStatus checks the nodes from its indexer and determines whether
// the nodes are:
// - pending: Node does not have the expected variant and/or version. No upgrade label.
// - in-progress: Node does not have the expected variant and/or version. It has the upgrade in-progress label.
// - in-sync: Node has the expected variant and version. It does not have the upgrade in-progress label.
// This returns an error (if any) and maps of the nodes that are pending,
// in-progress, or in-sync.
func (w *calicoWindowsUpgrader) getNodeUpgradeStatus() (error, map[string]*corev1.Node, map[string]*corev1.Node, map[string]*corev1.Node) {
	pending := make(map[string]*corev1.Node)
	insync := make(map[string]*corev1.Node)
	inprogress := make(map[string]*corev1.Node)
	expectedVersion := w.getExpectedVersion()

	for _, obj := range w.nodeIndexer.GetIndexer().List() {
		node, ok := obj.(*corev1.Node)
		if !ok {
			return fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj), nil, nil, nil
		}

		if node.Labels[corev1.LabelOSStable] != "windows" {
			continue
		}

		windowsLog.V(1).Info(fmt.Sprintf("Processing node %v", node.Name))
		exists, variant, version := common.GetNodeVariantAndVersion(node)

		// If the version annotation doesn't exist, something is wrong with the
		// Calico Windows node or it needs to be upgraded manually to
		// a version supported by the calicoWindowsUpgrader.
		if !exists {
			return fmt.Errorf("Node %v does not have the version annotation, it might be unhealthy or it might be running an unsupported Calico version.", node.Name), nil, nil, nil
		}

		if variant != w.install.Variant || version != expectedVersion {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v doesn't have the latest variant and/or version. variant=%v, expectedVariant=%v, version=%v, expectedVersion=%v", node.Name, variant, w.install.Variant, version, expectedVersion))

			if node.Labels[common.CalicoWindowsUpgradeLabel] == common.CalicoWindowsUpgradeLabelInProgress {
				windowsLog.V(1).Info(fmt.Sprintf("Node %v has the upgrade in-progress label", node.Name))
				inprogress[node.Name] = node
			} else {
				// If the version is outdated but it already has the upgrade label
				// we do nothing since we're waiting for the node service to finish
				// working.
				windowsLog.V(1).Info(fmt.Sprintf("Node %v is pending upgrade", node.Name))
				pending[node.Name] = node
			}
		} else {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v has the latest variant and version", node.Name))
			// If the node has the latest version and it still has the upgrade
			// script label, then it has just finished upgrading and needs the label
			// removed. If it does not have the label, it's already upgraded and
			// nothing needs to be done.
			if node.Labels[common.CalicoWindowsUpgradeLabel] == common.CalicoWindowsUpgradeLabelInProgress {
				windowsLog.V(1).Info(fmt.Sprintf("Node %v still has the upgrade label", node.Name))
				inprogress[node.Name] = node
			} else {
				insync[node.Name] = node
			}
		}
	}

	windowsLog.V(1).Info(fmt.Sprintf("pending=%v, in-progress=%v, in-sync=%v", len(pending), len(inprogress), len(insync)))
	return nil, pending, inprogress, insync
}

func (w *calicoWindowsUpgrader) upgradeCompleted(node *corev1.Node) bool {
	_, variant, version := common.GetNodeVariantAndVersion(node)
	if variant == w.install.Variant && version == w.getExpectedVersion() {
		return true
	}
	return false
}

func (w *calicoWindowsUpgrader) isUpgradeFromCalicoToEnterprise(node *corev1.Node) bool {
	_, variant, _ := common.GetNodeVariantAndVersion(node)
	if variant == operatorv1.Calico && w.install.Variant == operatorv1.TigeraSecureEnterprise {
		return true
	}
	return false
}

func (w *calicoWindowsUpgrader) getExpectedVersion() string {
	if w.install.Variant == operatorv1.TigeraSecureEnterprise {
		return components.EnterpriseRelease
	}
	return components.CalicoRelease
}

func (w *calicoWindowsUpgrader) updateWindowsNodes() {
	if w.install == nil {
		windowsLog.V(1).Info("Skipping update since installation not set yet")
		return
	}

	err, pending, inprogress, insync := w.getNodeUpgradeStatus()
	if err != nil {
		windowsLog.Error(err, "Failed to get Windows nodes upgrade status")
		return
	}

	for _, node := range inprogress {
		if w.upgradeCompleted(node) {
			if err := w.finishUpgrade(context.Background(), node); err != nil {
				// Log the error and continue. We will retry when we update nodes again.
				windowsLog.Info(fmt.Sprintf("Could not complete upgrade on node %v: %v", node.Name, err))
				continue
			}
			// Successfully finished completing the upgrade. Moving the node
			// from in-progress to in-sync.
			insync[node.Name] = node
			delete(inprogress, node.Name)
		}
	}

	// Get the total # of windows nodes we can have upgrading using the
	// maxUnavailable value, if the node upgrade strategy was respected.
	numWindowsNodes := len(pending) + len(inprogress) + len(insync)
	maxUnavailable, err := intstr.GetValueFromIntOrPercent(w.install.NodeUpdateStrategy.RollingUpdate.MaxUnavailable, numWindowsNodes, false)
	if err != nil {
		windowsLog.Error(err, "Invalid maxUnavailable value, falling back to default of 1")
		maxUnavailable = defaultMaxUnavailable
	}

	for _, node := range pending {
		// For upgrades from Calico -> Enterprise, we always upgrade regardless
		// of maxUnavailable. For other upgrades, check that we have room
		// available.
		if w.isUpgradeFromCalicoToEnterprise(node) || len(inprogress) < maxUnavailable {
			if err := w.startUpgrade(context.Background(), node); err != nil {
				// Log the error and continue. We will retry when we update nodes again.
				windowsLog.Info(fmt.Sprintf("Could not start upgrade on node %v: %v", node.Name, err))
				continue
			}
			// Successfully started the upgrade. Moving the node
			// from pending to in-progress.
			inprogress[node.Name] = node
			delete(pending, node.Name)
		}
	}
}

func (w *calicoWindowsUpgrader) startUpgrade(ctx context.Context, node *corev1.Node) error {
	windowsLog.Info(fmt.Sprintf("Starting Calico Windows upgrade on node %v", node.Name))
	if err := addTaint(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradingTaint); err != nil {
		return fmt.Errorf("Unable to add taint to node %v: %w", node.Name, err)
	}

	if err := nodeutils.AddNodeLabel(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradeLabel, common.CalicoWindowsUpgradeLabelInProgress); err != nil {
		return fmt.Errorf("Unable to remove label from node %v: %w", node.Name, err)
	}

	_, currentVariant, currentVersion := common.GetNodeVariantAndVersion(node)
	w.statusManager.AddWindowsNodeUpgrade(node.Name, currentVariant, w.install.Variant, currentVersion, w.getExpectedVersion())
	return nil
}

func (w *calicoWindowsUpgrader) finishUpgrade(ctx context.Context, node *corev1.Node) error {
	windowsLog.Info(fmt.Sprintf("Finishing upgrade on upgraded node %v", node.Name))
	if err := removeTaint(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradingTaint); err != nil {
		return fmt.Errorf("Unable to clear taint from node %v: %w", node.Name, err)
	}

	if err := nodeutils.RemoveNodeLabel(ctx, w.clientset, node.Name, common.CalicoWindowsUpgradeLabel); err != nil {
		return fmt.Errorf("Unable to remove label from node: %w", err)
	}

	w.statusManager.RemoveWindowsNodeUpgrade(node.Name)
	return nil
}

// Start begins running the calicoWindowsUpgrader.
func (w *calicoWindowsUpgrader) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(w.syncPeriod)
		defer ticker.Stop()
		for {
			select {
			case install := <-w.installChan:
				w.install = install
			case <-ticker.C:
				w.updateWindowsNodes()
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
