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
	"sort"
	"strings"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"

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
	clientset         kubernetes.Interface
	client            client.Client
	statusManager     status.StatusManager
	nodeIndexInformer cache.SharedIndexInformer
	syncPeriod        time.Duration
	installChan       chan *operatorv1.InstallationSpec
	install           *operatorv1.InstallationSpec
}

type calicoWindowsUpgraderOption func(*calicoWindowsUpgrader)

// calicoWindowsUpgraderSyncPeriod sets the sync period for the
// calicoWindowsUpgrader.
func CalicoWindowsUpgraderSyncPeriod(syncPeriod time.Duration) calicoWindowsUpgraderOption {
	return func(w *calicoWindowsUpgrader) {
		w.syncPeriod = syncPeriod
	}
}

// NewCalicoWindowsUpgrader creates a Calico Windows upgrader.
func NewCalicoWindowsUpgrader(cs kubernetes.Interface, c client.Client, indexInformer cache.SharedIndexInformer, statusManager status.StatusManager, options ...calicoWindowsUpgraderOption) CalicoWindowsUpgrader {
	w := &calicoWindowsUpgrader{
		clientset:         cs,
		client:            c,
		statusManager:     statusManager,
		nodeIndexInformer: indexInformer,
		syncPeriod:        10 * time.Second,
		installChan:       make(chan *operatorv1.InstallationSpec, 100),
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
// - inProgress: Node does not have the expected variant and/or version. It has the upgrade in-progress label.
// - inSync: Node has the expected variant and version. It does not have the upgrade in-progress label.
// This returns an error (if any) and maps of the nodes that are pending,
// inProgress, or inSync.
func (w *calicoWindowsUpgrader) getNodeUpgradeStatus() (map[string]*corev1.Node, map[string]*corev1.Node, map[string]*corev1.Node, error) {
	pending := make(map[string]*corev1.Node)
	inSync := make(map[string]*corev1.Node)
	inProgress := make(map[string]*corev1.Node)
	expectedVersion := w.getExpectedVersion()

	for _, obj := range w.nodeIndexInformer.GetIndexer().List() {
		node, ok := obj.(*corev1.Node)
		if !ok {
			return nil, nil, nil, fmt.Errorf("Never expected index to have anything other than a Node object: %v", obj)
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
			return nil, nil, nil, fmt.Errorf("Node %v does not have the version annotation, it might be unhealthy or it might be running an unsupported Calico version.", node.Name)
		}

		if node.Labels[common.CalicoWindowsUpgradeLabel] == common.CalicoWindowsUpgradeLabelInProgress {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v has the upgrade in-progress label", node.Name))
			inProgress[node.Name] = node
		} else if variant != w.install.Variant || version != expectedVersion {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v doesn't have the latest variant and/or version. variant=%v, expectedVariant=%v, version=%v, expectedVersion=%v", node.Name, variant, w.install.Variant, version, expectedVersion))
			pending[node.Name] = node
		} else {
			windowsLog.V(1).Info(fmt.Sprintf("Node %v has the latest variant and version", node.Name))
			inSync[node.Name] = node
		}
	}

	windowsLog.V(1).Info(fmt.Sprintf("pending=%v, in-progress=%v, in-sync=%v", len(pending), len(inProgress), len(inSync)))
	return pending, inProgress, inSync, nil
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

func sortedSliceFromMap(m map[string]*corev1.Node) []string {
	nodeNames := make([]string, 0, len(m))
	// Copy map keys to slice and sort.
	for nodeName, _ := range m {
		nodeNames = append(nodeNames, nodeName)
	}
	sort.Strings(nodeNames)
	return nodeNames
}

func (w *calicoWindowsUpgrader) updateWindowsNodes() {
	// For now, do nothing if the upgrade version is Enterprise since current
	// Enterprise versions do not support the upgrade.
	// This prevents a user from accidentally triggering an
	// in-place upgrade from Calico v3.21.0 to Enterprise v3.10.x. That upgrade
	// would fail since the calico windows upgrade is will only be supported in
	// Enterprise v3.11+
	// TODO: remove this once Enterprise v3.11.0 is released.
	if w.install.Variant == operatorv1.TigeraSecureEnterprise {
		windowsLog.V(1).Info("Enterprise upgrades for Windows are not currently supported, skipping remainder of sync")
		return
	}

	pending, inProgress, inSync, err := w.getNodeUpgradeStatus()
	if err != nil {
		// TODO: handle reporting status
		windowsLog.Error(err, "Failed to get Windows nodes upgrade status")
		return
	}

	for _, nodeName := range sortedSliceFromMap(inProgress) {
		node := inProgress[nodeName]

		if w.upgradeCompleted(node) {
			if err := w.finishUpgrade(context.Background(), node); err != nil {
				// Log the error and continue. We will retry when we update nodes again.
				windowsLog.Info(fmt.Sprintf("Could not complete upgrade on node %v: %v", node.Name, err))
				continue
			}
			// Successfully finished completing the upgrade. Moving the node
			// from in-progress to in-sync.
			inSync[node.Name] = node
			delete(inProgress, node.Name)
		}
	}

	// Get the total # of windows nodes we can have upgrading using the
	// maxUnavailable value, if the node upgrade strategy was respected.
	numWindowsNodes := len(pending) + len(inProgress) + len(inSync)
	maxUnavailable, err := intstr.GetValueFromIntOrPercent(w.install.NodeUpdateStrategy.RollingUpdate.MaxUnavailable, numWindowsNodes, false)
	if err != nil {
		windowsLog.Error(err, "Invalid maxUnavailable value, falling back to default of 1")
		maxUnavailable = defaultMaxUnavailable
	}

	for _, nodeName := range sortedSliceFromMap(pending) {
		node := pending[nodeName]

		// For upgrades from Calico -> Enterprise, we always upgrade regardless
		// of maxUnavailable. For other upgrades, check that we have room
		// available.
		if w.isUpgradeFromCalicoToEnterprise(node) || len(inProgress) < maxUnavailable {
			if err := w.startUpgrade(context.Background(), node); err != nil {
				// Log the error and continue. We will retry when we update nodes again.
				windowsLog.Info(fmt.Sprintf("Could not start upgrade on node %v: %v", node.Name, err))
				continue
			}
			// Successfully started the upgrade. Moving the node
			// from pending to in-progress.
			inProgress[node.Name] = node
			delete(pending, node.Name)
		}
	}

	// Notify status manager of upgrades status.
	w.statusManager.SetWindowsUpgradeStatus(sortedSliceFromMap(pending), sortedSliceFromMap(inProgress), sortedSliceFromMap(inSync))
}

func (w *calicoWindowsUpgrader) startUpgrade(ctx context.Context, node *corev1.Node) error {
	windowsLog.Info(fmt.Sprintf("Starting Calico Windows upgrade on node %v", node.Name))
	if err := patchNodeToStartUpgrade(ctx, w.clientset, node.Name); err != nil {
		return fmt.Errorf("Unable to patch node %v to start upgrade: %w", node.Name, err)
	}

	return nil
}

func (w *calicoWindowsUpgrader) finishUpgrade(ctx context.Context, node *corev1.Node) error {
	windowsLog.Info(fmt.Sprintf("Completing upgrade on upgraded node %v", node.Name))
	if err := patchNodeToCompleteUpgrade(ctx, w.clientset, node.Name); err != nil {
		return fmt.Errorf("Unable to patch node %v to complete upgrade: %w", node.Name, err)
	}

	return nil
}

// Start begins running the calicoWindowsUpgrader.
func (w *calicoWindowsUpgrader) Start(ctx context.Context) {
	go func() {
		for !w.nodeIndexInformer.HasSynced() {
			time.Sleep(100 * time.Millisecond)
		}
		// Wait for initial config before starting main loop.
		w.install = <-w.installChan

		ticker := time.NewTicker(w.syncPeriod)
		defer ticker.Stop()
		windowsLog.Info("Starting main loop")
		for {
			select {
			case install := <-w.installChan:
				w.install = install
			case <-ticker.C:
				w.updateWindowsNodes()
			case <-ctx.Done():
				windowsLog.Info("Stopping main loop")
				return
			}
		}
	}()
}

// patchNodeToStartUpgrade patches a Windows node to prepare it for the calico
// windows upgrade. It applies a NoSchedule taint and adds the upgrade label.
func patchNodeToStartUpgrade(ctx context.Context, client kubernetes.Interface, nodeName string) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		var taintExists bool
		var upgradeLabelExists bool

		// Check if the taint exists.
		for _, t := range node.Spec.Taints {
			if t.MatchTaint(common.CalicoWindowsUpgradingTaint) {
				taintExists = true
				break
			}
		}

		// Check if the upgrade label exists.
		if curr, ok := node.Labels[common.CalicoWindowsUpgradeLabel]; ok && curr == common.CalicoWindowsUpgradeLabelInProgress {
			upgradeLabelExists = true
		}

		// If either the taint or label are missing, patch the node.
		if !taintExists || !upgradeLabelExists {
			windowsLog.V(1).Info(fmt.Sprintf("Taint or upgrade label missing for node %v. taintExists: %v, labelExists: %v", nodeName, taintExists, upgradeLabelExists))
			newTaints := node.DeepCopy().Spec.Taints
			newTaints = append(newTaints, *common.CalicoWindowsUpgradingTaint)

			// With JSONPatch '/' must be escaped as '~1' http://jsonpatch.com/
			labelKey := strings.Replace(common.CalicoWindowsUpgradeLabel, "/", "~1", -1)

			p := []objPatch{
				{
					Op:    "add",
					Path:  fmt.Sprintf("/metadata/labels/%s", labelKey),
					Value: common.CalicoWindowsUpgradeLabelInProgress,
				},
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

// patchNodeToCompleteUpgrade patches a Windows node to remove the taint and
// upgrade label added before upgrading the node. The taint and label should be
// removed when the node has finished upgrading.
func patchNodeToCompleteUpgrade(ctx context.Context, client kubernetes.Interface, nodeName string) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		var taintExists bool
		var upgradeLabelExists bool
		var taintIndex int

		// Check if the taint exists. Keep the taint's index for the patch.
		for i, t := range node.Spec.Taints {
			if t.MatchTaint(common.CalicoWindowsUpgradingTaint) {
				taintIndex = i
				taintExists = true
				break
			}
		}

		// Check if the label exists.
		if curr, ok := node.Labels[common.CalicoWindowsUpgradeLabel]; ok && curr == common.CalicoWindowsUpgradeLabelInProgress {
			upgradeLabelExists = true
		}

		// If either the taint or label exist, patch the node to remove them.
		if taintExists || upgradeLabelExists {
			windowsLog.V(1).Info(fmt.Sprintf("Taint or upgrade label exists for node %v. taintExists: %v, labelExists: %v", nodeName, taintExists, upgradeLabelExists))
			// With JSONPatch '/' must be escaped as '~1' http://jsonpatch.com/
			labelKey := strings.Replace(common.CalicoWindowsUpgradeLabel, "/", "~1", -1)

			p := []objPatch{
				// Remove the upgrade label.
				{
					Op:   "remove",
					Path: fmt.Sprintf("/metadata/labels/%s", labelKey),
				},
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

			err = patchNode(ctx, client, nodeName, p...)

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

type objPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func patchNode(ctx context.Context, client kubernetes.Interface, nodeName string, jsonStringPatches ...objPatch) error {
	patchBytes, err := json.Marshal(jsonStringPatches)
	if err != nil {
		return err
	}

	_, err = client.CoreV1().Nodes().Patch(ctx, nodeName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
	return err
}
