// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

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
	"sync"
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

const (
	defaultMaxUnavailable int32 = 1
)

var windowsLog = logf.Log.WithName("windows_upgrader")

type CalicoWindowsUpgrader interface {
	UpdateConfig(install *operatorv1.InstallationSpec)
	Start(ctx context.Context)
	IsDegraded() bool
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
	isDegraded        bool
	lock              sync.Mutex
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

		// Don't upgrade from Calico to Calico
		if variant == w.install.Variant && variant == operatorv1.Calico {
			windowsLog.V(1).Info(fmt.Sprintf("Skipping upgrade of node %v from Calico to Calico", node.Name))
			continue
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
	// Use the component's version rather than top-level version values
	// `EnterpriseRelease` or `CalicoRelease` since for dev releases we use
	// a custom versions YAML file with an aggregate release name.
	//
	// For release versions, the windows upgrade component version will be equal
	// to the top-level version.
	if w.install.Variant == operatorv1.TigeraSecureEnterprise {
		return components.ComponentTigeraWindowsUpgrade.Version
	}
	return components.ComponentWindowsUpgrade.Version
}

func sortedSliceFromMap(m map[string]*corev1.Node) []string {
	nodeNames := make([]string, 0, len(m))
	// Copy map keys to slice and sort.
	for nodeName := range m {
		nodeNames = append(nodeNames, nodeName)
	}
	sort.Strings(nodeNames)
	return nodeNames
}

func (w *calicoWindowsUpgrader) updateWindowsNodes() {
	w.lock.Lock()
	defer w.lock.Unlock()

	pending, inProgress, inSync, err := w.getNodeUpgradeStatus()
	if err != nil {
		windowsLog.Error(err, "Failed to get Windows nodes upgrade status")
		w.isDegraded = true
		w.statusManager.SetWindowsUpgradeStatus(nil, nil, nil, err)
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

	var maxUnavailable int32 = defaultMaxUnavailable
	// Get the total # of windows nodes we can have upgrading using the
	// maxUnavailable value, if the node upgrade strategy was respected.
	numWindowsNodes := len(pending) + len(inProgress) + len(inSync)
	numNodesMaxUnavailable, err := intstr.GetValueFromIntOrPercent(w.install.NodeUpdateStrategy.RollingUpdate.MaxUnavailable, numWindowsNodes, false)
	if err != nil {
		// Due to the potential rounding down of numNodesMaxUnavailable =  (maxUnavailable %) * ksD+csD, where maxUnavailable is a percentage value,
		// it may resolve to zero. Then we should default back maxUnavailable to 1 on the theory that surge might not work due to quota.
		windowsLog.Error(err, "Invalid maxUnavailable value, falling back to default of 1")
	} else {
		if numNodesMaxUnavailable < 1 {
			windowsLog.Info("Max unavailble nodes calculation resolved to 0, defaulting back to 1 to allow upgrades to continue")
		} else {
			maxUnavailable = int32(numNodesMaxUnavailable)
		}
	}

	for _, nodeName := range sortedSliceFromMap(pending) {
		node := pending[nodeName]

		// For upgrades from Calico -> Enterprise, we always upgrade regardless
		// of maxUnavailable. For other upgrades, check that we have room
		// available.
		if w.isUpgradeFromCalicoToEnterprise(node) || int32(len(inProgress)) < maxUnavailable {
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
	w.isDegraded = false
	w.statusManager.SetWindowsUpgradeStatus(sortedSliceFromMap(pending), sortedSliceFromMap(inProgress), sortedSliceFromMap(inSync), nil)
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
				if w.install.KubernetesProvider == operatorv1.ProviderAKS {
					w.updateWindowsNodes()
				} else {
					windowsLog.V(2).Info("windows upgrader only runs on AKS, skipping update call")
				}
			case <-ctx.Done():
				windowsLog.Info("Stopping main loop")
				return
			}
		}
	}()
}

func (w *calicoWindowsUpgrader) IsDegraded() bool {
	w.lock.Lock()
	defer w.lock.Unlock()
	return w.isDegraded
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

		patches := []objPatch{}

		if !taintExists {
			windowsLog.V(1).Info(fmt.Sprintf("Taint missing for node %v", nodeName))
			newTaints := node.DeepCopy().Spec.Taints
			newTaints = append(newTaints, *common.CalicoWindowsUpgradingTaint)

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
			patches = append(patches, p...)

		}

		if !upgradeLabelExists {
			windowsLog.V(1).Info(fmt.Sprintf("Upgrade label missing for node %v", nodeName))
			// With JSONPatch '/' must be escaped as '~1' http://jsonpatch.com/
			labelKey := strings.Replace(common.CalicoWindowsUpgradeLabel, "/", "~1", -1)

			p := objPatch{
				Op:    "add",
				Path:  fmt.Sprintf("/metadata/labels/%s", labelKey),
				Value: common.CalicoWindowsUpgradeLabelInProgress,
			}
			patches = append(patches, p)
		}

		// If either the taint or label do not exist, patch the node to add them.
		if len(patches) > 0 {
			windowsLog.V(1).Info(fmt.Sprintf("Patching node %v to add upgrade taint and/or label", nodeName))

			err = patchNode(ctx, client, nodeName, patches...)

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

		patches := []objPatch{}

		if taintExists {
			windowsLog.V(1).Info(fmt.Sprintf("Upgrade taint exists for node %v", nodeName))
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
			patches = append(patches, p...)
		}

		if upgradeLabelExists {
			windowsLog.V(1).Info(fmt.Sprintf("Upgrade label exists for node %v", nodeName))
			// With JSONPatch '/' must be escaped as '~1' http://jsonpatch.com/
			labelKey := strings.Replace(common.CalicoWindowsUpgradeLabel, "/", "~1", -1)

			p := objPatch{
				// Remove the upgrade label.
				Op:   "remove",
				Path: fmt.Sprintf("/metadata/labels/%s", labelKey),
			}
			patches = append(patches, p)
		}

		// If either the taint or label exist, patch the node to remove them.
		if len(patches) > 0 {
			windowsLog.V(1).Info(fmt.Sprintf("Patching node %v to remove upgrade taint and/or label", nodeName))

			err = patchNode(ctx, client, nodeName, patches...)

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
