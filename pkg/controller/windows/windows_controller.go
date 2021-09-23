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
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"

	"github.com/tigera/operator/pkg/components"
	"golang.org/x/mod/semver"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var (
	log = logf.Log.WithName("controller_windows")

	// The Enterprise version this operator supports.
	supportedUpgradeVersion = fmt.Sprintf("Enterprise-%v", components.EnterpriseRelease)
)

// Add creates a new Windows Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	// create the reconciler
	reconciler := newReconciler(mgr, opts)

	// Create a new controller
	controller, err := controller.New("windows-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return err
	}

	return add(mgr, controller)
}

// newReconciler returns a new *reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) reconcile.Reconciler {
	r := &reconcileWindows{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		provider:      opts.DetectedProvider,
		status:        status.New(mgr.GetClient(), "windows", opts.KubernetesVersion),
		clusterDomain: opts.ClusterDomain,
	}
	r.status.Run()
	return r
}

// add adds watches for resources that are available at startup
func add(mgr manager.Manager, c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.Installation{}}, &handler.EnqueueRequestForObject{})
}

// blank assignment to verify that reconcileWindows implements reconcile.Reconciler
var _ reconcile.Reconciler = &reconcileWindows{}

// reconcileWindows reconciles windows nodes. For now, this handles Calico
// Windows upgrades.
type reconcileWindows struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client        client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
}

func (r *reconcileWindows) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Windows")

	// Get supported Windows nodes. Nodes are supported if they have a version
	// annotation.
	nodes, err := common.GetWindowsNodes(ctx, r.client, func(n *corev1.Node) bool {
		return common.GetWindowsNodeVersion(n) != ""
	})

	if err != nil {
		r.status.SetDegraded("Error querying windows nodes", err.Error())
		return reconcile.Result{}, err
	}

	nodesToUpgrade := []corev1.Node{}
	nodesUpgraded := []corev1.Node{}

	log.V(1).Info(fmt.Sprintf("Operator's supported Calico version=%v, Calico Enterprise version=%v", components.CalicoRelease, components.EnterpriseRelease))

	// Get all Windows nodes that should get the upgrade triggered.
	for _, n := range nodes {
		log.V(1).Info(fmt.Sprintf("Checking node %v", n.Name))

		// Skip the node if it's already running the supported Enterprise version.
		if common.GetWindowsNodeVersion(&n) == supportedUpgradeVersion {
			log.Info(fmt.Sprintf("Skipping upgrade of node %v, it already has the latest Enterprise version", n.Name))
			continue
		}

		// If the upgrade label exists on the node, skip it -- it's already upgrading.
		if n.Labels[common.CalicoWindowsUpgradeScriptLabel] != "" {
			log.Info(fmt.Sprintf("Skipping upgrade of node %v, upgrade has already been triggered", n.Name))
			continue
		}

		currentProduct, currentVersion, err := getInstalledCalicoVersion(&n)
		if err != nil {
			return reconcile.Result{}, err
		}

		log.Info(fmt.Sprintf("Node %v has product=%v, version=%v", n.Name, currentProduct, currentVersion))
		switch currentProduct {
		case "Calico":
			// If the node has Calico for Windows installed, we will upgrade to Enterprise version supported by
			// this operator if the current Calico version is less-than/equal to the operator's supported Calico version.
			// This prevents us from downgrading to an older Enterprise version.
			if semver.Compare(currentVersion, components.CalicoRelease) <= 0 {
				log.Info(fmt.Sprintf("Triggering upgrade of node %v, current Calico version=%v is supported by the operator's Calico version=%v", n.Name, currentVersion, components.CalicoRelease))
				nodesToUpgrade = append(nodesToUpgrade, n)
			} else {
				log.Info(fmt.Sprintf("Skipping upgrade of node %v, current Calico version=%v is not supported by the operator's Calico version=%v", n.Name, currentVersion, components.CalicoRelease))
			}

		case "Enterprise":
			// If the node has Calico Enterprise for Windows already installed,
			// we will upgrade if this operator's supported Enterprise version is newer.
			if semver.Compare(currentVersion, components.EnterpriseRelease) < 0 {
				log.Info(fmt.Sprintf("Triggering upgrade of node %v, current Enterprise version=%v is supported by the operator's Enterprise version=%v", n.Name, currentVersion, components.EnterpriseRelease))
				nodesToUpgrade = append(nodesToUpgrade, n)
			} else {
				log.Info(fmt.Sprintf("Skipping upgrade of node %v since current Enterprise version=%v is not supported by the operator's Calico version=%v", n.Name, currentVersion, components.CalicoRelease))
			}
		default:
			log.Info(fmt.Sprintf("Unexpected Calico product %v on the node %v", currentProduct, n.Name))
			return reconcile.Result{}, err
		}
	}

	// Get all Windows nodes that have already finished upgrading
	// Nodes are finished upgrading if:
	// - They have the `projectcalico.org/CalicoWindowsUpgradeScript` label
	// - They have the `projectcalico.org/CalicoVersion` annotation with the
	//   value equal to this operator's supported Enterprise version.
	for _, n := range nodes {
		// If the upgrade label exists on the node and the node's version is this
		// operator's supported Enterprise version, then the upgrade has
		// completed.
		if n.Labels[common.CalicoWindowsUpgradeScriptLabel] != "" && common.GetWindowsNodeVersion(&n) == supportedUpgradeVersion {
			log.Info(fmt.Sprintf("Node %v finished upgrading to %v", n.Name, supportedUpgradeVersion))
			nodesUpgraded = append(nodesUpgraded, n)
		}
	}

	// Remove upgrade label from nodes that are already upgraded.
	for _, n := range nodesUpgraded {
		log.Info(fmt.Sprintf("Removing upgrade label from upgraded node %v", n.Name))
		patchFrom := client.MergeFrom(n.DeepCopy())
		delete(n.Labels, common.CalicoWindowsUpgradeScriptLabel)

		if err := r.client.Patch(ctx, &n, patchFrom); err != nil {
			r.status.SetDegraded("Unable to Patch node", err.Error())
			return reconcile.Result{}, err
		}

		r.status.RemoveWindowsNodeUpgrade(n.Name)
	}

	// Add upgrade label to nodes that need to be upgraded.
	for _, n := range nodesToUpgrade {
		log.V(1).Info(fmt.Sprintf("Triggering upgrade on node %v", n.Name))
		patchFrom := client.MergeFrom(n.DeepCopy())
		n.Labels[common.CalicoWindowsUpgradeScriptLabel] = common.CalicoWindowsUpgradeScript

		if err := r.client.Patch(ctx, &n, patchFrom); err != nil {
			r.status.SetDegraded("Unable to Patch node", err.Error())
			return reconcile.Result{}, err
		}

		r.status.AddWindowsNodeUpgrade(n.Name, supportedUpgradeVersion)
	}

	// Query for the whole installation object, not just the spec. The
	// Installation cr will own the resources of this component.
	install := &operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, install); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	// Query for pull secrets in operator namespace.
	pullSecrets, err := utils.GetNetworkingPullSecrets(&install.Spec, r.client)
	if err != nil {
		log.Error(err, "Error retrieving Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, install)

	// Render the desired objects from the CRD and create or update them.
	hasSupportedNodes := len(nodes) > 0
	component, err := render.Windows(install, pullSecrets, hasSupportedNodes)
	if err != nil {
		log.Error(err, "error rendering windows upgrade")
		r.status.SetDegraded("Error rendering windows upgrade", err.Error())
		return reconcile.Result{}, err
	}

	if err = imageset.ApplyImageSet(ctx, r.client, install.Spec.Variant, component); err != nil {
		log.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err := handler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating / deleting resource", err.Error())
		return reconcile.Result{}, err
	}

	if hasSupportedNodes {
		// Clear the degraded bit if we've reached this far.
		r.status.ClearDegraded()

		r.status.OnCRFound()

		// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
		r.status.ReadyToMonitor()

	} else {
		r.status.OnCRNotFound()
	}

	return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
}

// getInstalledCalicoVersion returns the installed Calico version on the Windows
// node based on the `projectcalico.org/CalicoVersion` annotation value.
// The version annotation on each Calico for Windows node should have
// the prefix "Calico-" or "Enterprise-", followed by the actual version.
// Example values: "Calico-v3.20.0", "Enterprise-v3.9.0"
func getInstalledCalicoVersion(n *corev1.Node) (string, string, error) {
	currentVersion := common.GetWindowsNodeVersion(n)
	currentVersionParts := strings.Split(currentVersion, "-")
	if len(currentVersionParts) < 2 {
		return "", "", fmt.Errorf("Got an unexpected Calico version %v on the node %v", currentVersion, n.Name)
	}

	version := strings.Join(currentVersionParts[1:], "-")
	return currentVersionParts[0], version, nil
}
