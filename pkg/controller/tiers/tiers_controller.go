// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package tiers

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/tiers"
	"k8s.io/apimachinery/pkg/types"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// The Tiers controller reconciles system tiers and network policies using the v3 API. v3 resources require the API server to be available.
// System tiers are reconciled here instead of the installation controller since the API server is not available until after installation completes.
// Similarly, policies for installation and API server controllers are reconciled here to ensure the API server is available when they are reconciled.

var log = logf.Log.WithName("controller_tiers")

// Add creates a new Tiers Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}

	tierWatchReady := &utils.ReadyFlag{}
	policyWatchesReady := &utils.ReadyFlag{}

	reconciler := newReconciler(mgr, opts, tierWatchReady, policyWatchesReady)

	c, err := controller.New("tiers-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, tierWatchReady)

	policyNames := []types.NamespacedName{
		{Name: tiers.APIServerPolicyName, Namespace: rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise)},
		{Name: tiers.KubeControllerPolicyName, Namespace: common.CalicoNamespace},
		{Name: tiers.PacketCapturePolicyName, Namespace: render.PacketCaptureNamespace},
	}
	if opts.DetectedProvider == operatorv1.ProviderOpenShift {
		policyNames = append(policyNames, types.NamespacedName{Name: tiers.ClusterDNSPolicyName, Namespace: "openshift-dns"})
	} else {
		policyNames = append(policyNames, types.NamespacedName{Name: tiers.ClusterDNSPolicyName, Namespace: "kube-system"})
	}
	go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, policyWatchesReady, policyNames)

	return add(mgr, c)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions, tierWatchReady *utils.ReadyFlag, policyWatchesReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileTiers{
		Client:             mgr.GetClient(),
		scheme:             mgr.GetScheme(),
		provider:           opts.DetectedProvider,
		status:             status.New(mgr.GetClient(), "tiers", opts.KubernetesVersion),
		tierWatchReady:     tierWatchReady,
		policyWatchesReady: policyWatchesReady,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup.
func add(mgr manager.Manager, c controller.Controller) error {
	return nil
}

var _ reconcile.Reconciler = &ReconcileTiers{}

type ReconcileTiers struct {
	client.Client
	scheme             *runtime.Scheme
	provider           operatorv1.Provider
	status             status.StatusManager
	tierWatchReady     *utils.ReadyFlag
	policyWatchesReady *utils.ReadyFlag
}

func (r *ReconcileTiers) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Tiers")

	if !utils.IsAPIServerReady(r.Client, reqLogger) {
		r.status.SetDegraded("Waiting for Tigera API server to be ready", "")
		return reconcile.Result{}, nil
	}

	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded("Waiting for Tier watch to be established", "")
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	if !r.policyWatchesReady.IsReady() {
		r.status.SetDegraded("Waiting for NetworkPolicy watches to be established", "")
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.Client)
	if err != nil {
		log.Error(err, "Failed to read ManagementClusterConnection")
		r.status.SetDegraded("Failed to read ManagementClusterConnection", err.Error())
		return reconcile.Result{}, err
	}

	component := tiers.Tiers(&tiers.Config{
		Openshift:      r.provider == operatorv1.ProviderOpenShift,
		ManagedCluster: managementClusterConnection != nil,
	})

	componentHandler := utils.NewComponentHandler(log, r.Client, r.scheme, nil)
	err = componentHandler.CreateOrUpdateOrDelete(ctx, component, nil)
	if err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
