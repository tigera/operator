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
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/client-go/kubernetes"

	"github.com/tigera/operator/pkg/common"
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

// The Tiers controller reconciles Tiers and NetworkPolicies that are shared across components or do not directly
// relate to any particular component.

var log = logf.Log.WithName("controller_tiers")

// Add creates a new Tiers Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}

	reconciler := newReconciler(mgr, opts)

	c, err := controller.New("tiers-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, nil)

	go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, []types.NamespacedName{
		{Name: tiers.ClusterDNSPolicyName, Namespace: "openshift-dns"},
		{Name: tiers.ClusterDNSPolicyName, Namespace: "kube-system"},
	})

	return add(mgr, c)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) reconcile.Reconciler {
	r := &ReconcileTiers{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: opts.DetectedProvider,
		status:   status.New(mgr.GetClient(), "tiers", opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup.
func add(mgr manager.Manager, c controller.Controller) error {
	if err := utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("tiers-controller failed to watch Tigera network resource: %v", err)
	}

	if err := utils.AddAPIServerWatch(c); err != nil {
		return fmt.Errorf("tiers-controller failed to watch APIServer resource: %v", err)
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileTiers{}

type ReconcileTiers struct {
	client             client.Client
	scheme             *runtime.Scheme
	provider           operatorv1.Provider
	status             status.StatusManager
	tierWatchReady     *utils.ReadyFlag
	policyWatchesReady *utils.ReadyFlag
}

func (r *ReconcileTiers) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Tiers")

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Ensure a license is present that enables this controller to create/manage tiers.
	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if !utils.IsFeatureActive(license, common.TiersFeature) {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: tiers", err, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	component := tiers.Tiers(&tiers.Config{Openshift: r.provider == operatorv1.ProviderOpenShift})

	componentHandler := utils.NewComponentHandler(log, r.client, r.scheme, nil)
	err = componentHandler.CreateOrUpdateOrDelete(ctx, component, nil)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
