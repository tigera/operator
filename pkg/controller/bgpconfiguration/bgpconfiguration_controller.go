// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package bgpconfiguration

import (
	"context"
	"fmt"
	v1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var log = logf.Log.WithName("controller_bgpconfiguration")

// Add creates a new AmazonCloudIntegration Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	return add(mgr, newReconciler(mgr, opts))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) reconcile.Reconciler {
	r := &ReconcileBgpConfiguration{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: opts.DetectedProvider,
		status:   status.New(mgr.GetClient(), "bgp-configuration", opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("bgpconfiguration-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create bgpconfiguration-controller: %v", err)
	}

	// Watch for changes to primary resource BGPConfiguration
	err = c.Watch(&source.Kind{Type: &v1.BGPConfiguration{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create BGPConfiguration watch", "err", err)
		return fmt.Errorf("bgpconfiguration-controller failed to watch primary resource: %v", err)
	}

	log.V(5).Info("Controller created and Watches setup")
	return nil
}

// blank assignment to verify that ReconcileAmazonCloudIntegration implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileBgpConfiguration{}

// ReconcileAmazonCloudIntegration reconciles a AmazonCloudIntegration object
type ReconcileBgpConfiguration struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	provider operatorv1.Provider
	status   status.StatusManager
}

// Reconcile reads that state of the cluster for a AmazonCloudIntegration object and makes changes based on the state read
// and what is in the AmazonCloudIntegration.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileBgpConfiguration) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling BgpConfiguration")


	return reconcile.Result{}, nil
}


