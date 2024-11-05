// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package demoresource

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
)

const ResourceName string = "demoresource"

var log = logf.Log.WithName("controller_demoresource")

// Add creates a new DemoResource Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
//
// Start Watches within the Add function for any resources that this controller creates or monitors. This will trigger
// calls to Reconcile() when an instance of one of the watched resources is modified.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	r := newReconciler(mgr, opts)

	c, err := ctrlruntime.NewController("demoresource-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create demoresource-controller: %w", err)
	}

	// Watch for changes to primary resource DemoResource
	err = c.WatchObject(&operatorv1.DemoResource{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create DemoResource watch", "err", err)
		return fmt.Errorf("demoresource-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("demoresource-controller failed to watch Tigera network resource: %v", err)
	}
	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) *ReconcileDemoResource {
	r := &ReconcileDemoResource{
		client:              mgr.GetClient(),
		scheme:              mgr.GetScheme(),
		provider:            opts.DetectedProvider,
		enterpriseCRDsExist: opts.EnterpriseCRDExists,
		status:              status.New(mgr.GetClient(), "demoresource", opts.KubernetesVersion),
		clusterDomain:       opts.ClusterDomain,
		multiTenant:         opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// blank assignment to verify that ReconcileDemoResource implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileDemoResource{}

// ReconcileDemoResource reconciles a DemoResource object
type ReconcileDemoResource struct {
	client              client.Client
	scheme              *runtime.Scheme
	provider            operatorv1.Provider
	enterpriseCRDsExist bool
	status              status.StatusManager
	clusterDomain       string
	multiTenant         bool
}

// Reconcile reads that state of the cluster for a DemoResource object and makes changes based on the state read
// and what is in the DemoResource.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileDemoResource) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling DemoResource")

	// Get the DemoResource instance, and any other CRs or resources that this controller needs to know about.
	// e.g., Installation, Secrets, etc.

	// Set defaults and validate the DemoResource instance.

	// Write back the defaults to the DemoResource instance before proceeding.

	// Call through to the render package to render the necessary resources.

	// Create / update / delete the resources in the cluster.

	// Update the status of the DemoResource instance and StatusManager.
	return reconcile.Result{}, nil
}

// setDefaults sets the default values for a DemoResource instance.
func setDefaults(instance *operatorv1.DemoResource) {
}

// validateDemoResourceResource validates a DemoResource amd returns an error if it is invalid.
func validateDemoResourceResource(instance *operatorv1.DemoResource) error {
	return nil
}
