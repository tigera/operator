// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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

package gatewayapi

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
)

var log = logf.Log.WithName("controller_gatewayapi")

// Add creates a new GatewayAPI Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
//
// Start Watches within the Add function for any resources that this controller creates or monitors. This will trigger
// calls to Reconcile() when an instance of one of the watched resources is modified.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller
		return nil
	}

	r := newReconciler(mgr, opts)

	c, err := ctrlruntime.NewController("gatewayapi-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create gatewayapi-controller: %w", err)
	}

	// Watch for changes to primary resource GatewayAPI
	err = c.WatchObject(&operatorv1.GatewayAPI{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create GatewayAPI watch", "err", err)
		return fmt.Errorf("gatewayapi-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("gatewayapi-controller failed to watch Tigera network resource: %v", err)
	}
	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) *ReconcileGatewayAPI {
	r := &ReconcileGatewayAPI{
		client:              mgr.GetClient(),
		scheme:              mgr.GetScheme(),
		provider:            opts.DetectedProvider,
		enterpriseCRDsExist: opts.EnterpriseCRDExists,
		status:              status.New(mgr.GetClient(), "gatewayapi", opts.KubernetesVersion),
		clusterDomain:       opts.ClusterDomain,
		multiTenant:         opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// blank assignment to verify that ReconcileGatewayAPI implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileGatewayAPI{}

// ReconcileGatewayAPI reconciles a GatewayAPI object
type ReconcileGatewayAPI struct {
	client              client.Client
	scheme              *runtime.Scheme
	provider            operatorv1.Provider
	enterpriseCRDsExist bool
	status              status.StatusManager
	clusterDomain       string
	multiTenant         bool
}

// Reconcile reads that state of the cluster for a GatewayAPI object and makes changes based on the state read
// and what is in the GatewayAPI.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileGatewayAPI) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling GatewayAPI")

	// Get the GatewayAPI CR.
	gatewayAPI := &operatorv1.GatewayAPI{}
	err := r.client.Get(ctx, utils.DefaultTSEEInstanceKey, gatewayAPI)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("GatewayAPI object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for GatewayAPI CR", err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&gatewayAPI.ObjectMeta)

	// Get the Installation, for private registry and pull secret config.
	variant, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), nil, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Render CRDs.  For these we specify nil for the owning CR - i.e. no ownership - so that
	// the CRDs are left in place even if the GatewayAPI CR is removed again.  This is in case
	// the customer uses a second (or more) implementation of the Gateway API in addition to the
	// one that we are providing here.
	crdComponent := render.NewPassthrough(render.GatewayAPICRDs(log)...)
	handler := utils.NewComponentHandler(log, r.client, r.scheme, nil)
	if gatewayAPI.Spec.CRDManagement == nil || *gatewayAPI.Spec.CRDManagement == operatorv1.CRDManagementPreferExisting {
		handler.SetCreateOnly()
	}
	err = handler.CreateOrUpdateOrDelete(ctx, crdComponent, nil)
	if gatewayAPI.Spec.CRDManagement == nil && (err == nil || errors.IsAlreadyExists(err)) {
		// The GatewayAPI CR does not yet have a specified value for its CRDManagement
		// field, and we can now infer a reasonable value.
		if err == nil {
			// None of the CRDs previously existed, and all of them were just created by
			// us.  Therefore, in future we can consider the CRDs as Tigera
			// operator-owned, and reconcile them so as to deliver future updates.
			setting := operatorv1.CRDManagementReconcile
			gatewayAPI.Spec.CRDManagement = &setting
		} else {
			// Some (i.e. at least one) of the CRDs already existed.  Therefore we have
			// to assume that someone or something else is provisioning the CRDs in this
			// cluster, and make sure not to clobber them.
			setting := operatorv1.CRDManagementPreferExisting
			gatewayAPI.Spec.CRDManagement = &setting
		}
		// Patch that value back into the datastore.
		err = r.client.Patch(ctx, &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{
				Name: utils.DefaultTSEEInstanceKey.Name,
			},
			Spec: operatorv1.GatewayAPISpec{
				CRDManagement: gatewayAPI.Spec.CRDManagement,
			},
		}, client.MergeFrom(&operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				CRDManagement: nil,
			},
		}))
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to patch CRDManagement field", err, reqLogger)
			return reconcile.Result{}, err
		}
	}
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering GatewayAPI CRDs", err, log)
		return reconcile.Result{}, err
	}

	// Render non-CRD resources for Gateway API support, i.e. for our specific bundled
	// implementation of the Gateway API.  For these we specify the GatewayAPI CR as the owner,
	// so that they all get automatically cleaned up if the GatewayAPI CR is removed again.
	nonCRDComponent := render.GatewayAPIImplementationComponent(&render.GatewayAPIImplementationConfig{
		Installation: installation,
		PullSecrets:  pullSecrets,
		GatewayAPI:   gatewayAPI,
	})
	err = imageset.ApplyImageSet(ctx, r.client, variant, nonCRDComponent)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error with images from ImageSet", err, log)
		return reconcile.Result{}, err
	}
	err = utils.NewComponentHandler(log, r.client, r.scheme, gatewayAPI).CreateOrUpdateOrDelete(ctx, nonCRDComponent, r.status)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering GatewayAPI resources", err, log)
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	// Update the status of the GatewayAPI instance and StatusManager.
	return reconcile.Result{}, nil
}
