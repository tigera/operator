// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package ippool

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	v1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
)

const (
	reconcilePeriod = 5 * time.Minute
)

const InstallationName string = "calico"

var log = logf.Log.WithName("controller_ippool")

func Add(mgr manager.Manager, opts options.AddOptions) error {
	ri, err := newReconciler(mgr, opts)
	if err != nil {
		return fmt.Errorf("failed to create Core Reconciler: %w", err)
	}
	c, err := controller.New("tigera-ippool-controller", mgr, controller.Options{Reconciler: ri})
	if err != nil {
		return fmt.Errorf("Failed to create tigera-ippool-controller: %w", err)
	}
	return add(c, ri)
}

func newReconciler(mgr manager.Manager, opts options.AddOptions) (*Reconciler, error) {
	statusManager := status.New(mgr.GetClient(), "ip-pools", opts.KubernetesVersion)
	r := &Reconciler{
		config:               mgr.GetConfig(),
		client:               mgr.GetClient(),
		scheme:               mgr.GetScheme(),
		watches:              make(map[runtime.Object]struct{}),
		autoDetectedProvider: opts.DetectedProvider,
		status:               statusManager,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

// add adds watches for resources that are available at startup
func add(c controller.Controller, r *Reconciler) error {
	// Watch for changes to primary resource Installation
	err := c.Watch(&source.Kind{Type: &operator.Installation{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, InstallationName); err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch calico Tigerastatus: %w", err)
	}

	// Watch for changes to IPPool.
	err = c.Watch(&source.Kind{Type: &crdv1.IPPool{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch IPPool resource: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, reconcilePeriod)
	if err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	config               *rest.Config
	client               client.Client
	scheme               *runtime.Scheme
	watches              map[runtime.Object]struct{}
	autoDetectedProvider operator.Provider
	status               status.StatusManager
	clusterDomain        string
}

// Reconcile reconciles IP pools in the cluster.
//
// - Query desired IP pools (from Installation)
// - Query existing IP pools owned by this controller
// - Reconcile the differences
// - Populate Installation status with ALL IP pools in the cluster.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling IP pools")

	// TODO: Needed?
	// newActiveCM, err := r.checkActive(reqLogger)
	// if err != nil {
	// 	return reconcile.Result{}, err
	// }

	// Get the Installation object - this is the source of truth for IP pools managed by
	// this controller.
	instance := &operator.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}

	// Mark CR found so we can report converter problems via tigerastatus
	r.status.OnCRFound()

	// Get the APIServer. If healthy, we'll use it for managing pools.
	// Otherwise, we'll use the CRD API for bootstrapping the cluster until the API server is available.
	apiserver, _, err := utils.GetAPIServer(ctx, r.client)
	if err != nil && !apierrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	apiAvailable := apiserver != nil && apiserver.Status.State == v1.TigeraStatusReady

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Get all IP pools in the cluster.
	currentPools := &crdv1.IPPoolList{}
	err = r.client.List(ctx, currentPools)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operator.ResourceReadError, "error querying IP pools", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a lookup map of pools owned by this controller for easy access.
	// This controller will ignore any IP pools that it itself did not create.
	ourPools := map[string]crdv1.IPPool{}
	for _, p := range currentPools.Items {
		// TODO: Check if owned by this installation resource / controller.
		ourPools[p.Spec.CIDR] = p
	}

	// For each pool that is desired, but doesn't exist, create it.
	toCreate := []client.Object{}
	for _, p := range instance.Spec.CalicoNetwork.IPPools {
		if pool, ok := ourPools[p.CIDR]; !ok || !reflect.DeepEqual(pool, p) {
			// Create a new pool, or update an existing one.
			res := p.ToCRD()
			if apiAvailable {
				toCreate = append(toCreate, crdToV3(res))
			} else {
				toCreate = append(toCreate, res)
			}
		}
	}

	// Check existing pools owned by this controller that are no longer in
	// the Installation resource.
	toDelete := []client.Object{}
	for cidr, pool := range ourPools {
		reqLogger.WithValues("cidr", cidr).Info("Checking if pool is still valid")
		found := false
		for _, p := range instance.Spec.CalicoNetwork.IPPools {
			if p.CIDR == cidr {
				found = true
				break
			}
		}
		if !found {
			reqLogger.WithValues("cidr", cidr).Info("Pool needs to be deleted")
			if apiAvailable {
				// No match. Needs delete. We only ever send deletes via the API server,
				// since deletion requires rather complex logic. If the API server isn't available,
				// we'll instead just mark the pool as disabled temporarily.
				toDelete = append(toDelete, crdToV3(&pool))
			} else {
				// API server is not available. Just mark the pool as disabled so that new allocations
				// don't come from this pool. We'll delete it once the API server is available.
				pool.Spec.Disabled = true
				toCreate = append(toCreate, &pool)
			}
		}
	}

	// Update pools in the cluster.
	// TODO: This is bypassing a lot of validaiton! For example:
	// - Verify that the pool doesn't overlap with an existing pool.
	// - Verify that the block size hasn't changed.
	// - Verify that the pool doesn't overlap with existing IPAM blocks.
	// We should add this validation to productize this. Ideally, we'd go through the API server (and maybe we should at steady-state).
	// We only need to use the crd.projectcalico.org API for bootstrapping.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	passThru := render.NewPassthrough(toCreate...)
	if err := handler.CreateOrUpdateOrDelete(ctx, passThru, nil); err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Error creating / updating IPPools", err, log)
		return reconcile.Result{}, err
	}
	delPassThru := render.NewDeletionPassthrough(toDelete...)
	if err := handler.CreateOrUpdateOrDelete(ctx, delPassThru, nil); err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Error deleting / updating IPPools", err, log)
		return reconcile.Result{}, err
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Update status to include the full set of IP pools. This tells the core controller
	// that it's good to start installing Calico.
	// TODO: Re-query so we have the ones we just created!
	instance.Status.IPPools = crdsToOperator(currentPools.Items)
	if err := r.client.Status().Update(ctx, instance); err != nil {
		r.status.SetDegraded(v1.ResourceUpdateError, fmt.Sprintf("Error updating Installation status %s", v1.TigeraStatusReady), err, reqLogger)
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func crdsToOperator(crds []crdv1.IPPool) []v1.IPPool {
	pools := []v1.IPPool{}
	for _, p := range crds {
		pools = append(pools, crdToOperator(p))
	}
	return pools
}

func crdToOperator(crd crdv1.IPPool) v1.IPPool {
	pool := v1.IPPool{
		CIDR: crd.Spec.CIDR,
	}

	// Set encap.
	switch crd.Spec.IPIPMode {
	case crdv1.IPIPModeAlways:
		pool.Encapsulation = v1.EncapsulationIPIP
	case crdv1.IPIPModeCrossSubnet:
		pool.Encapsulation = v1.EncapsulationIPIPCrossSubnet
	}
	switch crd.Spec.VXLANMode {
	case crdv1.VXLANModeAlways:
		pool.Encapsulation = v1.EncapsulationVXLAN
	case crdv1.VXLANModeCrossSubnet:
		pool.Encapsulation = v1.EncapsulationVXLANCrossSubnet
	}

	// Set NAT
	if crd.Spec.NATOutgoing {
		pool.NATOutgoing = v1.NATOutgoingEnabled
	}

	// Set BlockSize
	blockSize := int32(crd.Spec.BlockSize)
	pool.BlockSize = &blockSize

	// Set selector.
	pool.NodeSelector = crd.Spec.NodeSelector

	// Set BGP export.
	if crd.Spec.DisableBGPExport {
		t := true
		pool.DisableBGPExport = &t
	}

	return pool
}

func crdToV3(crd *crdv1.IPPool) *v3.IPPool {
	bs, err := json.Marshal(crd)
	if err != nil {
		panic(err)
	}

	v3p := v3.IPPool{}
	err = json.Unmarshal(bs, &v3p)
	if err != nil {
		panic(err)
	}
	return &v3p
}
