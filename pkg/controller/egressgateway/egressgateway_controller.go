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

package egressgateway

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/egressgateway"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("controller_egressgateway")

// Add creates a new EgressGateway Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	var licenseAPIReady = &utils.ReadyFlag{}

	reconciler := newReconciler(mgr, opts, licenseAPIReady)

	c, err := controller.New("egressgateway-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(c, k8sClient, log, licenseAPIReady)

	return add(mgr, c)
}

// newReconciler returns a new *reconcile.Reconciler.
func newReconciler(mgr manager.Manager, opts options.AddOptions, licenseAPIReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileEgressGateway{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "egressgateway", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup.
func add(mgr manager.Manager, c controller.Controller) error {
	var err error

	// Watch for changes to primary resource applicationlayer.
	err = c.Watch(&source.Kind{Type: &operatorv1.EgressGateway{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("egressgateway-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("egressgateway-controller failed to watch Tigera network resource: %v", err)
	}
	return nil
}

// Blank assignment to verify that ReconcileEgressGateway implements reconcile.Reconciler.
var _ reconcile.Reconciler = &ReconcileEgressGateway{}

// ReconcileEgressGatewayLayer reconciles a EgressGatewayLayer object.
type ReconcileEgressGateway struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	licenseAPIReady *utils.ReadyFlag
}

// Reconcile reads that state of the cluster for an EgressGateway object and makes changes
// based on the state read and what is in the EgressGateway.Spec.
func (r *ReconcileEgressGateway) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling EgressGateway")

	if request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	egw, err := getEgressGateway(ctx, r.client, request.Namespace, request.Name)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("EgressGateway object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "Error querying for Egress Gateway")
		r.status.SetDegraded("Error querying for Egress Gateway", err.Error())
		return reconcile.Result{}, err
	}
	variant, installation, err := utils.GetInstallation(ctx, r.client)

	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "Installation not found")
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "Error querying installation")
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	if variant != operatorv1.TigeraSecureEnterprise {
		reqLogger.Error(err, fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise))
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)

	if err != nil {
		reqLogger.Error(err, "Error retrieving pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	config := &egressgateway.Config{
		PullSecrets:  pullSecrets,
		Installation: installation,
		OsType:       rmeta.OSTypeLinux,
		EgressGW:     egw,
	}
	component := egressgateway.EgressGateway(config)
	ch := utils.NewComponentHandler(log, r.client, r.scheme, egw)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err = ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		reqLogger.Error(err, "Error creating / updating resource")
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future, hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	egw.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, egw); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

// getEgressGateway returns the namespaced EgressGateway instance.
func getEgressGateway(ctx context.Context, cli client.Client, nameSpace, name string) (*operatorv1.EgressGateway, error) {
	instance := &operatorv1.EgressGateway{}
	key := types.NamespacedName{Name: name, Namespace: nameSpace}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}
