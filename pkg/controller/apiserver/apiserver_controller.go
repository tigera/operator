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

package apiserver

import (
	"context"
	"fmt"
	"time"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
)

var log = logf.Log.WithName("controller_apiserver")

// Add creates a new APIServer Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	return add(mgr, newReconciler(mgr, opts.DetectedProvider, opts.AmazonCRDExists, opts.ClusterDomain))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operatorv1.Provider, amazonCRDExists bool, clusterDomain string) *ReconcileAPIServer {
	r := &ReconcileAPIServer{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        provider,
		amazonCRDExists: amazonCRDExists,
		status:          status.New(mgr.GetClient(), "apiserver"),
		clusterDomain:   clusterDomain,
	}
	r.status.Run()
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r *ReconcileAPIServer) error {
	// Create a new controller
	c, err := controller.New("apiserver-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create apiserver-controller: %v", err)
	}

	// Watch for changes to primary resource APIServer
	err = c.Watch(&source.Kind{Type: &operatorv1.APIServer{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create APIServer watch", "err", err)
		return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("apiserver-controller failed to watch Tigera network resource: %v", err)
	}

	if err = utils.AddSecretsWatch(c, render.APIServerTLSSecretName, rmeta.OperatorNamespace()); err != nil {
		return fmt.Errorf("apiserver-controller failed to watch the Secret resource: %v", err)
	}

	if err = utils.AddConfigMapWatch(c, render.K8sSvcEndpointConfigMapName, rmeta.OperatorNamespace()); err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch ConfigMap %s: %w", render.K8sSvcEndpointConfigMapName, err)
	}

	for _, namespace := range []string{rmeta.OperatorNamespace(), render.APIServerNamespace} {
		if err = utils.AddSecretsWatch(c, render.VoltronTunnelSecretName, namespace); err != nil {
			return fmt.Errorf("apiserver-controller failed to watch the Secret resource: %v", err)
		}
	}

	if r.amazonCRDExists {
		err = c.Watch(&source.Kind{Type: &operatorv1.AmazonCloudIntegration{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			log.V(5).Info("Failed to create AmazonCloudIntegration watch", "err", err)
			return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
		}
	}

	// Watch for changes to primary resource ManagementCluster
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("apiserver-controller failed to watch ImageSet: %w", err)
	}

	log.V(5).Info("Controller created and Watches setup")
	return nil
}

// blank assignment to verify that ReconcileAPIServer implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAPIServer{}

// ReconcileAPIServer reconciles a APIServer object
type ReconcileAPIServer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	amazonCRDExists bool
	status          status.StatusManager
	clusterDomain   string
}

// Reconcile reads that state of the cluster for a APIServer object and makes changes based on the state read
// and what is in the APIServer.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAPIServer) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling APIServer")

	// Fetch the APIServer instance
	instance := &operatorv1.APIServer{}
	err := r.client.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(5).Info("APIServer CR not found", "err", err)
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.V(5).Info("failed to get APIServer CR", "err", err)
		r.status.SetDegraded("Error querying APIServer", err.Error())
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// Query for the installation object.
	variant, network, err := installation.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}
	if variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	}

	var tlsSecret *v1.Secret
	if network.CertificateManagement == nil {
		// Check that if the apiserver cert pair secret exists that it is valid (has key and cert fields)
		// If it does not exist then this function still returns true
		tlsSecret, err = utils.ValidateCertPair(r.client,
			rmeta.OperatorNamespace(),
			render.APIServerTLSSecretName,
			render.APIServerSecretKeyName,
			render.APIServerSecretCertName,
		)
		if err != nil {
			log.Error(err, "Invalid TLS Cert")
			r.status.SetDegraded("Error validating TLS certificate", err.Error())
			return reconcile.Result{}, err
		}
		r.status.RemoveCertificateSigningRequests(render.APIServerNamespace)
	} else {
		// Monitor pending CSRs for the TigeraStatus
		r.status.AddCertificateSigningRequests(render.APIServerNamespace, map[string]string{
			"k8s-app": render.APIServerNamespace,
		})
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		log.Error(err, "Error reading ManagementCluster")
		r.status.SetDegraded("Error reading ManagementCluster", err.Error())
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		log.Error(err, "Error reading ManagementClusterConnection")
		r.status.SetDegraded("Error reading ManagementClusterConnection", err.Error())
		return reconcile.Result{}, err
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		log.Error(err, "")
		r.status.SetDegraded(err.Error(), "")
		return reconcile.Result{}, err
	}

	var tunnelCASecret *v1.Secret
	if managementCluster != nil {
		tunnelCASecret, err = utils.ValidateCertPair(r.client,
			rmeta.OperatorNamespace(),
			render.VoltronTunnelSecretName,
			render.VoltronTunnelSecretKeyName,
			render.VoltronTunnelSecretCertName,
		)
		if err != nil {
			log.Error(err, "Invalid TLS Cert")
			r.status.SetDegraded("Error validating TLS certificate", err.Error())
			return reconcile.Result{}, err
		}
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		log.Error(err, "Error retrieving Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	var amazon *operatorv1.AmazonCloudIntegration
	if r.amazonCRDExists {
		amazon, err = utils.GetAmazonCloudIntegration(ctx, r.client)
		if errors.IsNotFound(err) {
			amazon = nil
		} else if err != nil {
			log.Error(err, "Error reading AmazonCloudIntegration")
			r.status.SetDegraded("Error reading AmazonCloudIntegration", err.Error())
			return reconcile.Result{}, err
		}
	}

	k8sEndpoint, err := utils.GetK8sServiceEndPoint(r.client)
	if err != nil {
		log.Error(err, "Error reading services endpoint configmap")
		r.status.SetDegraded("Error reading services endpoint configmap", err.Error())
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	reqLogger.V(3).Info("rendering components")
	component, err := render.APIServer(*k8sEndpoint, network, managementCluster, managementClusterConnection, amazon, tlsSecret, pullSecrets, r.provider == operatorv1.ProviderOpenShift,
		tunnelCASecret, r.clusterDomain)
	if err != nil {
		log.Error(err, "Error rendering APIServer")
		r.status.SetDegraded("Error rendering APIServer", err.Error())
		return reconcile.Result{}, err
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		log.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err := handler.CreateOrUpdateOrDelete(context.Background(), component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CRD status.
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
