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

package amazoncloudintegration

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var log = logf.Log.WithName("controller_amazoncloudintegration")

// Add creates a new AmazonCloudIntegration Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.AmazonCRDExists {
		// No need to start this controller.
		return nil
	}
	return add(mgr, newReconciler(mgr, opts.DetectedProvider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operatorv1.Provider) reconcile.Reconciler {
	r := &ReconcileAmazonCloudIntegration{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: provider,
		status:   status.New(mgr.GetClient(), "amazon-cloud-integration"),
	}
	r.status.Run()
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("amazoncloudintegration-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create amazoncloudintegration-controller: %v", err)
	}

	// Watch for changes to primary resource AmazonCloudIntegration
	err = c.Watch(&source.Kind{Type: &operatorv1.AmazonCloudIntegration{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create AmazonCloudIntegration watch", "err", err)
		return fmt.Errorf("amazoncloudintegration-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("amazoncloudintegration-controller failed to watch Tigera network resource: %v", err)
	}

	if err = utils.AddSecretsWatch(c, render.AmazonCloudIntegrationCredentialName, render.OperatorNamespace()); err != nil {
		log.V(5).Info("amazoncloudintegration-controller failed to watch Secret", "err", err, "resource", render.AmazonCloudIntegrationCredentialName)
		return fmt.Errorf("amazoncloudintegration-controller failed to watch the Secret resource(%s): %v", render.AmazonCloudIntegrationCredentialName, err)
	}

	log.V(5).Info("Controller created and Watches setup")
	return nil
}

// blank assignment to verify that ReconcileAmazonCloudIntegration implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAmazonCloudIntegration{}

// ReconcileAmazonCloudIntegration reconciles a AmazonCloudIntegration object
type ReconcileAmazonCloudIntegration struct {
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
func (r *ReconcileAmazonCloudIntegration) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AmazonCloudIntegration")

	ctx := context.Background()

	// Fetch the AmazonCloudIntegration instance
	instance, err := getAmazonCloudIntegration(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.V(5).Info("AmazonCloudIntegration CR not found", "err", err)
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.SetDegraded("Error querying AmazonCloudIntegration", err, reqLogger)
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// Validate the configuration.
	if err = validateCustomResource(instance); err != nil {
		r.SetDegraded("Invalid AmazonCloudIntegration provided", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
	// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
	if err = r.client.Update(ctx, instance); err != nil {
		r.SetDegraded("Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Query for the installation object.
	network, err := installation.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.SetDegraded("Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.SetDegraded("Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}
	if network.Variant != operatorv1.TigeraSecureEnterprise {
		r.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), fmt.Errorf(""), reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		r.SetDegraded("Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	awsCredential, err := getAmazonCredential(r.client)
	if err != nil {
		r.SetDegraded("Failed to read Amazon credential secret", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	reqLogger.V(3).Info("rendering components")
	component, err := render.AmazonCloudIntegration(instance, network, awsCredential, pullSecrets, r.provider == operatorv1.ProviderOpenShift)
	if err != nil {
		r.SetDegraded("Error rendering AmazonCloudIntegration", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err := handler.CreateOrUpdate(context.Background(), component, r.status); err != nil {
		r.SetDegraded("Error creating / updating resource", err, reqLogger)
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

func (r *ReconcileAmazonCloudIntegration) SetDegraded(reason string, err error, log logr.Logger) {
	log.Error(err, reason)
	r.status.SetDegraded(reason, err.Error())
}

func getAmazonCredential(client client.Client) (*render.AmazonCredential, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      render.AmazonCloudIntegrationCredentialName,
		Namespace: render.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), secretNamespacedName, secret); err != nil {
		return nil, fmt.Errorf("Failed to read secret %q: %s", render.AmazonCloudIntegrationCredentialName, err)
	}

	return render.ConvertSecretToCredential(secret)
}

func fillDefaults(aci *operatorv1.AmazonCloudIntegration) {
	if aci.Spec.DefaultPodMetadataAccess == "" {
		aci.Spec.DefaultPodMetadataAccess = operatorv1.MetadataAccessDenied
	}
}

// GetAmazonCloudIntegration returns the tigera AmazonCloudIntegration instance.
func getAmazonCloudIntegration(ctx context.Context, client client.Client) (*operatorv1.AmazonCloudIntegration, error) {
	instance, err := utils.GetAmazonCloudIntegration(ctx, client)
	if err != nil {
		return nil, err
	}

	fillDefaults(instance)

	return instance, nil
}
