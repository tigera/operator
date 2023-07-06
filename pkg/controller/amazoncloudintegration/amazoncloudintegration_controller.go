// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
)

const ResourceName = "amazon-cloud-integration"

var log = logf.Log.WithName("controller_amazoncloudintegration")

// Add creates a new AmazonCloudIntegration Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.AmazonCRDExists {
		// No need to start this controller.
		return nil
	}
	return add(mgr, newReconciler(mgr, opts))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) reconcile.Reconciler {
	r := &ReconcileAmazonCloudIntegration{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		provider:      opts.DetectedProvider,
		status:        status.New(mgr.GetClient(), "amazon-cloud-integration", opts.KubernetesVersion),
		clusterDomain: opts.ClusterDomain,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("amazoncloudintegration-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create amazoncloudintegration-controller: %v", err)
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

	if err = utils.AddSecretsWatch(c, render.AmazonCloudIntegrationCredentialName, common.OperatorNamespace()); err != nil {
		log.V(5).Info("amazoncloudintegration-controller failed to watch Secret", "err", err, "resource", render.AmazonCloudIntegrationCredentialName)
		return fmt.Errorf("amazoncloudintegration-controller failed to watch the Secret resource(%s): %v", render.AmazonCloudIntegrationCredentialName, err)
	}

	err = imageset.AddImageSetWatch(c)
	if err != nil {
		return fmt.Errorf("amazoncloudintegration-controller failed to watch ImageSet: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("amazoncloudintegration-controller failed to watch amazon-cloud-integration Tigerastatus: %w", err)
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
	client        client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
}

// Reconcile reads that state of the cluster for a AmazonCloudIntegration object and makes changes based on the state read
// and what is in the AmazonCloudIntegration.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAmazonCloudIntegration) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AmazonCloudIntegration")

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
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying AmazonCloudIntegration", err, reqLogger)
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating AmazonCloudIntegration status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create amazoncloudintegration status conditions.")
			return reconcile.Result{}, err
		}
	}

	reqLogger.V(2).Info("Loaded config", "config", instance)
	preDefaultPatchFrom := client.MergeFrom(instance.DeepCopy())

	// Validate the configuration.
	if err = validateCustomResource(instance); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid AmazonCloudIntegration provided", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
	// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
	if err = r.client.Patch(ctx, instance, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourcePatchError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Query for the installation object.
	variant, network, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}
	if variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "", fmt.Errorf("waiting for network to be %s", operatorv1.TigeraSecureEnterprise), reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	awsCredential, err := getAmazonCredential(r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read Amazon credential secret", err, reqLogger)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, network, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	// cloud controllers need to trust a public CA, so we mount all the system certificates.
	trustedBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates()
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create tigera-ca-bundle configmap", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	reqLogger.V(3).Info("rendering components")
	amazonCloudIntegrationCfg := &render.AmazonCloudIntegrationConfiguration{
		AmazonCloudIntegration: instance,
		Installation:           network,
		Credentials:            awsCredential,
		PullSecrets:            pullSecrets,
		TrustedBundle:          trustedBundle,
	}
	component := render.AmazonCloudIntegration(amazonCloudIntegrationCfg)

	err = imageset.ApplyImageSet(ctx, r.client, variant, component)
	if err != nil {
		r.status.SetDegraded(operatorv1.ImageSetError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err := handler.CreateOrUpdateOrDelete(context.Background(), component, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
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

func getAmazonCredential(client client.Client) (*render.AmazonCredential, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      render.AmazonCloudIntegrationCredentialName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), secretNamespacedName, secret); err != nil {
		return nil, fmt.Errorf("failed to read secret %q: %s", render.AmazonCloudIntegrationCredentialName, err)
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
