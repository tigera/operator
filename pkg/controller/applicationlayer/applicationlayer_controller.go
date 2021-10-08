// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package applicationlayer

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_applicationlayer")

// Add creates a new ApplicationLayer Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	var licenseAPIReady = &utils.ReadyFlag{}

	reconciler := newReconciler(mgr, opts, licenseAPIReady)

	c, err := controller.New("applicationlayer-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
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
	r := &ReconcileApplicationLayer{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "applicationlayer", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
	}
	r.status.Run()
	return r
}

// add adds watches for resources that are available at startup.
func add(mgr manager.Manager, c controller.Controller) error {
	var err error

	// Watch for changes to primary resource applicationlayer.
	err = c.Watch(&source.Kind{Type: &operatorv1.ApplicationLayer{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch ImageSet: %w", err)
	}

	// Watch configmaps created for envoy.
	for _, configMapName := range []string{applicationlayer.EnvoyConfigMapName} {
		if err = utils.AddConfigMapWatch(c, configMapName, common.CalicoNamespace); err != nil {
			return fmt.Errorf("applicationlayer-controller failed to watch ConfigMap %s: %v", configMapName, err)
		}
	}

	// Watch for changes to FelixConfiguration.
	err = c.Watch(&source.Kind{Type: &crdv1.FelixConfiguration{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch FelixConfiguration resource: %w", err)
	}

	return nil
}

// Blank assignment to verify that ReconcileCompliance implements reconcile.Reconciler.
var _ reconcile.Reconciler = &ReconcileApplicationLayer{}

// ReconcileApplicationLayer reconciles a ApplicationLayer object.
type ReconcileApplicationLayer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	licenseAPIReady *utils.ReadyFlag
}

// Reconcile reads that state of the cluster for a ApplicationLayer object and makes changes
// based on the state read and what is in the ApplicationLayer.Spec.
func (r *ReconcileApplicationLayer) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ApplicationLayer")

	applicationLayer, err := getApplicationLayer(ctx, r.client)

	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("ApplicationLayer object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "Error querying for Application Layer")
		r.status.SetDegraded("Error querying for Application Layer", err.Error())
		return reconcile.Result{}, err
	}

	preDefaultPatchFrom := client.MergeFrom(applicationLayer.DeepCopy())

	updateApplicationLayerWithDefaults(applicationLayer)

	// Validate the configuration.
	if err := validateApplicationLayer(applicationLayer); err != nil {
		reqLogger.Error(err, "Invalid applicationLayer provided")
		r.status.SetDegraded("Invalid applicationLayer provided", err.Error())
		return reconcile.Result{}, err
	}

	// Write the application layer back to the datastore, so the controllers depending on this can reconcile.
	if err = r.client.Patch(ctx, applicationLayer, preDefaultPatchFrom); err != nil {
		reqLogger.Error(err, "Failed to write defaults to applicationLayer")
		r.status.SetDegraded("Failed to write defaults to applicationLayer", err.Error())
		return reconcile.Result{}, err
	}

	variant, installation, err := utils.GetInstallation(ctx, r.client)

	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "Installation not found")
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		reqLogger.Error(err, "Error querying installation")
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)

	if err != nil {
		reqLogger.Error(err, "Error retrieving pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	lcSpec := applicationLayer.Spec.LogCollection

	// If ApplicationLayer spec exists then LogCollection should be set.
	// TODO: when we will have multiple features in future this should change to at least one feature being set
	if lcSpec == nil {
		reqLogger.Error(err, "Missing required LogCollection spec in applicationLayer")
		r.status.SetDegraded(fmt.Sprintf("Missing required LogCollection spec in applicationLayer"), "")
		return reconcile.Result{}, nil
	}

	// Patch felix configuration if necessary.
	err = r.patchFelixTproxyMode(ctx, lcSpec)

	if err != nil {
		reqLogger.Error(err, "Error patching felix configuration")
		r.status.SetDegraded("Error patching felix configuration", err.Error())
		return reconcile.Result{}, err
	}

	component := applicationlayer.ApplicationLayer(pullSecrets, installation, rmeta.OSTypeLinux,
		r.isLogsCollectionEnabled(lcSpec), lcSpec.LogIntervalSeconds, lcSpec.LogRequestsPerInterval)

	ch := utils.NewComponentHandler(log, r.client, r.scheme, applicationLayer)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	// TODO: when there are more ApplicationLayer options then it will need to be restructured, as each of the
	// different features will not have their own CreateOrUpdateOrDelete
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

	// Everything is available - update the CRD status.
	applicationLayer.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, applicationLayer); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func validateApplicationLayer(al *operatorv1.ApplicationLayer) error {
	lcSpec := al.Spec.LogCollection
	if lcSpec != nil {
		if *lcSpec.LogIntervalSeconds < 1 {
			return fmt.Errorf("log interval seconds can not be less than 1 sec")
		}
	}

	return nil
}

// updateApplicationLayerWithDefaults populates the applicationlayer with defaults.
func updateApplicationLayerWithDefaults(al *operatorv1.ApplicationLayer) {
	defaultLogIntervalSeconds := int64(5)
	defaultLogRequestsPerInterval := int64(-1)

	if al.Spec.LogCollection != nil {
		if al.Spec.LogCollection.LogRequestsPerInterval == nil {
			al.Spec.LogCollection.LogRequestsPerInterval = &defaultLogRequestsPerInterval
		}
		if al.Spec.LogCollection.LogIntervalSeconds == nil {
			al.Spec.LogCollection.LogIntervalSeconds = &defaultLogIntervalSeconds
		}
	}
}

// getApplicationLayer returns the default ApplicationLayer instance with defaults populated.
func getApplicationLayer(ctx context.Context, cli client.Client) (*operatorv1.ApplicationLayer, error) {
	instance := &operatorv1.ApplicationLayer{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (r *ReconcileApplicationLayer) isLogsCollectionEnabled(l7Spec *operatorv1.LogCollectionSpec) bool {
	return l7Spec != nil && l7Spec.CollectLogs != nil && *l7Spec.CollectLogs == operatorv1.L7LogCollectionEnabled
}

// patchFelixTproxyMode takes all application layer specs as arguments and patches felix config.
// If at least one of the specs requires TPROXYMode as "Enabled" it'll be patched as "Enabled" otherwise it is "Disabled".
func (r *ReconcileApplicationLayer) patchFelixTproxyMode(ctx context.Context, l7Spec *operatorv1.LogCollectionSpec) error {
	// Fetch any existing default FelixConfiguration object.
	fc := &crdv1.FelixConfiguration{}
	err := r.client.Get(ctx, types.NamespacedName{Name: "default"}, fc)

	if err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded("Unable to read FelixConfiguration", err.Error())
		return err
	}

	var tproxyMode crdv1.TPROXYModeOption
	patchFrom := client.MergeFrom(fc.DeepCopy())

	if r.isLogsCollectionEnabled(l7Spec) {
		tproxyMode = crdv1.TPROXYModeOptionEnabled
	} else {
		tproxyMode = crdv1.TPROXYModeOptionDisabled
	}
	// If tproxy mode is already set to desired state return nil.
	if *fc.Spec.TPROXYMode == tproxyMode {
		return nil
	}
	fc.Spec.TPROXYMode = &tproxyMode

	log.Info("Patching TPROXYMode FelixConfiguration with mode", "mode", string(tproxyMode))

	if err := r.client.Patch(ctx, fc, patchFrom); err != nil {
		return err
	}

	return nil
}
