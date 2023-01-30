// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

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
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

const ResourceName = "applicationlayer"

var log = logf.Log.WithName("controller_applicationlayer")

// Add creates a new ApplicationLayer Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	licenseAPIReady := &utils.ReadyFlag{}

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
	r.status.Run(opts.ShutdownContext)
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

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("applicationlayer-controller failed to watch Tigera network resource: %v", err)
	}

	// Watch for configmap changes in tigera-operator namespace; the cm contains ruleset for ModSecurity library:
	err = utils.AddConfigMapWatch(c, applicationlayer.ModSecurityRulesetConfigMapName, common.OperatorNamespace())
	if err != nil {
		return fmt.Errorf(
			"applicationlayer-controller failed to watch ConfigMap %s: %v",
			applicationlayer.ModSecurityRulesetConfigMapName, err,
		)
	}

	// Watch configmaps created for envoy and dikastes in calico-system namespace:
	maps := []string{
		applicationlayer.EnvoyConfigMapName,
		applicationlayer.ModSecurityRulesetConfigMapName,
	}
	for _, configMapName := range maps {
		if err = utils.AddConfigMapWatch(c, configMapName, common.CalicoNamespace); err != nil {
			return fmt.Errorf("applicationlayer-controller failed to watch ConfigMap %s: %v", configMapName, err)
		}
	}

	// Watch for changes to FelixConfiguration.
	err = c.Watch(&source.Kind{Type: &crdv1.FelixConfiguration{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch FelixConfiguration resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch applicationlayer Tigerastatus: %w", err)
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
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("ApplicationLayer object not found")
			// Patch tproxyMode if it's  needed after crd deletion.
			if err = r.patchFelixTproxyMode(ctx, nil); err != nil {
				reqLogger.Error(err, "Error patching felix configuration")
			}
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for Application Layer", err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&applicationLayer.ObjectMeta)

	// Changes for updating application layer status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		applicationLayer.Status.Conditions = status.UpdateStatusCondition(applicationLayer.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, applicationLayer); err != nil {
			log.WithValues("reason", err).Info("Failed to create ApplicationLayer status conditions.")
			return reconcile.Result{}, err
		}
	}

	preDefaultPatchFrom := client.MergeFrom(applicationLayer.DeepCopy())

	updateApplicationLayerWithDefaults(applicationLayer)

	err = validateApplicationLayer(applicationLayer)

	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, nil
	}

	// Write the application layer back to the datastore, so the controllers depending on this can reconcile.
	if err = r.client.Patch(ctx, applicationLayer, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to write defaults to applicationLayer", err, reqLogger)
		return reconcile.Result{}, err
	}

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

	if operatorv1.IsFIPSModeEnabled(installation.FIPSMode) {
		msg := errors.New("ApplicationLayer features cannot be used in combination with FIPSMode=Enabled")
		r.status.SetDegraded(operatorv1.ResourceValidationError, msg.Error(), nil, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Patch felix configuration if necessary.
	err = r.patchFelixTproxyMode(ctx, applicationLayer)

	if err != nil {
		r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching felix configuration", err, reqLogger)
		return reconcile.Result{}, err
	}

	var passthroughModSecurityRuleSet bool
	var modSecurityRuleSet *corev1.ConfigMap
	if r.isWAFEnabled(&applicationLayer.Spec) {
		if modSecurityRuleSet, passthroughModSecurityRuleSet, err = r.getModSecurityRuleSet(ctx); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Web Application Firewall ModSecurity rule set", err, reqLogger)
			return reconcile.Result{}, err
		}
		if err = validateModSecurityRuleSet(modSecurityRuleSet); err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Error validating Web Application Firewall ModSecurity rule set", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	lcSpec := applicationLayer.Spec.LogCollection
	config := &applicationlayer.Config{
		PullSecrets:            pullSecrets,
		Installation:           installation,
		OsType:                 rmeta.OSTypeLinux,
		WAFEnabled:             r.isWAFEnabled(&applicationLayer.Spec),
		LogsEnabled:            r.isLogsCollectionEnabled(lcSpec),
		LogRequestsPerInterval: lcSpec.LogRequestsPerInterval,
		LogIntervalSeconds:     lcSpec.LogIntervalSeconds,
		ModSecurityConfigMap:   modSecurityRuleSet,
	}
	component := applicationlayer.ApplicationLayer(config)

	ch := utils.NewComponentHandler(log, r.client, r.scheme, applicationLayer)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if passthroughModSecurityRuleSet {
		err = ch.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(modSecurityRuleSet), r.status)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// TODO: when there are more ApplicationLayer options then it will need to be restructured, as each of the
	// different features will not have their own CreateOrUpdateOrDelete
	if err = ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
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

// updateApplicationLayerWithDefaults populates the applicationlayer with defaults.
func updateApplicationLayerWithDefaults(al *operatorv1.ApplicationLayer) {
	var defaultLogIntervalSeconds int64 = 5
	var defaultLogRequestsPerInterval int64 = -1
	var defaultLogCollectionDisabled operatorv1.LogCollectionStatusType = operatorv1.L7LogCollectionDisabled
	var defaultWebApplicationFirewallDisabled operatorv1.WAFStatusType = operatorv1.WAFDisabled

	if al.Spec.LogCollection == nil {
		al.Spec.LogCollection = new(operatorv1.LogCollectionSpec)
	}

	if al.Spec.LogCollection.CollectLogs == nil {
		al.Spec.LogCollection.CollectLogs = &defaultLogCollectionDisabled
	}

	if *al.Spec.LogCollection.CollectLogs == operatorv1.L7LogCollectionEnabled {
		if al.Spec.LogCollection.LogRequestsPerInterval == nil {
			al.Spec.LogCollection.LogRequestsPerInterval = &defaultLogRequestsPerInterval
		}
		if al.Spec.LogCollection.LogIntervalSeconds == nil {
			al.Spec.LogCollection.LogIntervalSeconds = &defaultLogIntervalSeconds
		}
	}

	if al.Spec.WebApplicationFirewall == nil {
		al.Spec.WebApplicationFirewall = &defaultWebApplicationFirewallDisabled
	}
}

// validateApplicationLayer validates ApplicationLayer
func validateApplicationLayer(al *operatorv1.ApplicationLayer) error {
	// Just a precaution to make sure it is safe to dereference pointers below.
	// This is already taken care of in updateApplicationLayerWithDefaults.
	properlyConfigured := al.Spec.LogCollection != nil &&
		al.Spec.LogCollection.CollectLogs != nil &&
		al.Spec.WebApplicationFirewall != nil

	// If ApplicationLayer spec exists then one of its features should be set.
	if !properlyConfigured || (*al.Spec.LogCollection.CollectLogs != operatorv1.L7LogCollectionEnabled && *al.Spec.WebApplicationFirewall != operatorv1.WAFEnabled) {
		return fmt.Errorf("at least one of webApplicationFirewall or logCollection.collectLogs must be specified in ApplicationLayer resource")
	}

	return nil
}

// getModSecurityRuleSet returns 'owasp-ruleset-config' ConfigMap from calico-operator namespace.
// The ConfigMap is meant to contain rule set files for ModSecurity library.
// If the ConfigMap does not exist a ConfigMap with OWASP provided Core Rule Set will be returned.
// The rule set was cloned from https://github.com/coreruleset/coreruleset/
func (r *ReconcileApplicationLayer) getModSecurityRuleSet(ctx context.Context) (*corev1.ConfigMap, bool, error) {
	ruleset := new(corev1.ConfigMap)

	if err := r.client.Get(
		ctx,
		types.NamespacedName{
			Namespace: common.OperatorNamespace(),
			Name:      applicationlayer.ModSecurityRulesetConfigMapName,
		},
		ruleset,
	); err == nil {
		return ruleset, false, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
	}

	ruleset, err := getDefaultCoreRuleset(ctx)
	if err != nil {
		return nil, false, err
	}
	return ruleset, true, nil
}

func getDefaultCoreRuleset(ctx context.Context) (*corev1.ConfigMap, error) {
	ruleset := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      applicationlayer.ModSecurityRulesetConfigMapName,
			Namespace: common.OperatorNamespace(),
		},
		Data: make(map[string]string),
	}

	for filename, dataBase64 := range applicationlayer.ModsecurityCoreRuleSet {
		if data, err := base64.StdEncoding.DecodeString(dataBase64); err == nil {
			ruleset.Data[filename] = string(data)
		} else {
			return nil, err
		}
	}

	return ruleset, nil
}

func validateModSecurityRuleSet(cm *corev1.ConfigMap) error {
	requiredFiles := []string{
		"modsecdefault.conf",
		"crs-setup.conf",
	}

	for _, f := range requiredFiles {
		if _, ok := cm.Data[f]; !ok {
			return fmt.Errorf("file must be found in Web Application Firewall rule set: %s", f)
		}
	}

	return nil
}

// getApplicationLayer returns the default ApplicationLayer instance.
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

func (r *ReconcileApplicationLayer) isWAFEnabled(applicationLayerSpec *operatorv1.ApplicationLayerSpec) bool {
	return applicationLayerSpec.WebApplicationFirewall != nil &&
		*applicationLayerSpec.WebApplicationFirewall == operatorv1.WAFEnabled
}

// patchFelixTproxyMode takes all application layer specs as arguments and patches felix config.
// If at least one of the specs requires TPROXYMode as "Enabled" it'll be patched as "Enabled" otherwise it is "Disabled".
func (r *ReconcileApplicationLayer) patchFelixTproxyMode(ctx context.Context, al *operatorv1.ApplicationLayer) error {
	// Fetch any existing default FelixConfiguration object.
	fc := &crdv1.FelixConfiguration{}
	err := r.client.Get(ctx, types.NamespacedName{Name: "default"}, fc)

	if err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read FelixConfiguration", err, log)
		return err
	}

	var tproxyMode crdv1.TPROXYModeOption
	patchFrom := client.MergeFrom(fc.DeepCopy())

	if al != nil && (r.isLogsCollectionEnabled(al.Spec.LogCollection) || r.isWAFEnabled(&al.Spec)) {
		tproxyMode = crdv1.TPROXYModeOptionEnabled
	} else {
		if fc.Spec.TPROXYMode == nil {
			// Workaround: we'd like to always force the value to be the correct one, matching the operator's
			// configuration.  However, during an upgrade from a version that predates the TPROXYMode option,
			// Felix hits a bug and gets confused by the new config parameter, which in turn triggers a restart.
			// Work around that by relying on Disabled being the default value for the field instead.
			//
			// The felix bug was fixed in v3.16, v3.15.1 and v3.14.4; it should be safe to set new config fields
			// once we know we're only upgrading from those versions and above.
			return nil
		}

		// If the mode is already set, fall through to the normal logic, it's safe to force-set the field now.
		// This also avoids churning the config if a previous version of the operator set it to Disabled already,
		// we avoid setting it back to nil.
		tproxyMode = crdv1.TPROXYModeOptionDisabled
	}
	// If tproxy mode is already set to desired state return nil.
	if fc.Spec.TPROXYMode != nil && *fc.Spec.TPROXYMode == tproxyMode {
		return nil
	}
	fc.Spec.TPROXYMode = &tproxyMode

	log.Info("Patching TPROXYMode FelixConfiguration with mode", "mode", string(tproxyMode))

	if err := r.client.Patch(ctx, fc, patchFrom); err != nil {
		return err
	}

	return nil
}
