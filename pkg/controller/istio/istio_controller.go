// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package istio

import (
	"context"
	"fmt"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/api/pkg/lib/numorstring"
	operatorv1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/gatewayapi"
	renderistio "github.com/tigera/operator/pkg/render/istio"
)

var (
	// blank assignment to verify that ReconcileIstio implements reconcile.Reconciler
	_ reconcile.Reconciler = &ReconcileIstio{}

	log = logf.Log.WithName("controller_istio")
)

// Add creates a new Istio Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
//
// Start Watches within the Add function for any resources that this controller creates or monitors. This will trigger
// calls to Reconcile() when an instance of one of the watched resources is modified.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	r := newReconciler(mgr, opts)

	c, err := ctrlruntime.NewController("istio-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create istio-controller: %w", err)
	}

	// Watch for changes to primary resource Istio
	err = c.WatchObject(&operatorv1.Istio{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create Istio watch", "err", err)
		return fmt.Errorf("istio-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("istio-controller failed to watch Tigera network resource: %v", err)
	}

	err = c.WatchObject(&crdv1.FelixConfiguration{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("istio-controller failed to watch FelixConfiguration resource: %w", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) *ReconcileIstio {
	r := &ReconcileIstio{
		Client:              mgr.GetClient(),
		scheme:              mgr.GetScheme(),
		provider:            opts.DetectedProvider,
		enterpriseCRDsExist: opts.EnterpriseCRDExists,
		status:              status.New(mgr.GetClient(), "istio", opts.KubernetesVersion),
		clusterDomain:       opts.ClusterDomain,
		multiTenant:         opts.MultiTenant,
	}

	r.status.Run(opts.ShutdownContext)
	return r
}

// ReconcileIstio reconciles a Istio object
type ReconcileIstio struct {
	client.Client
	scheme              *runtime.Scheme
	provider            operatorv1.Provider
	enterpriseCRDsExist bool
	status              status.StatusManager
	clusterDomain       string
	multiTenant         bool
}

// Reconcile reads that state of the cluster for a Istio object and makes changes based on the state read
// and what is in the Istio.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileIstio) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Istio")

	// Get the Istio CR.
	istio, msg, err := GetIstio(ctx, r)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Istio object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for Istio CR: "+msg, err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&istio.ObjectMeta)

	// Get the Installation, for private registry and pull secret config.
	variant, installation, err := utils.GetInstallation(ctx, r)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if variant == "" {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Installation Variant to be set", nil, reqLogger)
		return reconcile.Result{Requeue: true}, nil
	}

	// patch felixconfiguration
	_, err = utils.PatchFelixConfiguration(ctx, r.Client, func(fc *crdv1.FelixConfiguration) (bool, error) {
		var istioMode *string
		if fc.Annotations[render.IstioOperatorAnnotationMode] != "" {
			value := fc.Annotations[render.IstioOperatorAnnotationMode]
			istioMode = &value
		}

		// the variables only can be equal if they are nil
		if istioMode != fc.Spec.IstioMode &&
			(istioMode == nil || fc.Spec.IstioMode == nil || *istioMode != *fc.Spec.IstioMode) {
			return false, fmt.Errorf("felixconfig %q modified by user", "IstioMode")
		}

		istioModeDesired := "Enabled"
		fc.Spec.IstioMode = &istioModeDesired
		if fc.Annotations == nil {
			fc.Annotations = make(map[string]string)
		}
		fc.Annotations[render.IstioOperatorAnnotationMode] = istioModeDesired

		if istio.Spec.DSCPMark == nil {
			return true, nil
		}

		var dscpValue *numorstring.DSCP
		if fc.Annotations[render.IstioOperatorAnnotationDSCP] != "" {
			value, err := strconv.ParseUint(fc.Annotations[render.IstioOperatorAnnotationDSCP], 10, 32)
			if err != nil {
				return false, err
			}
			dscp := numorstring.DSCPFromInt(uint8(value))
			dscpValue = &dscp
		}

		// the variables only can be equal if they are nil
		if dscpValue != fc.Spec.IstioDSCPMark &&
			(dscpValue == nil || fc.Spec.IstioDSCPMark == nil || dscpValue.ToUint8() != fc.Spec.IstioDSCPMark.ToUint8()) {
			return false, fmt.Errorf("felixconfig %q modified by user", "IstioDSCPMark")
		}

		istioDSCPMarkDesired := *istio.Spec.DSCPMark
		fc.Spec.IstioDSCPMark = &istioDSCPMarkDesired
		fc.Annotations[render.IstioOperatorAnnotationDSCP] = strconv.FormatUint(uint64(istioDSCPMarkDesired.ToUint8()), 10)

		return true, nil
	})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering essential Tigera Istio CRDs", err, log)
		return reconcile.Result{}, err
	}

	// Get the Kubernetes Gateway API CRDs.
	essentialCRDs, optionalCRDs := gatewayapi.K8SGatewayAPICRDs(installation.KubernetesProvider)

	// Check CRDs are present and only create it if not
	handler := utils.NewComponentHandler(log, r, r.scheme, nil)
	handler.SetCreateOnly()
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(essentialCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering essential Tigera Istio CRDs", err, log)
		return reconcile.Result{}, err
	}
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(optionalCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		reqLogger.Info("Could not render all optional Tigera Istio CRDs", "err", err)
	}

	// Get pull secrets
	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.Client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Render resources for Istio support
	istioCfg := &render.IstioConfig{
		Installation:   installation,
		Istio:          istio,
		IstioNamespace: render.IstioNamespace,
		PullSecrets:    pullSecrets,
	}
	istioComponent := render.NewIstioComponent(istioCfg)

	// Apply the image set
	if err = imageset.ApplyImageSet(ctx, r.Client, installation.Variant, istioComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error with ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Produce Helm templates for Istio
	baseOpts := map[string]interface{}{
		"global": map[string]interface{}{
			"istioNamespace": render.IstioNamespace,
		},
	}
	istiodOpts := map[string]interface{}{
		"image": istioComponent.IstioPilotImage,
		"global": map[string]interface{}{
			"istioNamespace":         render.IstioNamespace,
			"operatorManageWebhooks": true,
			"proxy": map[string]interface{}{
				"image": istioComponent.IstioProxyv2Image,
			},
			"proxy_init": map[string]interface{}{
				"image": istioComponent.IstioProxyv2Image,
			},
		},
		"profile": "ambient",
	}
	cniOpts := map[string]interface{}{
		"image": istioComponent.IstioInstallCNIImage,
		"global": map[string]interface{}{
			"istioNamespace": render.IstioNamespace,
		},
		"ambient": map[string]interface{}{
			"enabled":                    true,
			"reconcileIptablesOnStartup": true,
		},
	}
	if installation.KubernetesProvider == operatorv1.ProviderGKE {
		cniOpts["global"].(map[string]interface{})["platform"] = "gke"
	}
	ztunnelOpts := map[string]interface{}{
		"image": istioComponent.IstioZtunnelImage,
		"global": map[string]interface{}{
			"istioNamespace": render.IstioNamespace,
		},
	}
	istioCfg.Resources, err = renderistio.GetResources(render.IstioNamespace, render.IstioReleaseName, baseOpts,
		istiodOpts, cniOpts, ztunnelOpts)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering Istio resources", err, log)
		return reconcile.Result{}, err
	}

	// Deploy Istio CRDs
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(istioCfg.Resources.CRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering Tigera Istio CRDs", err, log)
		return reconcile.Result{}, err
	}

	// Deploy Istio components
	err = utils.NewComponentHandler(log, r, r.scheme, istio).CreateOrUpdateOrDelete(ctx, istioComponent, r.status)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering Istio resources", err, log)
		return reconcile.Result{}, err
	}

	// Check all components are ready
	istiodDep := &appsv1.Deployment{}
	if err = r.Get(ctx, client.ObjectKey{Namespace: render.IstioNamespace,
		Name: render.IstioIstiodDeploymentName}, istiodDep); err != nil {

		r.status.SetDegraded(operatorv1.ResourceNotFound, "Istiod deployment not found", err, log)
		return reconcile.Result{}, err
	}
	if istiodDep.Spec.Replicas == nil || istiodDep.Status.ReadyReplicas != *istiodDep.Spec.Replicas {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Istiod deployment not ready", nil, log)
		return reconcile.Result{RequeueAfter: time.Second * 5}, nil
	}

	istioCniDs := &appsv1.DaemonSet{}
	if err = r.Get(ctx, client.ObjectKey{Namespace: render.IstioNamespace,
		Name: render.IstioCNIDaemonSetName}, istioCniDs); err != nil {

		r.status.SetDegraded(operatorv1.ResourceNotFound, "Istio CNI daemonset not found", err, log)
		return reconcile.Result{}, err
	}
	if istioCniDs.Status.NumberReady != istioCniDs.Status.DesiredNumberScheduled {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Istio CNI daemonset not ready", nil, log)
		return reconcile.Result{RequeueAfter: time.Second * 5}, nil
	}

	ztunnelDs := &appsv1.DaemonSet{}
	if err = r.Get(ctx, client.ObjectKey{Namespace: render.IstioNamespace,
		Name: render.IstioZTunnelDaemonSetName}, ztunnelDs); err != nil {

		r.status.SetDegraded(operatorv1.ResourceNotFound, "ZTunnel daemonset not found", err, log)
		return reconcile.Result{}, err
	}
	if ztunnelDs.Status.NumberReady != ztunnelDs.Status.DesiredNumberScheduled {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "ZTunnel daemonset not ready", nil, log)
		return reconcile.Result{RequeueAfter: time.Second * 5}, nil
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	// Update the status of the Istio instance and StatusManager.
	return reconcile.Result{RequeueAfter: utils.PeriodicReconcileTime}, nil
}

// GetIstio finds the correct Istio resource and returns a message and error in the case of an error.
func GetIstio(ctx context.Context, client client.Client) (*operatorv1.Istio, string, error) {
	// Fetch the Istio resource.  Look for "default" first.
	resource := &operatorv1.Istio{}
	err := client.Get(ctx, utils.DefaultInstanceKey, resource)
	if err != nil {
		return nil, fmt.Sprintf("failed to get Istio '%s'", utils.DefaultInstanceKey), err
	}
	return resource, "", nil
}
