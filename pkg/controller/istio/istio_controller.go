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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"
	"github.com/go-logr/logr"
	"github.com/tigera/api/pkg/lib/numorstring"
	operatorv1 "github.com/tigera/operator/api/v1"
	v1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/gatewayapi"
	renderistio "github.com/tigera/operator/pkg/render/istio"
)

const (
	reasonInfo = "Info_reconciling_Tigera_Istio"
	reasonErr  = "Error_reconciling_Tigera_Istio"
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

	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("istio-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) *ReconcileIstio {
	r := &ReconcileIstio{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		status: status.New(mgr.GetClient(), "istio", opts.KubernetesVersion),
	}

	r.status.Run(opts.ShutdownContext)
	return r
}

// ReconcileIstio reconciles a Istio object
type ReconcileIstio struct {
	client.Client
	scheme *runtime.Scheme
	status status.StatusManager
}

func (r *ReconcileIstio) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling Istio")

	if request.NamespacedName != utils.DefaultInstanceKey {
		reqLogger.V(1).Info("Istio resource named %q is not recognised, name it %q",
			request.Name, utils.DefaultInstanceKey.Name)
		return reconcile.Result{}, nil
	}

	// Get the Istio CR.
	instance := &operatorv1.Istio{}
	err := r.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Istio object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError,
			fmt.Sprintf("Error querying for Istio CR: failed to get Istio %q", utils.DefaultInstanceKey),
			err, reqLogger)
		return reconcile.Result{}, err
	}
	updateDefaults(instance)
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	defer r.setCondition(ctx, instance, reqLogger)

	setCurrentCondition(instance, v1.ComponentProgressing, reasonInfo, "Deploying Tigera Istio resources")

	if res, err, finished := r.maintainFinalizer(ctx, instance, reqLogger); err != nil || finished {
		return res, err
	}

	// Get the Installation, for k8s provider info.
	variant, installation, err := utils.GetInstallation(ctx, r)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		setCurrentCondition(instance, v1.ComponentDegraded, reasonErr, "Installation resource not found")
		return reconcile.Result{}, err
	}

	if variant == "" {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Installation Variant to be set", nil, reqLogger)
		return reconcile.Result{Requeue: true}, nil
	}

	// Get the Kubernetes Gateway API CRDs.
	essentialCRDs, optionalCRDs := gatewayapi.K8SGatewayAPICRDs(installation.KubernetesProvider)

	// Check CRDs are present and only create it if not
	handler := utils.NewComponentHandler(log, r, r.scheme, nil)
	handler.SetCreateOnly()
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(essentialCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating gateway API CRDs", err, log)
		setCurrentCondition(instance, v1.ComponentDegraded, reasonErr, fmt.Sprintf("Error creating Gateway API resources: %s", err.Error()))
		return reconcile.Result{}, err
	}
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(optionalCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		reqLogger.Info("Could not render all optional gateway API CRDs", "err", err)
	}

	// Render resources for Istio support
	istioCfg := &render.IstioConfig{
		Installation:   installation,
		Istio:          instance,
		IstioNamespace: render.IstioNamespace,
	}
	istioComponent := render.NewIstioComponent(istioCfg)

	// Apply the image set
	if err = imageset.ApplyImageSet(ctx, r.Client, installation.Variant, istioComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error with ImageSet", err, reqLogger)
		setCurrentCondition(instance, v1.ComponentDegraded, reasonErr, fmt.Sprintf("Error applying image set: %s", err.Error()))
		return reconcile.Result{}, err
	}

	// Produce Helm templates for Istio
	istioResOpts := &renderistio.ResourceOpts{
		Namespace:                 render.IstioNamespace,
		ReleaseName:               render.IstioReleaseName,
		IstiodDeploymentName:      render.IstioIstiodDeploymentName,
		IstioCNIDaemonSetName:     render.IstioCNIDaemonSetName,
		IstioZTunnelDaemonSetName: render.IstioZTunnelDaemonSetName,

		// Helm chart opts
		BaseOpts: renderistio.BaseOpts{
			Global: &renderistio.GlobalConfig{
				IstioNamespace: render.IstioNamespace,
			},
		},
		IstiodOpts: renderistio.IstiodOpts{
			Image: istioComponent.IstioPilotImage,
			Global: &renderistio.GlobalConfig{
				IstioNamespace:         render.IstioNamespace,
				OperatorManageWebhooks: true,
				Proxy: &renderistio.ProxyConfig{
					Image: istioComponent.IstioProxyv2Image,
				},
				ProxyInit: &renderistio.ProxyInitConfig{
					Image: istioComponent.IstioProxyv2Image,
				},
			},
			Profile: "ambient",
		},
		IstioCNIOpts: renderistio.IstioCNIOpts{
			Image: istioComponent.IstioInstallCNIImage,
			Global: &renderistio.GlobalConfig{
				IstioNamespace: render.IstioNamespace,
			},
			Ambient: &renderistio.AmbientConfig{
				Enabled:                    true,
				ReconcileIptablesOnStartup: true,
			},
		},
		ZTunnelOpts: renderistio.ZTunnelOpts{
			Image: istioComponent.IstioZtunnelImage,
			Global: &renderistio.GlobalConfig{
				IstioNamespace: render.IstioNamespace,
			},
		},
	}
	if installation.KubernetesProvider == operatorv1.ProviderGKE {
		istioResOpts.IstioCNIOpts.Global.Platform = "gke"
	}
	istioCfg.Resources, err = istioResOpts.GetResources()
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error generating Tigera Istio resources", err, log)
		setCurrentCondition(instance, v1.ComponentDegraded, reasonErr, fmt.Sprintf("Error generating Tigera Istio resources: %s", err.Error()))
		return reconcile.Result{}, err
	}

	// Deploy Istio CRDs
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(istioCfg.Resources.CRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering Tigera Istio CRDs", err, log)
		setCurrentCondition(instance, v1.ComponentDegraded, reasonErr, fmt.Sprintf("Error rendering Tigera Istio CRDs: %s", err.Error()))
		return reconcile.Result{}, err
	}

	// Deploy Istio components
	err = utils.NewComponentHandler(log, r, r.scheme, instance).CreateOrUpdateOrDelete(ctx, istioComponent, r.status)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering Tigera Istio resources", err, log)
		setCurrentCondition(instance, v1.ComponentDegraded, reasonErr, fmt.Sprintf("Error rendering Tigera Istio CRDs: %s", err.Error()))
		return reconcile.Result{}, err
	}

	_, err = utils.PatchFelixConfiguration(ctx, r.Client, func(fc *crdv1.FelixConfiguration) (bool, error) {
		return r.setIstioFelixConfiguration(ctx, instance, fc, false)
	})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error patching felix configuration with Istio settings", err, log)
		setCurrentCondition(instance, v1.ComponentDegraded, reasonErr, fmt.Sprintf("Error patching felix configuration with Istio settings: %s", err.Error()))
		return reconcile.Result{}, err
	}

	// Check all components are ready
	setCurrentCondition(instance, v1.ComponentProgressing, reasonInfo, "Waiting component \"Istiod\" to be ready")

	readyDep := &appsv1.Deployment{}
	k := client.ObjectKey{Namespace: render.IstioNamespace, Name: render.IstioIstiodDeploymentName}
	if err = r.Get(ctx, k, readyDep); err != nil {

		r.status.SetDegraded(operatorv1.ResourceNotFound, "Istiod deployment not found", err, log)
		return reconcile.Result{}, err
	}
	if readyDep.Spec.Replicas == nil || readyDep.Status.ReadyReplicas != *readyDep.Spec.Replicas {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Istiod deployment not ready", nil, log)
		return reconcile.Result{RequeueAfter: time.Second * 5}, nil
	}

	readyDS := &appsv1.DaemonSet{}
	for _, checker := range []struct{ namespace, name, description string }{
		{render.IstioNamespace, render.IstioCNIDaemonSetName, "Istio CNI"},
		{render.IstioNamespace, render.IstioZTunnelDaemonSetName, "ZTunnel"},
		{common.CalicoNamespace, render.CalicoNodeObjectName, "Calico"},
	} {
		setCurrentCondition(instance, v1.ComponentProgressing, reasonInfo, fmt.Sprintf("Waiting component %q to be ready", checker.description))
		if err = r.Get(ctx, client.ObjectKey{Namespace: checker.namespace, Name: checker.name}, readyDS); err != nil {

			r.status.SetDegraded(operatorv1.ResourceNotFound, checker.description+" daemonset not found", err, log)
			return reconcile.Result{}, err
		}
		if readyDS.Status.NumberReady != readyDS.Status.DesiredNumberScheduled {
			r.status.SetDegraded(operatorv1.ResourceNotReady, checker.description+" daemonset not ready", nil, log)
			return reconcile.Result{RequeueAfter: time.Second * 5}, nil
		}
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	setCurrentCondition(instance, v1.ComponentReady, reasonInfo, "Successfully deployed")

	return reconcile.Result{}, nil
}

func updateDefaults(istio *v1.Istio) {
	if istio.Spec.DSCPMark == nil {
		dscpMark := numorstring.DSCPFromInt(23)
		istio.Spec.DSCPMark = &dscpMark
	}
}

func (r *ReconcileIstio) setIstioFelixConfiguration(ctx context.Context, istio *v1.Istio, fc *crdv1.FelixConfiguration, remove bool) (bool, error) {
	var annotationMode *string
	if fc.Annotations[render.IstioOperatorAnnotationMode] != "" {
		value := fc.Annotations[render.IstioOperatorAnnotationMode]
		annotationMode = &value
	}

	// If the annotation does not match the spec value (ignoring both nil), it indicates a misconfiguration.
	if annotationMode != fc.Spec.IstioAmbientMode &&
		(annotationMode == nil || fc.Spec.IstioAmbientMode == nil || *annotationMode != *fc.Spec.IstioAmbientMode) {
		if remove {
			delete(fc.Annotations, render.IstioOperatorAnnotationMode)
			goto _checkDSCP
		}
		return false, fmt.Errorf("felixconfig IstioAmbientMode modified by user")
	}

	if remove {
		delete(fc.Annotations, render.IstioOperatorAnnotationMode)
		fc.Spec.IstioAmbientMode = nil
	} else {
		istioModeDesired := "Enabled"
		fc.Spec.IstioAmbientMode = &istioModeDesired
		if fc.Annotations == nil {
			fc.Annotations = make(map[string]string)
		}
		fc.Annotations[render.IstioOperatorAnnotationMode] = istioModeDesired
	}

_checkDSCP:
	var annotationDSCP *numorstring.DSCP
	if fc.Annotations[render.IstioOperatorAnnotationDSCP] != "" {
		value, err := strconv.ParseUint(fc.Annotations[render.IstioOperatorAnnotationDSCP], 10, 32)
		if err != nil {
			return false, err
		}
		dscp := numorstring.DSCPFromInt(uint8(value))
		annotationDSCP = &dscp
	}

	// Return an error if it appears that FelixConfiguration has been modified out of band.
	if annotationDSCP != fc.Spec.IstioDSCPMark &&
		(annotationDSCP == nil || fc.Spec.IstioDSCPMark == nil || annotationDSCP.ToUint8() != fc.Spec.IstioDSCPMark.ToUint8()) {
		if remove {
			delete(fc.Annotations, render.IstioOperatorAnnotationDSCP)
			goto _end
		}
		return false, fmt.Errorf("felixconfig IstioDSCPMark modified by user")
	}

	if remove || istio.Spec.DSCPMark == nil {
		delete(fc.Annotations, render.IstioOperatorAnnotationDSCP)
		fc.Spec.IstioDSCPMark = nil
	} else {
		istioDSCPMarkDesired := *istio.Spec.DSCPMark
		fc.Spec.IstioDSCPMark = &istioDSCPMarkDesired
		fc.Annotations[render.IstioOperatorAnnotationDSCP] = strconv.FormatUint(uint64(istioDSCPMarkDesired.ToUint8()), 10)
	}

_end:
	return true, nil
}

func (r *ReconcileIstio) maintainFinalizer(ctx context.Context, istio *v1.Istio, reqLogger logr.Logger) (res reconcile.Result, err error, finalized bool) {
	// Executing clean up on finalizing
	if !istio.ObjectMeta.DeletionTimestamp.IsZero() {
		if _, err = utils.PatchFelixConfiguration(ctx, r.Client, func(fc *crdv1.FelixConfiguration) (bool, error) {
			return r.setIstioFelixConfiguration(ctx, istio, fc, true)
		}); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error cleaning up felix configuration", err, reqLogger)
			return
		}
		patchFrom := client.MergeFrom(istio.DeepCopy())
		istio.Finalizers = stringsutil.RemoveStringInSlice(render.IstioFinalizer, istio.Finalizers)
		if err = r.Patch(ctx, istio, patchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error removing finalizer on Istio", err, reqLogger)
			return
		}

		r.status.ClearDegraded()
		return res, nil, true
	}

	if !stringsutil.StringInSlice(render.IstioFinalizer, istio.Finalizers) {
		patchFrom := client.MergeFrom(istio.DeepCopy())
		istio.Finalizers = append(istio.Finalizers, render.IstioFinalizer)
		if err = r.Patch(ctx, istio, patchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error setting finalizer on Istio", err, reqLogger)
			return
		}
	}

	return
}

func (r *ReconcileIstio) setCondition(ctx context.Context, istio *v1.Istio, reqLogger logr.Logger) {
	if err := r.Status().Update(ctx, istio); err != nil {
		reqLogger.Error(err, "Error updating Istio status condition")
	}
}

func setCurrentCondition(istio *v1.Istio, ctype v1.StatusConditionType, reason, msg string) {
	found := false
	for i, cond := range istio.Status.Conditions {
		if cond.Type == string(ctype) {
			if cond.Status == metav1.ConditionTrue &&
				cond.Reason == reason &&
				cond.Message == msg {
				return
			}
			cond.Status = metav1.ConditionTrue
			cond.Reason = reason
			cond.Message = msg
			found = true
		} else {
			cond.Status = metav1.ConditionFalse
			cond.Reason = string(operatorv1.Unknown)
			cond.Message = ""
		}
		cond.LastTransitionTime = metav1.Now()
		istio.Status.Conditions[i] = cond
	}
	if !found {
		istio.Status.Conditions = append(istio.Status.Conditions, metav1.Condition{
			Type:               string(ctype),
			Status:             metav1.ConditionTrue,
			Reason:             reason,
			Message:            msg,
			ObservedGeneration: istio.GetGeneration(),
			LastTransitionTime: metav1.Now(),
		})
	}
}
