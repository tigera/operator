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

package installation

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/tigera/operator/pkg/active"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var logw = logf.Log.WithName("controller_windows")

// Add creates a new Tiers Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func AddWindowsController(mgr manager.Manager, opts options.AddOptions) error {
	ri, err := newWindowsReconciler(mgr, opts)
	if err != nil {
		return fmt.Errorf("failed to create Windows Reconciler: %w", err)
	}

	c, err := controller.New("tigera-windows-controller", mgr, controller.Options{Reconciler: ri})
	if err != nil {
		return fmt.Errorf("Failed to create tigera-windows-controller: %w", err)
	}

	// Watch for changes to primary resource Installation
	err = c.Watch(&source.Kind{Type: &operatorv1.Installation{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, InstallationName); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch calico Tigerastatus: %w", err)
	}

	if ri.autoDetectedProvider == operatorv1.ProviderOpenShift {
		// Watch for openshift network configuration as well. If we're running in OpenShift, we need to
		// merge this configuration with our own and the write back the status object.
		err = c.Watch(&source.Kind{Type: &configv1.Network{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("tigera-windows-controller failed to watch openshift network config: %w", err)
			}
		}
	}

	// Watch for secrets in the operator namespace. We watch for all secrets, since we care
	// about specifically named ones - e.g., manager-tls, as well as image pull secrets that
	// may have been provided by the user with arbitrary names.
	err = utils.AddSecretsWatch(c, "", common.OperatorNamespace())
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch secrets: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, active.ActiveConfigMapName, common.CalicoNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch ConfigMap %s: %w", active.ActiveConfigMapName, err)
	}

	// Only watch AmazonCloudIntegration if the CRD is available
	if ri.amazonCRDExists {
		err = c.Watch(&source.Kind{Type: &operatorv1.AmazonCloudIntegration{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			logw.V(5).Info("Failed to create AmazonCloudIntegration watch", "err", err)
			return fmt.Errorf("amazoncloudintegration-controller failed to watch primary resource: %w", err)
		}
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch ImageSet: %w", err)
	}

	// Watch kube DNS service.
	dnsService := utils.GetDNSServiceName(opts.DetectedProvider)
	if err = utils.AddServiceWatch(c, dnsService.Name, dnsService.Namespace); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch Service: %w", err)
	}

	for _, t := range secondaryResources() {
		pred := predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				// Create occurs because we've created it, so we can safely ignore it.
				return false
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				if utils.IgnoreObject(e.ObjectOld) && !utils.IgnoreObject(e.ObjectNew) {
					// Don't skip the removal of the "ignore" annotation. We want to
					// reconcile when that happens.
					return true
				}
				// Otherwise, ignore updates to objects when metadata.Generation does not change.
				return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
			},
		}
		err = c.Watch(&source.Kind{Type: t}, &handler.EnqueueRequestForOwner{
			IsController: true,
			OwnerType:    &operatorv1.Installation{},
		}, pred)
		if err != nil {
			return fmt.Errorf("tigera-windows-controller failed to watch %s: %w", t, err)
		}
	}

	// Watch for changes to FelixConfiguration.
	err = c.Watch(&source.Kind{Type: &crdv1.FelixConfiguration{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch FelixConfiguration resource: %w", err)
	}

	// Watch for changes to IPAMConfiguration.
	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to establish a connection to k8s: %w", err)
	}
	go utils.WaitToAddResourceWatch(c, k8sClient, logw, ri.ipamConfigWatchReady, []client.Object{&apiv3.IPAMConfiguration{TypeMeta: metav1.TypeMeta{Kind: apiv3.KindIPAMConfiguration}}})

	if ri.enterpriseCRDsExist {
		for _, ns := range []string{common.CalicoNamespace, common.OperatorNamespace()} {
			if err = utils.AddSecretsWatch(c, render.NodePrometheusTLSServerSecret, ns); err != nil {
				return fmt.Errorf("tigera-windows-controller failed to watch secret '%s' in '%s' namespace: %w", render.NodePrometheusTLSServerSecret, ns, err)
			}
			if err = utils.AddSecretsWatch(c, monitor.PrometheusClientTLSSecretName, ns); err != nil {
				return fmt.Errorf("tigera-windows-controller failed to watch secret '%s' in '%s' namespace: %w", monitor.PrometheusClientTLSSecretName, ns, err)
			}
		}
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

type ReconcileWindows struct {
	config               *rest.Config
	client               client.Client
	scheme               *runtime.Scheme
	watches              map[runtime.Object]struct{}
	autoDetectedProvider operatorv1.Provider
	status               status.StatusManager
	enterpriseCRDsExist  bool
	amazonCRDExists      bool
	clusterDomain        string
	ipamConfigWatchReady *utils.ReadyFlag
}

// newWindowsReconciler returns a new reconcile.Reconciler
func newWindowsReconciler(mgr manager.Manager, opts options.AddOptions) (*ReconcileWindows, error) {
	statusManager := status.New(mgr.GetClient(), "calico-windows", opts.KubernetesVersion)

	r := &ReconcileWindows{
		config:               mgr.GetConfig(),
		client:               mgr.GetClient(),
		scheme:               mgr.GetScheme(),
		watches:              make(map[runtime.Object]struct{}),
		autoDetectedProvider: opts.DetectedProvider,
		status:               statusManager,
		amazonCRDExists:      opts.AmazonCRDExists,
		enterpriseCRDsExist:  opts.EnterpriseCRDExists,
		clusterDomain:        opts.ClusterDomain,
		ipamConfigWatchReady: &utils.ReadyFlag{},
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

// Reconcile reads that state of the cluster for a Installation object and makes changes based on the state read
// and what is in the Installation.Spec. The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileWindows) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := logw.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Installation.operator.tigera.io")

	// Get the installation object if it exists so that we can save the original
	// status before we merge/fill that object with other values.
	instance := &operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}

	// Don't render calico-node-windows if it's disabled in the installation
	if !common.WindowsEnabled(instance.Spec) {
		reqLogger.V(1).Info("Calico Windows daemonset is disabled in the operator installation")
		return reconcile.Result{}, nil
	}

	// Mark CR found so we can report converter problems via tigerastatus
	r.status.OnCRFound()
	// FIXME: add logic to merge Installation status metadata

	// FIXME: add logic to update Installation status conditions that doesn't conflict with
	// core_controller

	instanceStatus := instance.Status

	reqLogger.V(2).Info("Loaded config", "config", instance)

	// The k8s service endpoint configmap must populate k8sapi.Endpoint data before validating the configuration.
	if _, err := utils.GetK8sServiceEndPoint(r.client); err != nil {
		// PopulateK8sServiceEndPoint() does not return an error if the configmap is not found, check for this with GetK8sServiceEndPoint()
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading services endpoint configmap", err, reqLogger)
		return reconcile.Result{}, err
	}
	if err := utils.PopulateK8sServiceEndPoint(r.client); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading services endpoint configmap", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate the configuration.
	if err := validateCustomResource(instance); err != nil {
		r.status.SetDegraded(operatorv1.InvalidConfigurationError, "Invalid Installation provided", err, reqLogger)
		return reconcile.Result{}, err
	}

	// update Installation with 'overlay'
	overlay := operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.OverlayInstanceKey, &overlay); err != nil {
		if !apierrors.IsNotFound(err) {
			reqLogger.Error(err, "An error occurred when querying the 'overlay' Installation resource")
			return reconcile.Result{}, err
		}
		reqLogger.V(5).Info("no 'overlay' installation found")
	} else {
		instance.Spec = utils.OverrideInstallationSpec(instance.Spec, overlay.Spec)
		reqLogger.V(2).Info("loaded final computed config", "config", instance)

		// Validate the configuration.
		if err := validateCustomResource(instance); err != nil {
			r.status.SetDegraded(operatorv1.InvalidConfigurationError, "Invalid computed config", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// We rely on the core controller for defaulting, so wait until it has done so before continuing
	if reflect.DeepEqual(instanceStatus, operatorv1.InstallationStatus{}) {
		err := fmt.Errorf("InstallationStatus is empty")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "InstallationStatus is empty", err, reqLogger)
		return reconcile.Result{}, err
	}
	if instance.Spec.WindowsNodes == nil {
		err := fmt.Errorf("Installation.Spec.WindowsNodes is nil")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Installation.Spec.WindowsNodes is nil", err, reqLogger)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, &instance.Spec, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	typhaNodeTLS, err := GetTyphaNodeTLSConfig(r.client, certificateManager)
	if err != nil {
		logw.Error(err, "Error with Typha/Felix secrets")
		r.status.SetDegraded(operatorv1.CertificateError, "Error with Typha/Felix secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch default FelixConfiguration
	felixConfiguration := &crdv1.FelixConfiguration{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, felixConfiguration)
	if err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read FelixConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch and validate default IPAMConfiguration for StrictAffinity when using Calico IPAM
	if instance.Spec.CNI.Type == operatorv1.PluginCalico && instance.Spec.CNI.IPAM.Type == operatorv1.IPAMPluginCalico {
		if !r.ipamConfigWatchReady.IsReady() {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for IPAMConfiguration watch to be established", nil, logw)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		ipamConfiguration := &apiv3.IPAMConfiguration{}
		err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, ipamConfiguration)
		if err != nil && !apierrors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read IPAMConfiguration", err, reqLogger)
			return reconcile.Result{}, err
		}
		if !ipamConfiguration.Spec.StrictAffinity {
			err := fmt.Errorf("StrictAffinity is false, it must be set to 'true' in the default IPAMConfiguration when using Calico IPAM on Windows")
			r.status.SetDegraded(operatorv1.ResourceReadError, "Invalid StrictAffinity, it must be set to 'true' when using Calico IPAM on Windows", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	var aci *operatorv1.AmazonCloudIntegration
	if r.amazonCRDExists {
		aci, err = utils.GetAmazonCloudIntegration(ctx, r.client)
		if apierrors.IsNotFound(err) {
			aci = nil
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading AmazonCloudIntegration", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// nodeReporterMetricsPort is a port used in Enterprise to host internal metrics.
	// Operator is responsible for creating a service which maps to that port.
	// Here, we'll check the default felixconfiguration to see if the user is specifying
	// a non-default port, and use that value if they are.
	nodeReporterMetricsPort := defaultNodeReporterPort
	var nodePrometheusTLS certificatemanagement.KeyPairInterface
	if instance.Spec.Variant == operatorv1.TigeraSecureEnterprise {

		// Determine the port to use for nodeReporter metrics.
		if felixConfiguration.Spec.PrometheusReporterPort != nil {
			nodeReporterMetricsPort = *felixConfiguration.Spec.PrometheusReporterPort
		}

		if nodeReporterMetricsPort == 0 {
			err := errors.New("felixConfiguration prometheusReporterPort=0 not supported")
			r.status.SetDegraded(operatorv1.InvalidConfigurationError, "invalid metrics port", err, reqLogger)
			return reconcile.Result{}, err
		}

		// The key pair is created by the core controller, so if it isn't set, requeue to wait until it is
		nodePrometheusTLS, err = certificateManager.GetKeyPair(r.client, render.NodePrometheusTLSServerSecret, common.OperatorNamespace(), dns.GetServiceDNSNames(render.WindowsNodeMetricsService, common.CalicoNamespace, r.clusterDomain))
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error getting TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	var component render.Component

	kubeDNSServiceName := utils.GetDNSServiceName(r.autoDetectedProvider)
	kubeDNSService := &corev1.Service{}
	err = r.client.Get(ctx, kubeDNSServiceName, kubeDNSService)
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, fmt.Sprintf("%s service not found", kubeDNSServiceName.Name), err, reqLogger)
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error querying %s service", kubeDNSServiceName.Name), err, reqLogger)
		}
		return reconcile.Result{}, err
	}
	kubeDNSIPs := kubeDNSService.Spec.ClusterIPs

	// felixConfiguration.Spec.VXLANVNI is defaulted by fillDefaults() in the core controller, so if it isn't set, requeue to wait until it is
	if felixConfiguration.Spec.VXLANVNI == nil {
		err = fmt.Errorf("VXLANVNI not specified in FelixConfigurationSpec")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading VXLANVNI from FelixConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	windowsCfg := render.WindowsConfiguration{
		K8sServiceEp:            k8sapi.Endpoint,
		K8sDNSServers:           kubeDNSIPs,
		Installation:            &instance.Spec,
		ClusterDomain:           r.clusterDomain,
		TLS:                     typhaNodeTLS,
		AmazonCloudIntegration:  aci,
		PrometheusServerTLS:     nodePrometheusTLS,
		NodeReporterMetricsPort: nodeReporterMetricsPort,
		VXLANVNI:                *felixConfiguration.Spec.VXLANVNI,
	}
	component = render.Windows(&windowsCfg)

	imageSet, err := imageset.GetImageSet(ctx, r.client, instance.Spec.Variant)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error validating ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ResolveImages(imageSet, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error resolving ImageSet for components", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a component handler to create or update the rendered components.
	handler := utils.NewComponentHandler(logw, r.client, r.scheme, instance)
	if err := handler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	reqLogger.V(1).Info("Finished reconciling windows installation")
	return reconcile.Result{}, nil
}
