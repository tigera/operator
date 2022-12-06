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
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
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

	"github.com/go-logr/logr"
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

	// Watch for changes to primary resource Egress Gateway.
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

	// Watch for changes to FelixConfiguration.
	err = c.Watch(&source.Kind{Type: &crdv1.FelixConfiguration{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("egressGateway-controller failed to watch FelixConfiguration resource: %w", err)
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

	egws, err := getEgressGateways(ctx, r.client, request)
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
	r.status.OnCRFound()
	for _, egw := range egws {
		result, err := r.reconcile(ctx, &egw, reqLogger)
		if err != nil {
			return result, err
		}
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileEgressGateway) reconcile(ctx context.Context, egw *operatorv1.EgressGateway, reqLogger logr.Logger) (reconcile.Result, error) {
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

	fillDefaults(egw)
	err = validateEgressGateway(ctx, r.client, egw)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("Error validating Egress Gateway spec"))
		r.status.SetDegraded("Error validating egress gateway", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)

	if err != nil {
		reqLogger.Error(err, "Error retrieving pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	// Fetch any existing default FelixConfiguration object.
	fc := &crdv1.FelixConfiguration{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, fc)

	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded("Unable to read FelixConfiguration", err.Error())
		return reconcile.Result{}, err
	}

	egwVxlanPort := egressgateway.DefaultEGWVxlanPort
	egwVxlanVNI := egressgateway.DefaultEGWVxlanVNI
	if fc.Spec.EgressIPVXLANPort != nil {
		egwVxlanPort = *fc.Spec.EgressIPVXLANPort
	}
	if fc.Spec.EgressIPVXLANVNI != nil {
		egwVxlanVNI = *fc.Spec.EgressIPVXLANVNI
	}

	config := &egressgateway.Config{
		PullSecrets:       pullSecrets,
		Installation:      installation,
		OsType:            rmeta.OSTypeLinux,
		EgressGW:          egw,
		EgressGWVxlanPort: egwVxlanPort,
		EgressGWVxlanVNI:  egwVxlanVNI,
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

// validateEgressGateway checks if the ippools specified are already present.
func validateEgressGateway(ctx context.Context, cli client.Client, egw *operatorv1.EgressGateway) error {
	for _, ippool := range egw.Spec.IPPools {
		instance := &crdv1.IPPool{}
		key := types.NamespacedName{Name: ippool}
		err := cli.Get(ctx, key, instance)
		if err != nil {
			return err
		}
	}
	if egw.Spec.AWS != nil {
		if len(egw.Spec.AWS.ElasticIPs) > 0 && (*egw.Spec.AWS.NativeIP == operatorv1.NativeIPDisabled) {
			return fmt.Errorf("NativeIP should be enabled when elastic IPs are used")
		}
	}
	return nil
}

//getEgressGateways returns the egress gateways in all namespaces or in the request's namespace.
func getEgressGateways(ctx context.Context, cli client.Client, request reconcile.Request) ([]operatorv1.EgressGateway, error) {
	// Get all the Egress Gateways in all the namespaces.
	if request.Namespace == "" {
		instance := &operatorv1.EgressGatewayList{}
		err := cli.List(ctx, instance)
		if err != nil {
			return []operatorv1.EgressGateway{}, err
		}
		return instance.Items, nil
	}
	// Get the requested egress gateway
	instance, err := getEgressGateway(ctx, cli, request.Namespace, request.Name)
	if err != nil {
		return []operatorv1.EgressGateway{}, err
	}
	return []operatorv1.EgressGateway{*instance}, err

}

func fillDefaults(egw *operatorv1.EgressGateway) {
	defaultLogSeverity := "info"
	var defaultHealthPort int32 = 8080
	defaultHealthTimeoutDS := "90s"
	defaultIcmpTimeout := "15s"
	defaultIcmpInterval := "5s"
	defaultHttpTimeout := "30s"
	defaultHttpInterval := "10s"
	defaultAWSNativeIP := operatorv1.NativeIPDisabled

	if egw.Spec.LogSeverity == nil {
		egw.Spec.LogSeverity = &defaultLogSeverity
	}

	if egw.Spec.AWS != nil && egw.Spec.AWS.NativeIP == nil {
		egw.Spec.AWS.NativeIP = &defaultAWSNativeIP
	}

	if egw.Spec.EgressGatewayFailureDetection == nil {
		egw.Spec.EgressGatewayFailureDetection = &operatorv1.EgressGatewayFailureDetection{
			HealthPort:             &defaultHealthPort,
			HealthTimeoutDataStore: &defaultHealthTimeoutDS,
			ICMPProbes: &operatorv1.ICMPProbes{IPs: []string{},
				Interval: &defaultIcmpInterval, Timeout: &defaultIcmpTimeout},
			HTTPProbes: &operatorv1.HTTPProbes{URLs: []string{},
				Interval: &defaultHttpInterval, Timeout: &defaultHttpTimeout},
		}
	} else {
		if egw.Spec.EgressGatewayFailureDetection.HealthPort == nil {
			egw.Spec.EgressGatewayFailureDetection.HealthPort = &defaultHealthPort
		}

		if egw.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStore == nil {
			egw.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStore = &defaultHealthTimeoutDS
		}

		if egw.Spec.EgressGatewayFailureDetection.ICMPProbes == nil {
			egw.Spec.EgressGatewayFailureDetection.ICMPProbes = &operatorv1.ICMPProbes{IPs: []string{},
				Interval: &defaultIcmpInterval,
				Timeout:  &defaultIcmpTimeout}
		} else {
			if egw.Spec.EgressGatewayFailureDetection.ICMPProbes.Interval == nil {
				egw.Spec.EgressGatewayFailureDetection.ICMPProbes.Interval = &defaultIcmpInterval
			}
			if egw.Spec.EgressGatewayFailureDetection.ICMPProbes.Timeout == nil {
				egw.Spec.EgressGatewayFailureDetection.ICMPProbes.Timeout = &defaultIcmpTimeout
			}
		}
		if egw.Spec.EgressGatewayFailureDetection.HTTPProbes == nil {
			egw.Spec.EgressGatewayFailureDetection.HTTPProbes = &operatorv1.HTTPProbes{URLs: []string{},
				Interval: &defaultHttpInterval,
				Timeout:  &defaultHttpTimeout}
		} else {
			if egw.Spec.EgressGatewayFailureDetection.HTTPProbes.Interval == nil {
				egw.Spec.EgressGatewayFailureDetection.HTTPProbes.Interval = &defaultHttpInterval
			}
			if egw.Spec.EgressGatewayFailureDetection.HTTPProbes.Timeout == nil {
				egw.Spec.EgressGatewayFailureDetection.HTTPProbes.Timeout = &defaultHttpTimeout
			}
		}
	}
}
