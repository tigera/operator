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
	"github.com/tigera/operator/pkg/components"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		usePSP:          opts.UsePSP,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup.
// Watching namespaced resources must be avoided.
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
	usePSP          bool
}

// Reconcile reads that state of the cluster for an EgressGateway object and makes changes
// based on the state read and what is in the EgressGateway.Spec.
func (r *ReconcileEgressGateway) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling EgressGateway")

	// Wait for right version of the calico to be installed. When upgrading EGWs, calico-node needs to be upgraded
	// first, before proceeding with the EGW upgrade. Hence wait for the right version of calico to be installed.
	installStatus, err := utils.GetInstallationStatus(ctx, r.client)
	if err != nil || installStatus.CalicoVersion != components.EnterpriseRelease {
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// If request name and namespace is not "", getEgressGateways will just return the
	// exact EGW resource. If the namespace is "", getEgressGateways will return all the
	// EGW resources in all namespaces.
	egws, err := getEgressGateways(ctx, r.client, request)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("EgressGateway object not found")
			// Since the EGW resource is not found, remove the deployment.
			r.status.RemoveDeployments(types.NamespacedName{Name: request.Name, Namespace: request.Namespace})
			// Get the cumulative Egress Gateway status. Let's say we have 2 EGW resources red and blue.
			// Red has already degraded. When the user deletes Red, Tigerastatus should go back to available
			// as Blue is healthy. If all the EGWs are ready, clear the degraded Tigerastatus.
			// If at least one of the EGWs is unhealthy, get the degraded msg from the conditions and
			// update the Tigerastatus.
			egws, err := getEgressGateways(ctx, r.client, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ""}})
			if err != nil || len(egws) == 0 {
				r.status.OnCRNotFound()
			}
			status, egw := getCumulativeEgressGatewayStatus(egws)
			if !status {
				r.status.SetDegraded(operatorv1.ResourceNotReady,
					fmt.Sprintf("Error reconciling Egress Gateway resource. Name=%s Namespace=%s", egw.Name, egw.Namespace),
					fmt.Errorf("%s", getDegradedMsg(egw)), reqLogger)
				return reconcile.Result{}, nil
			}
			r.status.ClearDegraded()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "Error querying for Egress Gateway")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for Egress Gateway", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.OnCRFound()

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	variant, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "Installation not found")
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			// Set the EGW resource's condition to Degraded.
			for _, egw := range egws {
				r.setDegraded(ctx, &egw, "Installation not found", err)
			}
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "Error querying installation")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		for _, egw := range egws {
			r.setDegraded(ctx, &egw, "Error querying installation", err)
		}
		return reconcile.Result{}, err
	}

	if variant != operatorv1.TigeraSecureEnterprise {
		reqLogger.Error(err, fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise))
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), nil, reqLogger)
		for _, egw := range egws {
			r.setDegraded(ctx, &egw, fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), nil)
		}
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		reqLogger.Error(err, "Error retrieving pull secrets")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		for _, egw := range egws {
			r.setDegraded(ctx, &egw, "Error retrieving pull secrets", err)
		}
		return reconcile.Result{}, err
	}

	// Fetch any existing default FelixConfiguration object.
	fc := &crdv1.FelixConfiguration{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, fc)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading FelixConfiguration", err, reqLogger)
		for _, egw := range egws {
			r.setDegraded(ctx, &egw, "Error reading felix configuration", err)
		}
		return reconcile.Result{}, err
	}

	// Reconcile all the EGWs
	for _, egw := range egws {
		result, err := r.reconcile(ctx, &egw, reqLogger, variant, fc, pullSecrets, installation)
		if err != nil {
			return result, err
		}
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileEgressGateway) setDegraded(ctx context.Context, egw *operatorv1.EgressGateway, msg string, err error) {
	reconcileErr := "Error_reconciling_Egress_Gateway"
	if err != nil {
		setDegraded(r.client, ctx, egw, reconcileErr, fmt.Sprintf("%s Name = %s, Namespace = %s, err = %s", msg, egw.Name, egw.Namespace, err.Error()))
	} else {
		setDegraded(r.client, ctx, egw, reconcileErr, fmt.Sprintf("%s Name = %s, Namespace = %s", msg, egw.Name, egw.Namespace))
	}
}

func (r *ReconcileEgressGateway) reconcile(ctx context.Context, egw *operatorv1.EgressGateway, reqLogger logr.Logger,
	variant operatorv1.ProductVariant, fc *crdv1.FelixConfiguration, pullSecrets []*v1.Secret,
	installation *operatorv1.InstallationSpec) (reconcile.Result, error) {

	reconcileErr := "Error_reconciling_Egress_Gateway"

	preDefaultPatchFrom := client.MergeFrom(egw.DeepCopy())
	// update the EGW resource with default values.
	fillDefaults(egw, installation)
	// Validate the EGW resource.
	err := validateEgressGateway(ctx, r.client, egw)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("Error validating Egress Gateway Name = %s, Namespace = %s", egw.Name, egw.Namespace))
		r.status.SetDegraded(operatorv1.ResourceValidationError,
			fmt.Sprintf("Error validating egress gateway Name = %s, Namespace = %s", egw.Name, egw.Namespace), err, reqLogger)
		setDegraded(r.client, ctx, egw, reconcileErr,
			fmt.Sprintf("Error validating egress gateway Name = %s, Namespace = %s, err = %s", egw.Name, egw.Namespace, err.Error()))
		return reconcile.Result{}, err
	}

	if err = r.client.Patch(ctx, egw, preDefaultPatchFrom); err != nil {
		reqLogger.Error(err, fmt.Sprintf("Failed to write defaults to egress gateway Name = %s, Namespace = %s", egw.Name, egw.Namespace))
		r.status.SetDegraded(operatorv1.ResourceUpdateError,
			fmt.Sprintf("Failed to write defaults to egress gateway Name = %s, Namespace = %s", egw.Name, egw.Namespace), err, reqLogger)
		setDegraded(r.client, ctx, egw, reconcileErr,
			fmt.Sprintf("Failed to write defaults to egress gateway Name = %s, Namespace = %s, err = %s", egw.Name, egw.Namespace, err.Error()))
		return reconcile.Result{}, err
	}

	// Set the condition to progressing
	setProgressing(r.client, ctx, egw, string(operatorv1.ResourceNotReady), fmt.Sprintf("Name = %s, Namespace = %s", egw.Name, egw.Namespace))

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
		OSType:            rmeta.OSTypeLinux,
		EgressGW:          egw,
		EgressGWVxlanPort: egwVxlanPort,
		EgressGWVxlanVNI:  egwVxlanVNI,
		UsePSP:            r.usePSP,
	}

	component := egressgateway.EgressGateway(config)
	ch := utils.NewComponentHandler(log, r.client, r.scheme, egw)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		setDegraded(r.client, ctx, egw, reconcileErr,
			fmt.Sprintf("Error with images from ImageSet Name = %s, Namespace = %s, err = %s", egw.Name, egw.Namespace, err.Error()))
		return reconcile.Result{}, err
	}

	if err = ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		reqLogger.Error(err, fmt.Sprintf("Error creating / updating resource: Name = %s, Namespace = %s", egw.Name, egw.Namespace))
		r.status.SetDegraded(operatorv1.ResourceUpdateError,
			fmt.Sprintf("Error creating / updating resource: Name = %s, Namespace = %s", egw.Name, egw.Namespace), err, reqLogger)
		setDegraded(r.client, ctx, egw, reconcileErr,
			fmt.Sprintf("Error creating / updating resource Name = %s, Namespace = %s, err = %s", egw.Name, egw.Namespace, err.Error()))
		return reconcile.Result{}, err
	}

	// Update the status of this CR.
	egw.Status.State = operatorv1.TigeraStatusReady
	setAvailable(r.client, ctx, egw, string(operatorv1.AllObjectsAvailable), "All objects available")

	// After the resource is created/updated, Tigerastatus needs to be set by taking the cumulative status of the
	// available EGW resources. Lets say we create 2 EGW resources Red, Blue. Both are degraded. Now lets create 3rd resource
	// yellow. Though yellow is reconciled and rendered successfully, Tigerastatus should still be degraded as Red, Blue are
	// degraded. Now lets assume Blue gets updated and gets rendered properly. In this case, Tigerastatus should still be
	// degraded as Red is unhealthy.
	egws, err := getEgressGateways(ctx, r.client, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ""}})
	if err != nil {
		// Leave the status as it is and return
		return reconcile.Result{}, nil
	}

	// Get the cumulative status of all Egress Gateway resources.
	status, degradedEGW := getCumulativeEgressGatewayStatus(egws)
	if !status && degradedEGW != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError,
			fmt.Sprintf("Error reconciling Egress Gateway resource. Name=%s Namespace=%s", degradedEGW.Name, degradedEGW.Namespace),
			fmt.Errorf("%s", getDegradedMsg(degradedEGW)), reqLogger)
		return reconcile.Result{}, nil
	}

	r.status.ClearDegraded()
	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future, hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
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
	nativeIP := operatorv1.NativeIPDisabled
	if egw.Spec.AWS != nil && egw.Spec.AWS.NativeIP != nil {
		nativeIP = *egw.Spec.AWS.NativeIP
	}

	// Validate IPPools specified.
	// If name is specified, check IPPool exists.
	// If CIDR is specified, check if CIDR matches with any IPPool.
	// If Aws.NativeIP is enabled, check if the IPPool is backed by aws-subnet ID.
	for _, ippool := range egw.Spec.IPPools {
		err := validateIPPool(ctx, cli, ippool, nativeIP)
		if err != nil {
			return err
		}
	}
	// Check if ElasticIPs are specified only if NativeIP is enabled.
	if egw.Spec.AWS != nil {
		if len(egw.Spec.AWS.ElasticIPs) > 0 && (*egw.Spec.AWS.NativeIP == operatorv1.NativeIPDisabled) {
			return fmt.Errorf("NativeIP should be enabled when elastic IPs are used")
		}
	}

	// Check if ICMP and HTTP probe timeout is greater than interval.
	if *egw.Spec.EgressGatewayFailureDetection.ICMPProbes.TimeoutSeconds <
		*egw.Spec.EgressGatewayFailureDetection.ICMPProbes.IntervalSeconds {
		return fmt.Errorf("ICMP probe timeout must be greater than interval")
	}

	if *egw.Spec.EgressGatewayFailureDetection.HTTPProbes.TimeoutSeconds <
		*egw.Spec.EgressGatewayFailureDetection.HTTPProbes.IntervalSeconds {
		return fmt.Errorf("HTTP probe timeout must be greater than interval")
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

// fillDefaults sets the default values of the EGW resource.
func fillDefaults(egw *operatorv1.EgressGateway, installation *operatorv1.InstallationSpec) {
	defaultLogSeverity := operatorv1.LogLevelInfo
	var defaultHealthTimeoutDS int32 = 90
	var defaultIcmpTimeout int32 = 15
	var defaultIcmpInterval int32 = 5
	var defaultHttpTimeout int32 = 30
	var defaultHttpInterval int32 = 10
	defaultAWSNativeIP := operatorv1.NativeIPDisabled

	// Default value of LogSeverity is "Info"
	if egw.Spec.LogSeverity == nil {
		egw.Spec.LogSeverity = &defaultLogSeverity
	}

	// Default value of Native IP is Disabled.
	if egw.Spec.AWS != nil && egw.Spec.AWS.NativeIP == nil {
		egw.Spec.AWS.NativeIP = &defaultAWSNativeIP
	}

	// Set the default values for EGW failure detection spec.
	if egw.Spec.EgressGatewayFailureDetection == nil {
		egw.Spec.EgressGatewayFailureDetection = &operatorv1.EgressGatewayFailureDetection{
			HealthTimeoutDataStoreSeconds: &defaultHealthTimeoutDS,
			ICMPProbes: &operatorv1.ICMPProbes{IPs: []string{},
				IntervalSeconds: &defaultIcmpInterval, TimeoutSeconds: &defaultIcmpTimeout},
			HTTPProbes: &operatorv1.HTTPProbes{URLs: []string{},
				IntervalSeconds: &defaultHttpInterval, TimeoutSeconds: &defaultHttpTimeout},
		}
	} else {
		if egw.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStoreSeconds == nil {
			egw.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStoreSeconds = &defaultHealthTimeoutDS
		}

		if egw.Spec.EgressGatewayFailureDetection.ICMPProbes == nil {
			egw.Spec.EgressGatewayFailureDetection.ICMPProbes = &operatorv1.ICMPProbes{IPs: []string{},
				IntervalSeconds: &defaultIcmpInterval,
				TimeoutSeconds:  &defaultIcmpTimeout}
		} else {
			if egw.Spec.EgressGatewayFailureDetection.ICMPProbes.IntervalSeconds == nil {
				egw.Spec.EgressGatewayFailureDetection.ICMPProbes.IntervalSeconds = &defaultIcmpInterval
			}
			if egw.Spec.EgressGatewayFailureDetection.ICMPProbes.TimeoutSeconds == nil {
				egw.Spec.EgressGatewayFailureDetection.ICMPProbes.TimeoutSeconds = &defaultIcmpTimeout
			}
		}
		if egw.Spec.EgressGatewayFailureDetection.HTTPProbes == nil {
			egw.Spec.EgressGatewayFailureDetection.HTTPProbes = &operatorv1.HTTPProbes{URLs: []string{},
				IntervalSeconds: &defaultHttpInterval,
				TimeoutSeconds:  &defaultHttpTimeout}
		} else {
			if egw.Spec.EgressGatewayFailureDetection.HTTPProbes.IntervalSeconds == nil {
				egw.Spec.EgressGatewayFailureDetection.HTTPProbes.IntervalSeconds = &defaultHttpInterval
			}
			if egw.Spec.EgressGatewayFailureDetection.HTTPProbes.TimeoutSeconds == nil {
				egw.Spec.EgressGatewayFailureDetection.HTTPProbes.TimeoutSeconds = &defaultHttpTimeout
			}
		}
	}

	// set the default label if not specified.
	defLabel := map[string]string{"projectcalico.org/egw": egw.Name}
	if egw.Spec.Template == nil {
		egw.Spec.Template = &operatorv1.EgressGatewayDeploymentPodTemplateSpec{}
		egw.Spec.Template.Metadata = &operatorv1.EgressGatewayMetadata{Labels: defLabel}
	} else {
		if egw.Spec.Template.Metadata == nil {
			egw.Spec.Template.Metadata = &operatorv1.EgressGatewayMetadata{Labels: defLabel}
		} else {
			if len(egw.Spec.Template.Metadata.Labels) > 0 {
				egw.Spec.Template.Metadata.Labels["projectcalico.org/egw"] = egw.Name
			} else {
				egw.Spec.Template.Metadata.Labels = defLabel
			}
		}
	}

	// If affinity isn't specified by the user, default pod anti affinity is added so that 2 EGW pods aren't scheduled in
	// the same node. If the provider is AKS, set the node affinity so that pods don't run on virutal-nodes.
	defAffinity := &v1.Affinity{}
	defAffinity.PodAntiAffinity = &v1.PodAntiAffinity{
		PreferredDuringSchedulingIgnoredDuringExecution: []v1.WeightedPodAffinityTerm{
			{
				Weight: 1,
				PodAffinityTerm: v1.PodAffinityTerm{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: egw.Spec.Template.Metadata.Labels,
					},
					TopologyKey: "topology.kubernetes.io/zone",
				},
			},
		},
	}
	switch installation.KubernetesProvider {
	case operatorv1.ProviderAKS:
		defAffinity.NodeAffinity = &v1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
				NodeSelectorTerms: []v1.NodeSelectorTerm{{
					MatchExpressions: []v1.NodeSelectorRequirement{
						{
							Key:      "type",
							Operator: v1.NodeSelectorOpNotIn,
							Values:   []string{"virtual-node"},
						},
						{
							Key:      "kubernetes.azure.com/cluster",
							Operator: v1.NodeSelectorOpExists,
						},
					},
				}},
			},
		}
	default:
		defAffinity.NodeAffinity = nil
	}

	if egw.Spec.Template.Spec == nil {
		egw.Spec.Template.Spec = &operatorv1.EgressGatewayDeploymentPodSpec{Affinity: defAffinity}
	} else if egw.Spec.Template.Spec.Affinity == nil {
		egw.Spec.Template.Spec.Affinity = defAffinity
	}
}

func validateIPPool(ctx context.Context, cli client.Client, ipPool operatorv1.EgressGatewayIPPool, awsNativeIP operatorv1.NativeIP) error {
	if ipPool.Name != "" {
		instance := &crdv1.IPPool{}
		key := types.NamespacedName{Name: ipPool.Name}
		err := cli.Get(ctx, key, instance)
		if err != nil {
			return err
		}
		if ipPool.CIDR != "" {
			if instance.Spec.CIDR != ipPool.CIDR {
				return fmt.Errorf("IPPool CIDR does not match with name")
			}
		}
		if awsNativeIP == operatorv1.NativeIPEnabled && instance.Spec.AWSSubnetID == "" {
			return fmt.Errorf("AWS subnet ID must be set when NativeIP is enabled")
		}
		return nil
	}
	if ipPool.CIDR != "" {
		instance := &crdv1.IPPoolList{}
		err := cli.List(ctx, instance)
		if err != nil {
			return err
		}
		for _, item := range instance.Items {
			if item.Spec.CIDR == ipPool.CIDR {
				if awsNativeIP == operatorv1.NativeIPEnabled && item.Spec.AWSSubnetID == "" {
					return fmt.Errorf("AWS subnet ID must be set when NativeIP is enabled")
				}
				return nil
			}
		}
	}
	return fmt.Errorf("IPPool matching CIDR = %s not present", ipPool.CIDR)
}

func getCumulativeEgressGatewayStatus(egws []operatorv1.EgressGateway) (bool, *operatorv1.EgressGateway) {
	for _, egw := range egws {
		if egw.Status.State != operatorv1.TigeraStatusReady {
			return false, &egw
		}
	}
	return true, nil
}

func setDegraded(cli client.Client, ctx context.Context, egw *operatorv1.EgressGateway, reason, msg string) {
	updateEgwStatusConditions(cli, ctx, egw, operatorv1.ComponentDegraded, metav1.ConditionTrue, reason, msg, true)
}

func setProgressing(cli client.Client, ctx context.Context, egw *operatorv1.EgressGateway, reason, msg string) {
	updateEgwStatusConditions(cli, ctx, egw, operatorv1.ComponentProgressing, metav1.ConditionTrue, reason, msg, false)
}

func setAvailable(cli client.Client, ctx context.Context, egw *operatorv1.EgressGateway, reason, msg string) {
	updateEgwStatusConditions(cli, ctx, egw, operatorv1.ComponentAvailable, metav1.ConditionTrue, reason, msg, true)
}

func updateEgwStatusConditions(cli client.Client, ctx context.Context, egw *operatorv1.EgressGateway, ctype operatorv1.StatusConditionType, status metav1.ConditionStatus, reason, msg string, updateStatus bool) {
	found := false
	for idx, cond := range egw.Status.Conditions {
		if cond.Type == string(ctype) {
			cond.Status = status
			cond.Reason = reason
			cond.Message = msg
			found = true
		} else {
			cond.Status = metav1.ConditionFalse
			cond.Reason = string(operatorv1.Unknown)
			cond.Message = ""
		}
		cond.LastTransitionTime = metav1.NewTime(time.Now())
		egw.Status.Conditions[idx] = cond
	}
	if !found {
		condition := metav1.Condition{Type: string(ctype), Status: status, Reason: reason, Message: msg, LastTransitionTime: metav1.NewTime(time.Now())}
		egw.Status.Conditions = append(egw.Status.Conditions, condition)
	}
	if updateStatus {
		if err := cli.Status().Update(ctx, egw); err != nil {
			log.WithValues("Name", egw.Name, "Namespace", egw.Namespace, "error", err).Info("Error updating status")
		}
	}
}

func getDegradedMsg(egw *operatorv1.EgressGateway) string {
	for _, cond := range egw.Status.Conditions {
		if cond.Type == string(operatorv1.ComponentDegraded) {
			return cond.Message
		}
	}
	return ""
}
