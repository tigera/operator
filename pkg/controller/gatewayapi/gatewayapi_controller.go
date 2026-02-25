// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package gatewayapi

import (
	"context"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/set"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/gatewayapi"
)

const (
	DefaultPolicySyncPrefix = "/var/run/nodeagent"
)

var log = logf.Log.WithName("controller_gatewayapi")

// Add creates a new GatewayAPI Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
//
// Start Watches within the Add function for any resources that this controller creates or monitors. This will trigger
// calls to Reconcile() when an instance of one of the watched resources is modified.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	r := &ReconcileGatewayAPI{
		client:              mgr.GetClient(),
		scheme:              mgr.GetScheme(),
		enterpriseCRDsExist: opts.EnterpriseCRDExists,
		status:              status.New(mgr.GetClient(), "gatewayapi", opts.KubernetesVersion),
		clusterDomain:       opts.ClusterDomain,
		multiTenant:         opts.MultiTenant,
		newComponentHandler: utils.NewComponentHandler,
	}
	r.status.Run(opts.ShutdownContext)

	c, err := ctrlruntime.NewController("gatewayapi-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create gatewayapi-controller: %w", err)
	}

	// Watch for changes to primary resource GatewayAPI
	err = c.WatchObject(&operatorv1.GatewayAPI{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create GatewayAPI watch", "err", err)
		return fmt.Errorf("gatewayapi-controller failed to watch primary resource: %w", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("gatewayapi-controller failed to watch Tigera network resource: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("gatewayapi-controller failed to create periodic reconcile watch: %w", err)
	}

	watchedEnvoyProxies := make(map[operatorv1.NamespacedName]struct{})
	r.watchEnvoyProxy = func(namespacedName operatorv1.NamespacedName) error {
		if _, alreadyWatching := watchedEnvoyProxies[namespacedName]; !alreadyWatching {
			log.V(1).Info("Adding watch for EnvoyProxy", "namespacedName", namespacedName)
			if err = utils.AddNamespacedWatch(c, &envoyapi.EnvoyProxy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespacedName.Namespace,
					Name:      namespacedName.Name,
				},
			}, &handler.EnqueueRequestForObject{}); err != nil {
				log.V(5).Info("Failed to create EnvoyProxy watch", "err", err)
				return fmt.Errorf("gatewayapi-controller failed to watch EnvoyProxy resource: %w", err)
			}
			watchedEnvoyProxies[namespacedName] = struct{}{}
		}
		return nil
	}

	watchedEnvoyGateways := make(map[operatorv1.NamespacedName]struct{})
	r.watchEnvoyGateway = func(namespacedName operatorv1.NamespacedName) error {
		if _, alreadyWatching := watchedEnvoyGateways[namespacedName]; !alreadyWatching {
			log.V(1).Info("Adding watch for EnvoyGateway ConfigMap", "namespacedName", namespacedName)
			if err = utils.AddNamespacedWatch(c, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespacedName.Namespace,
					Name:      namespacedName.Name,
				},
			}, &handler.EnqueueRequestForObject{}); err != nil {
				log.V(5).Info("Failed to create EnvoyGateway watch", "err", err)
				return fmt.Errorf("gatewayapi-controller failed to watch EnvoyGateway resource: %w", err)
			}
			watchedEnvoyGateways[namespacedName] = struct{}{}
		}
		return nil
	}

	return nil
}

// blank assignment to verify that ReconcileGatewayAPI implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileGatewayAPI{}

// ReconcileGatewayAPI reconciles a GatewayAPI object
type ReconcileGatewayAPI struct {
	client              client.Client
	scheme              *runtime.Scheme
	enterpriseCRDsExist bool
	status              status.StatusManager
	clusterDomain       string
	multiTenant         bool
	newComponentHandler func(log logr.Logger, client client.Client, scheme *runtime.Scheme, cr metav1.Object) utils.ComponentHandler
	watchEnvoyProxy     func(namespacedName operatorv1.NamespacedName) error
	watchEnvoyGateway   func(namespacedName operatorv1.NamespacedName) error
}

// Reconcile reads that state of the cluster for a GatewayAPI object and makes changes based on the state read
// and what is in the GatewayAPI.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileGatewayAPI) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling GatewayAPI")

	// Get the GatewayAPI CR.
	gatewayAPI, msg, err := GetGatewayAPI(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(2).Info("GatewayAPI object not found")
			r.status.OnCRNotFound()
			f, err := r.maintainFinalizer(ctx, nil)
			// If the finalizer is still set, then requeue so we aren't dependent on the periodic reconcile to check and remove the finalizer
			if f {
				return reconcile.Result{RequeueAfter: utils.FinalizerRemovalRetry}, nil
			} else {
				return reconcile.Result{}, err
			}
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for GatewayAPI CR: "+msg, err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&gatewayAPI.ObjectMeta)

	// Get the Installation, for private registry and pull secret config.
	variant, installation, err := utils.GetInstallation(ctx, r.client)
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
		return reconcile.Result{}, nil
	}

	// Render CRDs.  Note, we do this as early as possible so as to enable the following
	// controller code that reads GatewayClasses and EnvoyProxies (which depends on the CRDs
	// already existing).  For the CRDs we specify nil for the owning CR - i.e. no ownership -
	// so that the CRDs are left in place even if the GatewayAPI CR is removed again.  This is
	// in case the customer uses a second (or more) implementation of the Gateway API in
	// addition to the one that we are providing here.
	//
	// OpenShift 4.19+ pre-installs some of the Gateway CRDs, but not all of them, and has a
	// webhook that prevents us from installing the ones that OpenShift is missing.  To work
	// with this we distinguish between "essential" and "optional" CRDs.  The "essential" set
	// must be a subset of those that OpenShift installs and/or allows to be installed, and must
	// also suffice for all of the Gateway-related feature that we consider important as part of
	// Calico; and this controller will report an error and degraded status if any of those do
	// not already exist and cannot be installed.  The "optional" set is everything else that we
	// would ideally install, to provide more options to our users; but this controller will
	// only warn if any of those cannot be installed (and do not already exist).
	essentialCRDs, optionalCRDs := gatewayapi.GatewayAPICRDs(installation.KubernetesProvider)
	handler := r.newComponentHandler(log, r.client, r.scheme, nil)
	if gatewayAPI.Spec.CRDManagement == nil || *gatewayAPI.Spec.CRDManagement == operatorv1.CRDManagementPreferExisting {
		handler.SetCreateOnly()
	}
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewCreationPassthrough(essentialCRDs...), nil)
	if gatewayAPI.Spec.CRDManagement == nil && (err == nil || errors.IsAlreadyExists(err)) {
		// The GatewayAPI CR does not yet have a specified value for its CRDManagement
		// field, and we can now infer a reasonable value.
		if err == nil {
			// None of the CRDs previously existed, and all of them were just created by
			// us.  Therefore, in future we can consider the CRDs as Tigera
			// operator-owned, and reconcile them so as to deliver future updates.
			setting := operatorv1.CRDManagementReconcile
			gatewayAPI.Spec.CRDManagement = &setting
		} else {
			// Some (i.e. at least one) of the CRDs already existed.  Therefore we have
			// to assume that someone or something else is provisioning the CRDs in this
			// cluster, and make sure not to clobber them.
			setting := operatorv1.CRDManagementPreferExisting
			gatewayAPI.Spec.CRDManagement = &setting
		}
		// Patch that value back into the datastore.
		err = r.client.Patch(ctx, &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{
				Name: gatewayAPI.Name,
			},
			Spec: operatorv1.GatewayAPISpec{
				CRDManagement: gatewayAPI.Spec.CRDManagement,
			},
		}, client.MergeFrom(&operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				CRDManagement: nil,
			},
		}))
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to patch CRDManagement field", err, reqLogger)
			return reconcile.Result{}, err
		}
	}
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering essential GatewayAPI CRDs", err, log)
		return reconcile.Result{}, err
	}
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewCreationPassthrough(optionalCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		reqLogger.Info("Could not render all optional GatewayAPI CRDs", "err", err)
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// patch felix config for l7-collector socket path.
	if err = r.patchFelixConfiguration(ctx); err != nil {
		r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching felix configuration", err, reqLogger)
		return reconcile.Result{}, err
	}

	gatewayConfig := &gatewayapi.GatewayAPIImplementationConfig{
		Installation:          installation,
		PullSecrets:           pullSecrets,
		GatewayAPI:            gatewayAPI,
		CustomEnvoyProxies:    make(map[string]*envoyapi.EnvoyProxy),
		CurrentGatewayClasses: set.New[string](),
	}

	if gatewayAPI.Spec.EnvoyGatewayConfigRef != nil {
		if err = r.watchEnvoyGateway(*gatewayAPI.Spec.EnvoyGatewayConfigRef); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error watching EnvoyGatewayConfigRef", err, log)
			return reconcile.Result{}, err
		}
		configMap := &corev1.ConfigMap{}
		err = r.client.Get(
			ctx,
			types.NamespacedName{
				Namespace: gatewayAPI.Spec.EnvoyGatewayConfigRef.Namespace,
				Name:      gatewayAPI.Spec.EnvoyGatewayConfigRef.Name,
			},
			configMap,
		)
		if err == nil {
			if _, ok := configMap.Data[gatewayapi.EnvoyGatewayConfigKey]; !ok {
				err = fmt.Errorf("missing '%s' key", gatewayapi.EnvoyGatewayConfigKey)
			}
		}
		if err == nil {
			gatewayConfig.CustomEnvoyGateway = &envoyapi.EnvoyGateway{}
			err = yaml.Unmarshal([]byte(configMap.Data[gatewayapi.EnvoyGatewayConfigKey]), gatewayConfig.CustomEnvoyGateway)
		}
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading EnvoyGatewayConfigRef", err, log)
			return reconcile.Result{}, err
		}
	}

	if gatewayAPI.Spec.GatewayClasses == nil {
		// Write back the default setup, which is to create a class named
		// "tigera-gateway-class" without any customizations.
		gatewayAPI.Spec.GatewayClasses = []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}}

		// Patch that back into the datastore.
		err = r.client.Patch(ctx, &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{
				Name: gatewayAPI.Name,
			},
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: gatewayAPI.Spec.GatewayClasses,
			},
		}, client.MergeFrom(&operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: nil,
			},
		}))
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to patch GatewayClasses field", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	for i := range gatewayAPI.Spec.GatewayClasses {
		if gatewayAPI.Spec.GatewayClasses[i].EnvoyProxyRef != nil {
			if err = r.watchEnvoyProxy(*gatewayAPI.Spec.GatewayClasses[i].EnvoyProxyRef); err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Error watching EnvoyProxyRef", err, log)
				return reconcile.Result{}, err
			}
			envoyProxy := &envoyapi.EnvoyProxy{}
			err = r.client.Get(ctx, types.NamespacedName{
				Namespace: gatewayAPI.Spec.GatewayClasses[i].EnvoyProxyRef.Namespace,
				Name:      gatewayAPI.Spec.GatewayClasses[i].EnvoyProxyRef.Name,
			}, envoyProxy)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading EnvoyProxyRef", err, log)
				return reconcile.Result{}, err
			}
			if gatewayAPI.Spec.GatewayClasses[i].GatewayKind != nil &&
				envoyProxy.Spec.Provider != nil &&
				envoyProxy.Spec.Provider.Kubernetes != nil {
				if *gatewayAPI.Spec.GatewayClasses[i].GatewayKind == operatorv1.GatewayKindDaemonSet &&
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment != nil {
					err = fmt.Errorf(
						"GatewayKind (for class '%v') cannot be 'DaemonSet' when EnvoyProxyRef already indicates "+
							"that gateways will be provisioned as a Deployment",
						gatewayAPI.Spec.GatewayClasses[i].Name,
					)
					r.status.SetDegraded(operatorv1.ResourceReadError, "Conflict between EnvoyProxyRef and GatewayKind", err, log)
					return reconcile.Result{}, err
				}
				if *gatewayAPI.Spec.GatewayClasses[i].GatewayKind == operatorv1.GatewayKindDeployment &&
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet != nil {
					err = fmt.Errorf(
						"GatewayKind (for class '%v') cannot be 'Deployment' when EnvoyProxyRef already indicates "+
							"that gateways will be provisioned as a DaemonSet",
						gatewayAPI.Spec.GatewayClasses[i].Name,
					)
					r.status.SetDegraded(operatorv1.ResourceReadError, "Conflict between EnvoyProxyRef and GatewayKind", err, log)
					return reconcile.Result{}, err
				}
			}
			gatewayConfig.CustomEnvoyProxies[gatewayAPI.Spec.GatewayClasses[i].Name] = envoyProxy
		}
	}

	// Enumerate existing GatewayClasses, in case some of them will need to be cleaned up.
	// Note, this is referring to scenarios where the GatewayAPI CR continues to exist but its
	// GatewayClasses field is updated so as to configure the provision of new custom gateway
	// classes.  If the configuration for a previously named gateway class is removed, it is
	// assumed that the corresponding GatewayClass and its EnvoyProxy are no longer wanted, and
	// so should be cleaned up.
	var gcList gapi.GatewayClassList
	err = r.client.List(ctx, &gcList)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading GatewayClasses", err, log)
		return reconcile.Result{}, err
	}
	for i := range gcList.Items {
		operatorOwned, err := controllerutil.HasOwnerReference(gcList.Items[i].GetOwnerReferences(), gatewayAPI, r.scheme)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading GatewayClass owner references", err, log)
			return reconcile.Result{}, err
		}
		if operatorOwned {
			gatewayConfig.CurrentGatewayClasses.Insert(gcList.Items[i].Name)
		}
	}

	// Render non-CRD resources for Gateway API support, i.e. for our specific bundled
	// implementation of the Gateway API.  For these we specify the GatewayAPI CR as the owner,
	// so that they all get automatically cleaned up if the GatewayAPI CR is removed again.
	nonCRDComponent := gatewayapi.GatewayAPIImplementationComponent(gatewayConfig)
	err = imageset.ApplyImageSet(ctx, r.client, variant, nonCRDComponent)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error with images from ImageSet", err, log)
		return reconcile.Result{}, err
	}

	if _, err := r.maintainFinalizer(ctx, gatewayAPI); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error setting finalizer on Installation", err, log)
		return reconcile.Result{}, err
	}

	err = r.newComponentHandler(log, r.client, r.scheme, gatewayAPI).CreateOrUpdateOrDelete(ctx, nonCRDComponent, r.status)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering GatewayAPI resources", err, log)
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	// Update the status of the GatewayAPI instance and StatusManager.
	return reconcile.Result{}, nil
}

// GetGatewayAPI finds the correct GatewayAPI resource and returns a message and error in the case of an error.
func GetGatewayAPI(ctx context.Context, client client.Client) (*operatorv1.GatewayAPI, string, error) {
	// Fetch the GatewayAPI resource.  Look for "default" first.
	resource := &operatorv1.GatewayAPI{}
	err := client.Get(ctx, utils.DefaultInstanceKey, resource)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, "failed to get GatewayAPI 'default'", err
		}

		// Default resource doesn't exist. Check for the legacy (enterprise only) CR.
		err = client.Get(ctx, utils.DefaultTSEEInstanceKey, resource)
		if err != nil {
			return nil, "failed to get GatewayAPI 'tigera-secure'", err
		}
	} else {
		// Assert there is no legacy "tigera-secure" resource present.
		err = client.Get(ctx, utils.DefaultTSEEInstanceKey, resource)
		if err == nil {
			return nil,
				"Duplicate configuration detected",
				fmt.Errorf("multiple GatewayAPI CRs provided. To fix, run \"kubectl delete gatewayapi tigera-secure\"")
		}
	}
	return resource, "", nil
}

// patchFelixConfiguration patches the FelixConfiguration resource with the desired policy sync path prefix.
func (r *ReconcileGatewayAPI) patchFelixConfiguration(ctx context.Context) error {
	_, err := utils.PatchFelixConfiguration(ctx, r.client, func(fc *v3.FelixConfiguration) (bool, error) {
		policySyncPrefix := r.getPolicySyncPathPrefix(&fc.Spec)
		policySyncPrefixSetDesired := DefaultPolicySyncPrefix == policySyncPrefix

		if !policySyncPrefixSetDesired && policySyncPrefix != "" {
			return false, nil
		}

		fc.Spec.PolicySyncPathPrefix = DefaultPolicySyncPrefix

		log.Info(
			"Patching FelixConfiguration: ",
			"policySyncPathPrefix", fc.Spec.PolicySyncPathPrefix,
		)
		return true, nil
	})

	return err
}

func (r *ReconcileGatewayAPI) getPolicySyncPathPrefix(fcSpec *v3.FelixConfigurationSpec) string {
	// Respect existing policySyncPathPrefix if it's already set (e.g. EGW)
	// This will cause policySyncPathPrefix value to remain when ApplicationLayer is disabled.
	existing := fcSpec.PolicySyncPathPrefix
	if existing != "" {
		return existing
	}

	return DefaultPolicySyncPrefix
}

// maintainFinalizer manages this controller's finalizer on the Installation resource.
// We add a finalizer to the Installation when the API server has been installed, and only remove that finalizer when
// the API server has been deleted and its pods have stopped running. This allows for a graceful cleanup of API server resources
// prior to the CNI plugin being removed.
// The bool return value indicates if the finalizer is Set
func (r *ReconcileGatewayAPI) maintainFinalizer(ctx context.Context, gatewayAPI client.Object) (bool, error) {
	// These objects require graceful termination before the CNI plugin is torn down.
	gatewayAPIDeployment := v1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}}
	return utils.MaintainInstallationFinalizer(ctx, r.client, gatewayAPI, render.GatewayAPIFinalizer, &gatewayAPIDeployment)
}
