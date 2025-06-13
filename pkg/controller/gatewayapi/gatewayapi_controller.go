// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
)

var log = logf.Log.WithName("controller_gatewayapi")

// Add creates a new GatewayAPI Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
//
// Start Watches within the Add function for any resources that this controller creates or monitors. This will trigger
// calls to Reconcile() when an instance of one of the watched resources is modified.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	r := &ReconcileGatewayAPI{
		client:              mgr.GetClient(),
		scheme:              mgr.GetScheme(),
		provider:            opts.DetectedProvider,
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
		return fmt.Errorf("gatewayapi-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("gatewayapi-controller failed to watch Tigera network resource: %v", err)
	}

	watchedEnvoyProxies := make(map[operatorv1.NamespacedName]struct{})
	r.watchEnvoyProxy = func(namespacedName operatorv1.NamespacedName) error {
		if _, alreadyWatching := watchedEnvoyProxies[namespacedName]; !alreadyWatching {
			if err = utils.AddNamespacedWatch(c, &envoyapi.EnvoyProxy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespacedName.Namespace,
					Name:      namespacedName.Name,
				},
			}, &handler.EnqueueRequestForObject{}); err != nil {
				log.V(5).Info("Failed to create EnvoyProxy watch", "err", err)
				return fmt.Errorf("gatewayapi-controller failed to watch EnvoyProxy resource: %v", err)
			}
			watchedEnvoyProxies[namespacedName] = struct{}{}
		}
		return nil
	}

	watchedEnvoyGateways := make(map[operatorv1.NamespacedName]struct{})
	r.watchEnvoyGateway = func(namespacedName operatorv1.NamespacedName) error {
		if _, alreadyWatching := watchedEnvoyGateways[namespacedName]; !alreadyWatching {
			if err = utils.AddNamespacedWatch(c, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespacedName.Namespace,
					Name:      namespacedName.Name,
				},
			}, &handler.EnqueueRequestForObject{}); err != nil {
				log.V(5).Info("Failed to create EnvoyGateway watch", "err", err)
				return fmt.Errorf("gatewayapi-controller failed to watch EnvoyGateway resource: %v", err)
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
	provider            operatorv1.Provider
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
	reqLogger.Info("Reconciling GatewayAPI")

	// Get the GatewayAPI CR.
	gatewayAPI, msg, err := GetGatewayAPI(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("GatewayAPI object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
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

	if variant == operatorv1.Calico {
		reqLogger.Info("Variant is Calico")
		if unsupportedFields := checkEnterpriseOnlyFields(gatewayAPI); len(unsupportedFields) > 0 {
			err = fmt.Errorf("unsupported fields are %v", strings.Join(unsupportedFields, ","))
			r.status.SetDegraded(
				operatorv1.InvalidConfigurationError,
				"GatewayAPI is using fields that are only supported in Calico Enterprise",
				err,
				reqLogger,
			)
			return reconcile.Result{}, err
		}
	}

	// Render CRDs.  Note, we do this as early as possible so as to enable the following
	// controller code that reads GatewayClasses and EnvoyProxies (which depends on the CRDs
	// already existing).  For the CRDs we specify nil for the owning CR - i.e. no ownership -
	// so that the CRDs are left in place even if the GatewayAPI CR is removed again.  This is
	// in case the customer uses a second (or more) implementation of the Gateway API in
	// addition to the one that we are providing here.
	crdComponent := render.NewPassthrough(render.GatewayAPICRDs(log)...)
	handler := r.newComponentHandler(log, r.client, r.scheme, nil)
	if gatewayAPI.Spec.CRDManagement == nil || *gatewayAPI.Spec.CRDManagement == operatorv1.CRDManagementPreferExisting {
		handler.SetCreateOnly()
	}
	err = handler.CreateOrUpdateOrDelete(ctx, crdComponent, nil)
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
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering GatewayAPI CRDs", err, log)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	gatewayConfig := &render.GatewayAPIImplementationConfig{
		Installation:          installation,
		PullSecrets:           pullSecrets,
		GatewayAPI:            gatewayAPI,
		CustomEnvoyProxies:    make(map[string]*envoyapi.EnvoyProxy),
		CurrentGatewayClasses: make(map[string]string),
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
			if _, ok := configMap.Data[render.EnvoyGatewayConfigKey]; !ok {
				err = fmt.Errorf("missing '%s' key", render.EnvoyGatewayConfigKey)
			}
		}
		if err == nil {
			gatewayConfig.CustomEnvoyGateway = &envoyapi.EnvoyGateway{}
			err = yaml.Unmarshal([]byte(configMap.Data[render.EnvoyGatewayConfigKey]), gatewayConfig.CustomEnvoyGateway)
		}
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading EnvoyGatewayConfigRef", err, log)
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
			gatewayConfig.CustomEnvoyProxies[gatewayAPI.Spec.GatewayClasses[i].Name] = envoyProxy
		}
	}

	// Enumerate existing GatewayClasses, in case some of them will need to be cleaned up.
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
			gatewayConfig.CurrentGatewayClasses[gcList.Items[i].Name] = gcList.Items[i].Spec.ParametersRef.Name
		}
	}

	// Render non-CRD resources for Gateway API support, i.e. for our specific bundled
	// implementation of the Gateway API.  For these we specify the GatewayAPI CR as the owner,
	// so that they all get automatically cleaned up if the GatewayAPI CR is removed again.
	nonCRDComponent := render.GatewayAPIImplementationComponent(gatewayConfig)
	err = imageset.ApplyImageSet(ctx, r.client, variant, nonCRDComponent)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error with images from ImageSet", err, log)
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

func checkEnterpriseOnlyFields(gatewayAPI *operatorv1.GatewayAPI) (unsupportedFields []string) {
	noteField := func(field string) {
		unsupportedFields = append(unsupportedFields, field)
	}
	if gatewayAPI.Spec.EnvoyGatewayConfigRef != nil {
		noteField("EnvoyGatewayConfigRef")
	}
	if gatewayAPI.Spec.GatewayClasses != nil {
		noteField("GatewayClasses")
	}
	if gatewayAPI.Spec.GatewayDaemonSet != nil {
		noteField("GatewayDaemonSet")
	}
	if gatewayAPI.Spec.GatewayService != nil {
		noteField("GatewayService")
	}
	if gatewayAPI.Spec.GatewayControllerDeployment != nil &&
		gatewayAPI.Spec.GatewayControllerDeployment.Spec != nil {
		if gatewayAPI.Spec.GatewayControllerDeployment.Spec.Replicas != nil {
			noteField("GatewayControllerDeployment.Spec.Replicas")
		}
		if gatewayAPI.Spec.GatewayControllerDeployment.Spec.Template != nil &&
			gatewayAPI.Spec.GatewayControllerDeployment.Spec.Template.Spec != nil &&
			gatewayAPI.Spec.GatewayControllerDeployment.Spec.Template.Spec.TopologySpreadConstraints != nil {
			noteField("GatewayControllerDeployment.Spec.Template.Spec.TopologySpreadConstraints")
		}
	}
	if gatewayAPI.Spec.GatewayDeployment != nil &&
		gatewayAPI.Spec.GatewayDeployment.Spec != nil {
		if gatewayAPI.Spec.GatewayDeployment.Spec.Replicas != nil {
			noteField("GatewayDeployment.Spec.Replicas")
		}
	}
	return
}
