// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	configv1 "github.com/openshift/api/config/v1"

	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_installation")
var openshiftNetworkConfig = "cluster"

// Add creates a new Installation Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, provider operator.Provider, tsee bool) error {
	return add(mgr, newReconciler(mgr, provider, tsee))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operator.Provider, tsee bool) *ReconcileInstallation {
	r := &ReconcileInstallation{
		config:       mgr.GetConfig(),
		client:       mgr.GetClient(),
		scheme:       mgr.GetScheme(),
		watches:      make(map[runtime.Object]struct{}),
		provider:     provider,
		status:       status.New(mgr.GetClient(), "network"),
		requiresTSEE: tsee,
	}
	r.status.Run()
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r *ReconcileInstallation) error {
	// Create a new controller
	c, err := controller.New("tigera-installation-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create tigera-installation-controller: %v", err)
	}

	r.controller = c

	// Watch for changes to primary resource Installation
	err = c.Watch(&source.Kind{Type: &operator.Installation{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %v", err)
	}

	if r.provider == operator.ProviderOpenShift {
		// Watch for openshift network configuration as well. If we're running in OpenShift, we need to
		// merge this configuration with our own and the write back the status object.
		err = c.Watch(&source.Kind{Type: &configv1.Network{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("tigera-installation-controller failed to watch openshift network config: %v", err)
			}
		}
	}

	// Watch for secrets in the operator namespace. We watch for all secrets, since we care
	// about specifically named ones - e.g., manager-tls, as well as image pull secrets that
	// may have been provided by the user with arbitrary names.
	err = utils.AddSecretsWatch(c, "", render.OperatorNamespace())
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch secrets: %v", err)
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
				return e.MetaOld.GetGeneration() != e.MetaNew.GetGeneration()
			},
		}
		err = c.Watch(&source.Kind{Type: t}, &handler.EnqueueRequestForOwner{
			IsController: true,
			OwnerType:    &operator.Installation{},
		}, pred)
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch %s: %v", t, err)
		}
	}

	return nil
}

// secondaryResources returns a list of the secondary resources that this controller
// monitors for changes. Add resources here which correspond to the resources created by
// this controller.
func secondaryResources() []runtime.Object {
	return []runtime.Object{
		&apps.DaemonSet{},
		&rbacv1.ClusterRole{},
		&rbacv1.ClusterRoleBinding{},
		&corev1.ServiceAccount{},
		&v1beta1.APIService{},
		&corev1.Service{},
	}
}

var _ reconcile.Reconciler = &ReconcileInstallation{}

// ReconcileInstallation reconciles a Installation object
type ReconcileInstallation struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	config       *rest.Config
	client       client.Client
	scheme       *runtime.Scheme
	controller   controller.Controller
	watches      map[runtime.Object]struct{}
	provider     operator.Provider
	status       *status.StatusManager
	requiresTSEE bool
}

// GetInstallation returns the default installation instance with defaults populated.
func GetInstallation(ctx context.Context, client client.Client, provider operator.Provider) (*operator.Installation, error) {
	// Fetch the Installation instance. We only support a single instance named "default".
	instance := &operator.Installation{}
	err := client.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	// Populate the instance with defaults for any fields not provided by the user.
	fillDefaults(instance, provider)
	return instance, nil
}

// Reconcile reads that state of the cluster for a Installation object and makes changes based on the state read
// and what is in the Installation.Spec. The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileInstallation) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling Installation.operator.tigera.io")

	ctx := context.Background()

	// Query for the installation object.
	instance, err := GetInstallation(ctx, r.client, r.provider)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// The operator supports running in a "Calico only" mode so that it doesn't need to run TSEE specific controllers.
	// If we are switching from this mode to one that enables TSEE, we need to restart the operator to enable the other controllers.
	if !r.requiresTSEE && instance.Spec.Variant == operator.TigeraSecureEnterprise {
		// Perform an API discovery to determine if the necessary APIs exist. If they do, we can reboot into TSEE mode.
		// if they do not, we need to notify the user that the requested configuration is invalid.
		b, err := utils.RequiresTigeraSecure(r.config)
		if b {
			log.Info("Rebooting to enable TigeraSecure controllers")
			os.Exit(0)
		} else if err != nil {
			r.status.SetDegraded("Error discovering Tigera Secure availability", err.Error())
		} else {
			r.status.SetDegraded("Cannot deploy Tigera Secure", "Missing Tigera Secure custom resource definitions")
		}

		// Queue a retry. We don't want to watch the APIServer API since it might not exist and would cause
		// this controller to fail.
		reqLogger.Info("Scheduling a retry in 30 seconds")
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// convert specified and detected settings into render configuration.
	provider, netConf, err := GenerateRenderConfig(r.provider, instance)
	if err != nil {
		r.status.SetDegraded("Invalid settings", err.Error())
		return reconcile.Result{}, err
	}

	openshiftConfig := &configv1.Network{}
	if provider == operator.ProviderOpenShift {
		// If configured to run in openshift, then also fetch the openshift configuration API.
		reqLogger.V(1).Info("Querying for openshift network config")
		err = r.client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig)
		if err != nil {
			// Error reading the object - requeue the request.
			r.status.SetDegraded("Unable to read openshift network configuration", err.Error())
			return reconcile.Result{}, err
		}

		// Use the openshift provided CIDRs.
		instance.Spec.IPPools = []operator.IPPool{}
		for _, net := range openshiftConfig.Spec.ClusterNetwork {
			instance.Spec.IPPools = append(instance.Spec.IPPools, operator.IPPool{CIDR: net.CIDR})
		}
	}

	// Validate the configuration.
	if err = validateCustomResource(instance); err != nil {
		r.status.SetDegraded("Error validating CRD", err.Error())
		return reconcile.Result{}, err
	}

	// Query for pull secrets in operator namespace
	pullSecrets, err := utils.GetNetworkingPullSecrets(instance, r.client)
	if err != nil {
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	caConfigMap, typhaSecrets, err := r.GetTyphaFelixTLSConfig()
	if err != nil {
		log.Error(err, "Error with Typha/Felix secrets")
		r.status.SetDegraded("Error with Typha/Felix secrets", err.Error())
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered components.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired Calico components based on our configuration and then
	// create or update them.
	calico, err := render.Calico(
		instance,
		pullSecrets,
		caConfigMap,
		typhaSecrets,
		provider,
		netConf,
	)
	if err != nil {
		log.Error(err, "Error with rendering Calico")
		r.status.SetDegraded("Error with rendering Calico resources", err.Error())
		return reconcile.Result{}, err
	}

	for _, component := range calico.Render() {
		if err := handler.CreateOrUpdate(ctx, component, nil); err != nil {
			r.status.SetDegraded("Error creating / updating resource", err.Error())
			return reconcile.Result{}, err
		}
	}

	// TODO: We handle too many components in this controller at the moment. Once we are done consolidating,
	// we can have the CreateOrUpdate logic handle this for us.
	r.status.SetDaemonsets([]types.NamespacedName{{Name: "calico-node", Namespace: "calico-system"}})
	r.status.SetDeployments([]types.NamespacedName{{Name: "calico-kube-controllers", Namespace: "calico-system"}})

	// We have successfully reconciled the Calico installation.
	if provider == operator.ProviderOpenShift {
		// If configured to run in openshift, update the config status with the current state.
		reqLogger.V(1).Info("Updating openshift cluster network status")
		openshiftConfig.Status.ClusterNetwork = openshiftConfig.Spec.ClusterNetwork
		openshiftConfig.Status.ServiceNetwork = openshiftConfig.Spec.ServiceNetwork
		openshiftConfig.Status.ClusterNetworkMTU = 1440
		openshiftConfig.Status.NetworkType = "Calico"
		if err = r.client.Update(ctx, openshiftConfig); err != nil {
			r.status.SetDegraded("Error updating openshift network status", err.Error())
			return reconcile.Result{}, err
		}
	}

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CRD status.
	instance.Status.Variant = instance.Spec.Variant
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}

	// Created successfully - don't requeue
	reqLogger.V(1).Info("Finished reconciling network installation")
	return reconcile.Result{}, nil
}

// GenerateRenderConfig converts user input and detected settings into render config.
func GenerateRenderConfig(provider operator.Provider, install *operator.Installation) (
	operator.Provider, render.NetworkConfig, error) {

	// if we detected one provider but user set Provider to something else, throw an error
	if provider != operator.ProviderNone &&
		install.Spec.KubernetesProvider != "" &&
		install.Spec.KubernetesProvider != provider {
		return operator.ProviderNone, render.NetworkConfig{},
			fmt.Errorf("Can't specify provider '%s' with %s", install.Spec.KubernetesProvider, provider)
	}

	if provider == operator.ProviderOpenShift {
		return provider,
			render.NetworkConfig{
				CNI: render.CNICalico,
			}, nil
	}

	if provider == operator.ProviderDockerEE {
		return provider,
			render.NetworkConfig{
				CNI:                  render.CNICalico,
				NodenameFileOptional: true,
			}, nil
	}

	if install.Spec.KubernetesProvider == operator.ProviderEKS {
		return operator.ProviderEKS,
			render.NetworkConfig{
				CNI: render.CNINone,
			}, nil
	}

	// default to Calico CNI
	return operator.ProviderNone,
		render.NetworkConfig{
			CNI: render.CNICalico,
		}, nil
}

// GetTyphaFelixTLSConfig reads and validates the CA ConfigMap and Secrets for
// Typha and Felix configuration. It returns the validated resources or error
// if there was one.
func (r *ReconcileInstallation) GetTyphaFelixTLSConfig() (*corev1.ConfigMap, []*corev1.Secret, error) {
	// accumulate all the error messages so all problems with the certs
	// and CA are reported.
	errMsgs := []string{}
	ca, err := r.validateTyphaCAConfigMap()
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CA for Typha is invalid: %s", err))
	}

	secrets := []*corev1.Secret{}
	felix, err := utils.ValidateCertPair(
		r.client,
		render.FelixTLSSecretName,
		render.TLSSecretKeyName,
		render.TLSSecretCertName,
	)
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Felix is invalid: %s", err))
	} else if felix != nil {
		secrets = append(secrets, felix)
		if felix.Data != nil {
			// We need the CommonName, URISAN, or both to be set
			_, okCN := felix.Data[render.CommonName]
			_, okUS := felix.Data[render.URISAN]
			if !(okCN || okUS) {
				errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Felix does not contain common-name or uri-san: %v", felix))
			}
		}
	}

	typha, err := utils.ValidateCertPair(
		r.client,
		render.TyphaTLSSecretName,
		render.TLSSecretKeyName,
		render.TLSSecretCertName,
	)
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Typha is invalid: %s", err))
	} else if typha != nil {
		secrets = append(secrets, typha)
		if typha.Data != nil {
			// We need the CommonName, URISAN, or both to be set
			_, okCN := typha.Data[render.CommonName]
			_, okUS := typha.Data[render.URISAN]
			if !(okCN || okUS) {
				errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Typha does not contain common-name or uri-san: %v", typha))
			}
		}
	}

	// CA, typha, and felix are all not set
	allNil := (ca == nil && typha == nil && felix == nil)
	// CA, typha, and felix are all are set
	allSet := (ca != nil && typha != nil && felix != nil)
	// All CA, typha, and felix must be set or not set.
	if !(allNil || allSet) {
		errMsgs = append(errMsgs, fmt.Sprintf("Typha-Felix CA and Secrets should all be set or none set: ca(%v) typha(%v) felix(%v)", ca, typha, felix))
		errMsgs = append(errMsgs, "If not providing custom CA and certs, feel free to remove them from the operator namespace, they will be recreated")
	}

	// TODO: We could make sure both TLS Secrets were signed by the CA

	if len(errMsgs) != 0 {
		return nil, nil, fmt.Errorf(strings.Join(errMsgs, ";"))
	}
	return ca, secrets, nil
}

// validateTyphaCAConfigMap reads the Typha CA config map from the Operator
// namespace and validates that it has a CA Bundle. It returns the validated
// ConfigMap or an error.
func (r *ReconcileInstallation) validateTyphaCAConfigMap() (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      render.TyphaCAConfigMapName,
		Namespace: render.OperatorNamespace(),
	}
	err := r.client.Get(context.Background(), cmNamespacedName, cm)
	if err != nil {
		// If the reason for the error is not found then that is acceptable
		// so return valid in that case.
		statErr, ok := err.(*apierrors.StatusError)
		if ok && statErr.ErrStatus.Reason == metav1.StatusReasonNotFound {
			return nil, nil
		} else {
			return nil, fmt.Errorf("Failed to read configmap %q from datastore: %s", render.TyphaCAConfigMapName, err)
		}
	}

	if val, ok := cm.Data[render.TyphaCABundleName]; !ok || len(val) == 0 {
		return nil, fmt.Errorf("ConfigMap %q does not have a field named %q", render.TyphaCAConfigMapName, render.TyphaCABundleName)
	}

	return cm, nil
}
