// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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
	"log"
	"net"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	operatorv1beta1 "github.com/tigera/operator/pkg/apis/operator/v1beta1"
	"github.com/tigera/operator/pkg/controller/migration"
	"github.com/tigera/operator/pkg/controller/migration/parser"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/go-logr/logr"
	apps "k8s.io/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var openshiftNetworkConfig = "cluster"

// Add creates a new Installation Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	ri, err := newReconciler(mgr, opts)
	if err != nil {
		return fmt.Errorf("failed to create Core Reconciler: %v", err)
	}
	return add(mgr, ri)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) (*ReconcileInstallation, error) {
	nm, err := migration.NewCoreNamespaceMigration(mgr.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize Namespace migration: %v", err)
	}
	r := &ReconcileInstallation{
		config:               mgr.GetConfig(),
		client:               mgr.GetClient(),
		scheme:               mgr.GetScheme(),
		watches:              make(map[runtime.Object]struct{}),
		autoDetectedProvider: opts.DetectedProvider,
		status:               status.New(mgr.GetClient(), "calico"),
		typhaAutoscaler:      newTyphaAutoscaler(mgr.GetClient()),
		namespaceMigration:   nm,
		amazonCRDExists:      opts.AmazonCRDExists,
		enterpriseCRDsExist:  opts.EnterpriseCRDExists,
	}
	r.status.Run()
	r.typhaAutoscaler.run()
	return r, nil
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

	if r.autoDetectedProvider == operator.ProviderOpenShift {
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

	cm := render.BirdTemplatesConfigMapName
	if err = utils.AddConfigMapWatch(c, cm, render.OperatorNamespace()); err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch ConfigMap %s: %v", cm, err)
	}

	// Only watch the AmazonCloudIntegration if the CRD is available
	if r.amazonCRDExists {
		err = c.Watch(&source.Kind{Type: &operatorv1beta1.AmazonCloudIntegration{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			log.Printf("Failed to create AmazonCloudIntegration watch", "err", err)
			return fmt.Errorf("amazoncloudintegration-controller failed to watch primary resource: %v", err)
		}
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
	config               *rest.Config
	client               client.Client
	scheme               *runtime.Scheme
	controller           controller.Controller
	watches              map[runtime.Object]struct{}
	autoDetectedProvider operator.Provider
	status               status.StatusManager
	typhaAutoscaler      *typhaAutoscaler
	namespaceMigration   *migration.CoreNamespaceMigration
	enterpriseCRDsExist  bool
	amazonCRDExists      bool
}

// GetInstallation returns the default installation instance with defaults populated.
func GetInstallation(ctx context.Context, client client.Client, provider operator.Provider) (*operator.Installation, error) {
	// Fetch the Installation instance. We only support a single instance named "default".
	instance := &operator.Installation{}
	err := client.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	// Determine the provider in use by combining any auto-detected value with any value
	// specified in the Installation CR. mergeProvider updates the CR with the correct value.
	err = mergeProvider(instance, provider)
	if err != nil {
		return nil, err
	}

	var openshiftConfig *configv1.Network
	var kubeadmConfig *v1.ConfigMap
	if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
		openshiftConfig = &configv1.Network{}
		// If configured to run in openshift, then also fetch the openshift configuration API.
		err = client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig)
		if err != nil {
			return nil, fmt.Errorf("Unable to read openshift network configuration: %s", err.Error())
		}
	} else {
		// Check if we're running on kubeadm by getting the config map.
		kubeadmConfig = &v1.ConfigMap{}
		key := types.NamespacedName{Name: kubeadmConfigMap, Namespace: metav1.NamespaceSystem}
		err = client.Get(ctx, key, kubeadmConfig)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("Unable to read kubeadm config map: %s", err.Error())
			}
			kubeadmConfig = nil
		}
	}

	ei, err := parser.GetExistingInstallation(ctx, client)
	if err != nil {
		return nil, err
	}

	err = mergeAndFillDefaults(instance, openshiftConfig, kubeadmConfig, ei)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// mergeAndFillDefaults merges in configuration from the Kubernetes provider, if applicable, and then
// populates defaults in the Installation instance.
func mergeAndFillDefaults(i *operator.Installation, o *configv1.Network, kubeadmConfig *v1.ConfigMap, ei *parser.Config) error {
	if ei != nil {
		// Merge in Existing configuration
		if err := updateInstallationForExistingInstall(i, ei); err != nil {
			return fmt.Errorf("Could not migrate existing config: %w", err)
		}
	} else if o != nil {
		// Merge in OpenShift configuration.
		if err := updateInstallationForOpenshiftNetwork(i, o); err != nil {
			return fmt.Errorf("Could not resolve CalicoNetwork IPPool and OpenShift network: %s", err.Error())
		}
	} else if kubeadmConfig != nil {
		// Merge in kubeadm configuraiton.
		if err := updateInstallationForKubeadm(i, kubeadmConfig); err != nil {
			return fmt.Errorf("Could not resolve CalicoNetwork IPPool and kubeadm configuration: %s", err.Error())
		}
	}

	return fillDefaults(i)
}

// fillDefaults populates the default values onto an Installation object.
func fillDefaults(instance *operator.Installation) error {
	// Populate the instance with defaults for any fields not provided by the user.
	if len(instance.Spec.Registry) != 0 && !strings.HasSuffix(instance.Spec.Registry, "/") {
		// Make sure registry always ends with a slash.
		instance.Spec.Registry = fmt.Sprintf("%s/", instance.Spec.Registry)
	}

	if len(instance.Spec.Variant) == 0 {
		// Default to installing Calico.
		instance.Spec.Variant = operator.Calico
	}

	// Based on the Kubernetes provider, we may or may not need to default to using Calico networking.
	// For managed clouds, we use the cloud provided networking. For other platforms, use Calico networking.
	switch instance.Spec.KubernetesProvider {
	case operator.ProviderAKS, operator.ProviderEKS, operator.ProviderGKE:
		if instance.Spec.CalicoNetwork != nil {
			// For these platforms, it's an error to have CalicoNetwork set.
			msg := "Installation spec.calicoNetwork must not be set for provider %s"
			return fmt.Errorf(msg, instance.Spec.KubernetesProvider)
		}
	default:
		if instance.Spec.CalicoNetwork == nil {
			// For all other platforms, default to using Calico networking.
			instance.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
		}
	}

	var v4pool, v6pool *operator.IPPool

	// If Calico networking is in use, then default some fields.
	if instance.Spec.CalicoNetwork != nil {
		// Default IP pools, only if it is nil.
		// If it is an empty slice then that means no default IPPools
		// should be created.
		if instance.Spec.CalicoNetwork.IPPools == nil {
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				operator.IPPool{CIDR: "192.168.0.0/16"},
			}
		}

		v4pool = render.GetIPv4Pool(instance.Spec.CalicoNetwork)
		v6pool = render.GetIPv6Pool(instance.Spec.CalicoNetwork)

		if v4pool != nil {
			if v4pool.Encapsulation == "" {
				v4pool.Encapsulation = operator.EncapsulationDefault
			}
			if v4pool.NATOutgoing == "" {
				v4pool.NATOutgoing = operator.NATOutgoingEnabled
			}
			if v4pool.NodeSelector == "" {
				v4pool.NodeSelector = operator.NodeSelectorDefault
			}
			if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 == nil {
				// Default IPv4 address detection to "first found" if not specified.
				t := true
				instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
					FirstFound: &t,
				}
			}
			if v4pool.BlockSize == nil {
				var twentySix int32 = 26
				v4pool.BlockSize = &twentySix
			}
		}

		if v6pool != nil {
			if v6pool.Encapsulation == "" {
				v6pool.Encapsulation = operator.EncapsulationNone
			}
			if v6pool.NATOutgoing == "" {
				v6pool.NATOutgoing = operator.NATOutgoingDisabled
			}
			if v6pool.NodeSelector == "" {
				v6pool.NodeSelector = operator.NodeSelectorDefault
			}
			if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 == nil {
				// Default IPv6 address detection to "first found" if not specified.
				t := true
				instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 = &operator.NodeAddressAutodetection{
					FirstFound: &t,
				}
			}
			if v6pool.BlockSize == nil {
				var oneTwentyTwo int32 = 122
				v6pool.BlockSize = &oneTwentyTwo
			}
		}

		if instance.Spec.CalicoNetwork.HostPorts == nil {
			hp := operator.HostPortsEnabled
			instance.Spec.CalicoNetwork.HostPorts = &hp
		}

		if instance.Spec.CalicoNetwork.MultiInterfaceMode == nil {
			mm := operator.MultiInterfaceModeNone
			instance.Spec.CalicoNetwork.MultiInterfaceMode = &mm
		}
	}

	// If not specified by the user, set the flex volume plugin location based on platform.
	if len(instance.Spec.FlexVolumePath) == 0 {
		if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
			// In OpenShift 4.x, the location for flexvolume plugins has changed.
			// See: https://bugzilla.redhat.com/show_bug.cgi?id=1667606#c5
			instance.Spec.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
		} else if instance.Spec.KubernetesProvider == operator.ProviderGKE {
			instance.Spec.FlexVolumePath = "/home/kubernetes/flexvolume/"
		} else if instance.Spec.KubernetesProvider == operator.ProviderAKS {
			instance.Spec.FlexVolumePath = "/etc/kubernetes/volumeplugins/"
		} else {
			instance.Spec.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		}
	}

	instance.Spec.NodeUpdateStrategy.Type = appsv1.RollingUpdateDaemonSetStrategyType

	var one = intstr.FromInt(1)

	if instance.Spec.NodeUpdateStrategy.RollingUpdate == nil {
		instance.Spec.NodeUpdateStrategy.RollingUpdate = &apps.RollingUpdateDaemonSet{
			MaxUnavailable: &one,
		}
	} else if instance.Spec.NodeUpdateStrategy.RollingUpdate.MaxUnavailable == nil {
		instance.Spec.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &one
	}

	return nil
}

// mergeProvider determines the correct provider based on the auto-detected value, and the user-provided one,
// and updates the Installation CR accordingly. It returns an error if incompatible values are provided.
func mergeProvider(cr *operator.Installation, provider operator.Provider) error {
	// If we detected one provider but user set provider to something else, throw an error
	if provider != operator.ProviderNone && cr.Spec.KubernetesProvider != operator.ProviderNone && cr.Spec.KubernetesProvider != provider {
		msg := "Installation spec.kubernetesProvider '%s' does not match auto-detected value '%s'"
		return fmt.Errorf(msg, cr.Spec.KubernetesProvider, provider)
	}

	// If we've reached this point, it means only one source of provider is being used - auto-detection or
	// user-provided, but not both. Or, it means that both have been specified but are the same.
	// If it's the CR provided one, then just use that. Otherwise, use the auto-detected one.
	if cr.Spec.KubernetesProvider == operator.ProviderNone {
		cr.Spec.KubernetesProvider = provider
	}
	log.WithValues("provider", cr.Spec.KubernetesProvider).V(1).Info("Determined provider")
	return nil
}

// Reconcile reads that state of the cluster for a Installation object and makes changes based on the state read
// and what is in the Installation.Spec. The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileInstallation) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling Installation.operator.tigera.io")

	ctx := context.Background()

	// Perform an initial check so that we kick off the CR status reporting
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, nil); err != nil && apierrors.IsNotFound(err) {
		reqLogger.Info("Installation config not found")
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}
	r.status.OnCRFound()

	// Query for the installation object.
	instance, err := GetInstallation(ctx, r.client, r.autoDetectedProvider)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		if errors.As(err, &parser.ErrIncompatibleCluster{}) {
			r.SetDegraded("Existing Calico installation can not be managed by Tigera Operator as it is configured in a way that Operator does not currently support. Please update your existing Calico install config", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.SetDegraded("Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// Validate the configuration.
	if err = validateCustomResource(instance); err != nil {
		r.SetDegraded("Invalid Installation provided", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
	// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
	if err = r.client.Update(ctx, instance); err != nil {
		r.SetDegraded("Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// The operator supports running in a "Calico only" mode so that it doesn't need to run TSEE specific controllers.
	// If we are switching from this mode to one that enables TSEE, we need to restart the operator to enable the other controllers.
	if !r.enterpriseCRDsExist && instance.Spec.Variant == operator.TigeraSecureEnterprise {
		// Perform an API discovery to determine if the necessary APIs exist. If they do, we can reboot into TSEE mode.
		// if they do not, we need to notify the user that the requested configuration is invalid.
		b, err := utils.RequiresTigeraSecure(r.config)
		if b {
			log.Info("Rebooting to enable TigeraSecure controllers")
			os.Exit(0)
		} else if err != nil {
			r.SetDegraded("Error discovering Tigera Secure availability", err, reqLogger)
		} else {
			r.SetDegraded("Cannot deploy Tigera Secure", fmt.Errorf("Missing Tigera Secure custom resource definitions"), reqLogger)
		}

		// Queue a retry. We don't want to watch the APIServer API since it might not exist and would cause
		// this controller to fail.
		reqLogger.Info("Scheduling a retry in 30 seconds")
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// The operator supports running without the AmazonCloudIntegration when it's CRD is not installed.
	// If, when this controller was started, the CRD didn't exist, but it does now, then reboot.
	if !r.amazonCRDExists {
		amazonCRDRequired, err := utils.RequiresAmazonController(r.config)
		if err != nil {
			r.SetDegraded("Error discovering AmazonCloudIntegration CRD", err, reqLogger)
			reqLogger.Info("Scheduling a retry in 30 seconds")
			return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
		}
		if amazonCRDRequired {
			log.Info("Rebooting to enable AWS controllers")
			os.Exit(0)
		}
	}

	// Convert specified and detected settings into render configuration.
	netConf := GenerateRenderConfig(instance)

	// Query for pull secrets in operator namespace
	pullSecrets, err := utils.GetNetworkingPullSecrets(instance, r.client)
	if err != nil {
		r.SetDegraded("Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	var managerInternalTLSSecret *corev1.Secret
	managerInternalTLSSecret, err = utils.ValidateCertPair(r.client,
		render.ManagerInternalTLSSecretName,
		render.ManagerInternalSecretCertName,
		render.ManagerInternalSecretKeyName,
	)

	if instance.Spec.ClusterManagementType == operator.ClusterManagementTypeManagement {
		if err != nil {
			log.Error(err, "Invalid internal manager TLS Cert")
			r.status.SetDegraded("Error validating internal manager TLS certificate", err.Error())
			return reconcile.Result{}, err
		}
	}

	typhaNodeTLS, err := r.GetTyphaFelixTLSConfig()
	if err != nil {
		log.Error(err, "Error with Typha/Felix secrets")
		r.SetDegraded("Error with Typha/Felix secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	birdTemplates, err := getBirdTemplates(r.client)
	if err != nil {
		log.Error(err, "Error retrieving confd templates")
		r.SetDegraded("Error retrieving confd templates", err, reqLogger)
		return reconcile.Result{}, err
	}

	openShiftOnAws := false
	if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
		openShiftOnAws, err = isOpenshiftOnAws(instance, ctx, r.client)
		if err != nil {
			log.Error(err, "Error checking if OpenShift is on AWS")
			r.SetDegraded("Error checking if OpenShift is on AWS", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Determine if we need to migrate resources from the kube-system namespace. If
	// we do then we'll render the Calico components with additional node selectors to
	// prevent scheduling, later we will run a migration that migrates nodes one by one
	// to mimic a 'normal' rolling update.
	needNsMigration, err := r.namespaceMigration.NeedsCoreNamespaceMigration()
	if err != nil {
		log.Error(err, "Error checking if namespace migration is needed")
		r.status.SetDegraded("Error checking if namespace migration is needed", err.Error())
		return reconcile.Result{}, err
	}

	var aci *operatorv1beta1.AmazonCloudIntegration
	if r.amazonCRDExists {
		aci, err = utils.GetAmazonCloudIntegration(ctx, r.client)
		if apierrors.IsNotFound(err) {
			aci = nil
		} else if err != nil {
			log.Error(err, "Error reading AmazonCloudIntegration")
			r.status.SetDegraded("Error reading AmazonCloudIntegration", err.Error())
			return reconcile.Result{}, err
		}
	}

	// Create a component handler to manage the rendered components.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired Calico components based on our configuration and then
	// create or update them.
	calico, err := render.Calico(
		instance,
		pullSecrets,
		typhaNodeTLS,
		managerInternalTLSSecret,
		birdTemplates,
		instance.Spec.KubernetesProvider,
		netConf,
		aci,
		needNsMigration,
	)
	if err != nil {
		log.Error(err, "Error with rendering Calico")
		r.SetDegraded("Error with rendering Calico resources", err, reqLogger)
		return reconcile.Result{}, err
	}

	components := []render.Component{}
	// If we're on OpenShift on AWS render a Job (and needed resources) to
	// setup the security groups we need for IPIP, BGP, and Typha communication.
	if openShiftOnAws {
		awsSetup, err := render.AWSSecurityGroupSetup(instance.Spec.ImagePullSecrets, instance)
		if err != nil {
			// If there is a problem rendering this do not degrade or stop rendering
			// anything else.
			log.Info(err.Error())
		} else {
			components = append(components, awsSetup)
		}
	}
	components = append(components, calico.Render()...)

	for _, component := range components {
		if err := handler.CreateOrUpdate(ctx, component, nil); err != nil {
			r.SetDegraded("Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// TODO: We handle too many components in this controller at the moment. Once we are done consolidating,
	// we can have the CreateOrUpdate logic handle this for us.
	r.status.AddDaemonsets([]types.NamespacedName{{Name: "calico-node", Namespace: "calico-system"}})
	r.status.AddDeployments([]types.NamespacedName{{Name: "calico-kube-controllers", Namespace: "calico-system"}})

	// We have successfully reconciled the Calico installation.
	if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
		openshiftConfig := &configv1.Network{}
		err = r.client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig)
		if err != nil {
			r.SetDegraded("Unable to update OpenShift Network config: failed to read OpenShift network configuration", err, reqLogger)
			return reconcile.Result{}, err
		}
		// Get resource before updating to use in the Patch call.
		patchFrom := client.MergeFrom(openshiftConfig.DeepCopy())
		// If configured to run in openshift, update the config status with the current state.
		reqLogger.WithValues("openshiftConfig", openshiftConfig).V(1).Info("Updating OpenShift cluster network status")
		openshiftConfig.Status.ClusterNetwork = openshiftConfig.Spec.ClusterNetwork
		openshiftConfig.Status.ServiceNetwork = openshiftConfig.Spec.ServiceNetwork
		openshiftConfig.Status.NetworkType = "Calico"
		if instance.Spec.CalicoNetwork != nil && instance.Spec.CalicoNetwork.MTU != nil {
			// If specified in the spec, then use the value provided by the user.
			// This is what the rendering code will have populated into the created resources.
			openshiftConfig.Status.ClusterNetworkMTU = int(*instance.Spec.CalicoNetwork.MTU)
		} else if instance.Spec.CalicoNetwork != nil {
			// If not specified, then use the value for Calico VXLAN networking. This is the smallest
			// value, so might not perform the best but will work everywhere.
			openshiftConfig.Status.ClusterNetworkMTU = 1410
		}

		if err = r.client.Patch(ctx, openshiftConfig, patchFrom); err != nil {
			r.SetDegraded("Error patching openshift network status", err, reqLogger.WithValues("openshiftConfig", openshiftConfig))
			return reconcile.Result{}, err
		}
	}

	// Run this after we have rendered our components so the new (operator created)
	// Deployments and Daemonset exist with our special migration nodeSelectors.
	if needNsMigration {
		if err := r.namespaceMigration.Run(reqLogger); err != nil {
			r.SetDegraded("error migrating resources to calico-system", err, reqLogger)
			// We should always requeue a migration problem. Don't return error
			// to make sure we never start backing off retrying.
			return reconcile.Result{Requeue: true}, nil
		}
		// Requeue so we can update our resources (without the migration changes)
		return reconcile.Result{Requeue: true}, nil
	} else if r.namespaceMigration.NeedCleanup() {
		if err := r.namespaceMigration.CleanupMigration(); err != nil {
			r.SetDegraded("error migrating resources to calico-system", err, reqLogger)
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

// GenerateRenderConfig converts installation into render config.
func GenerateRenderConfig(install *operator.Installation) render.NetworkConfig {
	config := render.NetworkConfig{CNI: render.CNINone}

	// If CalicoNetwork is specified, then use Calico networking.
	if install.Spec.CalicoNetwork != nil {
		config.CNI = render.CNICalico
	}

	// Set other provider-specific settings.
	switch install.Spec.KubernetesProvider {
	case operator.ProviderDockerEE:
		config.NodenameFileOptional = true
	}

	return config
}

func (r *ReconcileInstallation) SetDegraded(reason string, err error, log logr.Logger) {
	log.Error(err, reason)
	r.status.SetDegraded(reason, err.Error())
}

// GetTyphaFelixTLSConfig reads and validates the CA ConfigMap and Secrets for
// Typha and Felix configuration. It returns the validated resources or error
// if there was one.
func (r *ReconcileInstallation) GetTyphaFelixTLSConfig() (*render.TyphaNodeTLS, error) {
	// accumulate all the error messages so all problems with the certs
	// and CA are reported.
	errMsgs := []string{}
	ca, err := r.validateTyphaCAConfigMap()
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CA for Typha is invalid: %s", err))
	}

	node, err := utils.ValidateCertPair(
		r.client,
		render.NodeTLSSecretName,
		render.TLSSecretKeyName,
		render.TLSSecretCertName,
	)
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Felix is invalid: %s", err))
	} else if node != nil {
		if node.Data != nil {
			// We need the CommonName, URISAN, or both to be set
			_, okCN := node.Data[render.CommonName]
			_, okUS := node.Data[render.URISAN]
			if !(okCN || okUS) {
				errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Felix does not contain common-name or uri-san"))
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
		if typha.Data != nil {
			// We need the CommonName, URISAN, or both to be set
			_, okCN := typha.Data[render.CommonName]
			_, okUS := typha.Data[render.URISAN]
			if !(okCN || okUS) {
				errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Typha does not contain common-name or uri-san"))
			}
		}
	}

	// CA, typha, and node are all not set
	allNil := (ca == nil && typha == nil && node == nil)
	// CA, typha, and node are all are set
	allSet := (ca != nil && typha != nil && node != nil)
	// All CA, typha, and node must be set or not set.
	if !(allNil || allSet) {
		errMsgs = append(errMsgs, fmt.Sprintf("Typha-Node CA and Secrets should all be set or none set: ca(%t) typha(%t) node(%t)", ca != nil, typha != nil, node != nil))
		errMsgs = append(errMsgs, "If not providing custom CA and certs, feel free to remove them from the operator namespace, they will be recreated")
	}

	// TODO: We could make sure both TLS Secrets were signed by the CA

	if len(errMsgs) != 0 {
		return nil, fmt.Errorf(strings.Join(errMsgs, ";"))
	}
	return &render.TyphaNodeTLS{CAConfigMap: ca, TyphaSecret: typha, NodeSecret: node}, nil
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

func getBirdTemplates(client client.Client) (map[string]string, error) {
	cmName := render.BirdTemplatesConfigMapName
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: render.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read ConfigMap %q: %s", cmName, err)
	}

	bt := make(map[string]string)
	for k, v := range cm.Data {
		bt[k] = v
	}
	return bt, nil
}

// isOpenshiftOnAws returns true if running on OpenShift on AWS, this is determined
// by the KubernetesProvider on the installation and the infrastructure OpenShift
// status.
func isOpenshiftOnAws(install *operator.Installation, ctx context.Context, client client.Client) (bool, error) {
	if install.Spec.KubernetesProvider != operator.ProviderOpenShift {
		return false, nil
	}
	infra := configv1.Infrastructure{}
	// If configured to run in openshift, then also fetch the openshift configuration API.
	if err := client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, &infra); err != nil {
		return false, fmt.Errorf("Unable to read OpenShift infrastructure configuration: %s", err.Error())
	}
	return (infra.Status.Platform == "AWS"), nil
}

func updateInstallationForExistingInstall(i *operator.Installation, ei *parser.Config) error {
	if i.Spec.CalicoNetwork == nil {
		i.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}

	if ei.AutoDetectionMethod != nil {
		i.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = ei.AutoDetectionMethod
	}
	if ei.MTU != nil {
		i.Spec.CalicoNetwork.MTU = ei.MTU
	}
	return nil
}

func updateInstallationForOpenshiftNetwork(i *operator.Installation, o *configv1.Network) error {
	if i.Spec.CalicoNetwork == nil {
		i.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}

	platformCIDRs := []string{}
	for _, c := range o.Spec.ClusterNetwork {
		platformCIDRs = append(platformCIDRs, c.CIDR)
	}
	return mergePlatformPodCIDRs(i, platformCIDRs)
}

func updateInstallationForKubeadm(i *operator.Installation, c *v1.ConfigMap) error {
	if i.Spec.CalicoNetwork == nil {
		i.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}

	platformCIDRs, err := extractKubeadmCIDRs(c)
	if err != nil {
		return err
	}
	return mergePlatformPodCIDRs(i, platformCIDRs)
}

func mergePlatformPodCIDRs(i *operator.Installation, platformCIDRs []string) error {
	// If IPPools is nil, add IPPool with CIDRs detected from platform configuration.
	if i.Spec.CalicoNetwork.IPPools == nil {
		if len(platformCIDRs) == 0 {
			// If the platform has no CIDRs defined as well, then return and let the
			// normal defaulting happen.
			return nil
		}
		v4found := false
		v6found := false

		// Currently we only support a single IPv4 and a single IPv6 CIDR configured via the operator.
		// So, grab the 1st IPv4 and IPv6 cidrs we find and use those. This will allow the
		// operator to work in situations where there are more than one of each.
		for _, c := range platformCIDRs {
			addr, _, err := net.ParseCIDR(c)
			if err != nil {
				log.Error(err, "Failed to parse platform's pod network CIDR.")
				continue
			}

			if addr.To4() == nil {
				if v6found {
					continue
				}
				v6found = true
				i.Spec.CalicoNetwork.IPPools = append(i.Spec.CalicoNetwork.IPPools,
					operator.IPPool{CIDR: c})
			} else {
				if v4found {
					continue
				}
				v4found = true
				i.Spec.CalicoNetwork.IPPools = append(i.Spec.CalicoNetwork.IPPools,
					operator.IPPool{CIDR: c})
			}
			if v6found && v4found {
				break
			}
		}
	} else if len(i.Spec.CalicoNetwork.IPPools) == 0 {
		// Empty IPPools list so nothing to do.
		return nil
	} else {
		// Pools are configured on the Installation. Make sure they are compatible with
		// the configuration set in the underlying Kubernetes platform.
		for _, pool := range i.Spec.CalicoNetwork.IPPools {
			within := false
			for _, c := range platformCIDRs {
				within = within || cidrWithinCidr(c, pool.CIDR)
			}
			if !within {
				return fmt.Errorf("IPPool %v is not within the platform's configured pod network CIDR(s)", pool.CIDR)
			}
		}
	}
	return nil
}

// cidrWithinCidr checks that all IPs in the pool passed in are within the
// passed in CIDR
func cidrWithinCidr(cidr, pool string) bool {
	_, cNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	_, pNet, err := net.ParseCIDR(pool)
	if err != nil {
		return false
	}
	ipMin := pNet.IP
	pOnes, _ := pNet.Mask.Size()
	cOnes, _ := cNet.Mask.Size()

	// If the cidr contains the network (1st) address of the pool and the
	// prefix on the pool is larger than or equal to the cidr prefix (the pool size is
	// smaller than the cidr) then the pool network is within the cidr network.
	if cNet.Contains(ipMin) && pOnes >= cOnes {
		return true
	}
	return false
}
