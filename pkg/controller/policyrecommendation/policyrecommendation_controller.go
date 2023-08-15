// Copyright (c) 2023 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in policy recommendation with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policyrecommendation

import (
	"context"
	"fmt"
	"time"

	"github.com/tigera/operator/pkg/controller/tenancy"

	octrl "github.com/tigera/operator/pkg/controller"

	"k8s.io/apimachinery/pkg/types"

	"github.com/go-logr/logr"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	PolicyRecommendationControllerName = "policy-recommendation-controller"
	ResourceName                       = "policy-recommendation"
)

var log = logf.Log.WithName("controller_policy_recommendation")

// Add creates a new PolicyRecommendation Controller and adds it to the Manager. The Manager will
// set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller
		return nil
	}
	licenseAPIReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}
	policyRecScopeWatchReady := &utils.ReadyFlag{}

	reconciler := newReconciler(mgr, opts, licenseAPIReady, tierWatchReady, policyRecScopeWatchReady)

	policyRecController, err := controller.New(PolicyRecommendationControllerName, mgr,
		controller.Options{
			Reconciler: reconciler,
		})
	if err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	installNS, _, watchNamespaces := tenancy.GetWatchNamespaces(opts.MultiTenant, render.PolicyRecommendationNamespace)

	go utils.WaitToAddLicenseKeyWatch(policyRecController, k8sClient, log, licenseAPIReady)
	go utils.WaitToAddPolicyRecommendationScopeWatch(policyRecController, k8sClient, log, policyRecScopeWatchReady)
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, policyRecController, k8sClient, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(policyRecController, k8sClient, log, []types.NamespacedName{
		{Name: render.PolicyRecommendationPolicyName, Namespace: installNS},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: installNS},
	})

	// Watch for changes to primary resource PolicyRecommendation
	err = policyRecController.Watch(&source.Kind{Type: &operatorv1.PolicyRecommendation{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource PolicyRecommendationScope
	err = policyRecController.Watch(&source.Kind{Type: &v3.PolicyRecommendationScope{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch policy recommendation scope resource: %w", err)
	}

	if err = utils.AddNetworkWatch(policyRecController); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch Network resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(policyRecController); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddAPIServerWatch(policyRecController); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch APIServer resource: %w", err)
	}

	// Watch the given secrets in each both the policy-recommendation and operator namespaces
	for _, namespace := range watchNamespaces {
		for _, secretName := range []string{
			relasticsearch.PublicCertSecret,
			render.ElasticsearchPolicyRecommendationUserSecret,
			certificatemanagement.CASecretName,
			render.ManagerInternalTLSSecretName,
			render.TigeraLinseedSecret,
		} {
			if err = utils.AddSecretsWatch(policyRecController, secretName, namespace); err != nil {
				return fmt.Errorf("policy-recommendation-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	if err = utils.AddConfigMapWatch(policyRecController, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch the ConfigMap resource: %w", err)
	}

	// Watch for changes to primary resource ManagementCluster
	err = policyRecController.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = policyRecController.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to TigeraStatus
	if err = utils.AddTigeraStatusWatch(policyRecController, ResourceName); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch policy-recommendation Tigerastatus: %w", err)
	}

	return nil
}

// newReconciler returns a new *reconcile.Reconciler.
func newReconciler(
	mgr manager.Manager,
	opts options.AddOptions,
	licenseAPIReady *utils.ReadyFlag,
	tierWatchReady *utils.ReadyFlag,
	policyRecScopeWatchReady *utils.ReadyFlag,
) reconcile.Reconciler {
	r := &ReconcilePolicyRecommendation{
		client:                   mgr.GetClient(),
		scheme:                   mgr.GetScheme(),
		provider:                 opts.DetectedProvider,
		status:                   status.New(mgr.GetClient(), "policy-recommendation", opts.KubernetesVersion),
		clusterDomain:            opts.ClusterDomain,
		licenseAPIReady:          licenseAPIReady,
		tierWatchReady:           tierWatchReady,
		policyRecScopeWatchReady: policyRecScopeWatchReady,
		usePSP:                   opts.UsePSP,
		multiTenant:              opts.MultiTenant,
	}

	r.status.Run(opts.ShutdownContext)

	return r
}

// blank assignment to verify that ReconcilePolicyRecommendation implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcilePolicyRecommendation{}

// ReconcilePolicyRecommendation reconciles a PolicyRecommendation object
type ReconcilePolicyRecommendation struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client                   client.Client
	clusterDomain            string
	licenseAPIReady          *utils.ReadyFlag
	scheme                   *runtime.Scheme
	status                   status.StatusManager
	tierWatchReady           *utils.ReadyFlag
	policyRecScopeWatchReady *utils.ReadyFlag
	provider                 operatorv1.Provider
	usePSP                   bool
	multiTenant              bool
}

func GetPolicyRecommendation(ctx context.Context, cli client.Client, ns string) (*operatorv1.PolicyRecommendation, error) {
	key := client.ObjectKey{Name: "tigera-secure", Namespace: ns}

	instance := &operatorv1.PolicyRecommendation{}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// Reconcile reads that state of the cluster for a PolicyRecommendation object and makes changes
// based on the state read and what is in the PolicyRecommendation.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcilePolicyRecommendation) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling PolicyRecommendation")

	if r.multiTenant && request.Namespace == "" {
		// For now, if we're running in multi-tenant mode, just skip any non-namespaced triggers.
		// A potential improvement here would be to reconcile multiple PolicyRecommendation instances.
		return reconcile.Result{}, nil
	}

	// In single-tenant mode, the policyrecommendation is always global scoped. However, for multi-tenant mode
	// the policyrecommendation instance will belong to a particular namespace.
	ns := ""
	if r.multiTenant {
		ns = request.Namespace
	}
	// Fetch the PolicyRecommendation instance
	instance, err := GetPolicyRecommendation(ctx, r.client, ns)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use
			// finalizers.
			// Return and don't requeue.
			reqLogger.Info("PolicyRecommendation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying policy-recommendation", err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// SetMetaData in the TigeraStatus such as observedGenerations
	defer r.status.SetMetaData(&instance.ObjectMeta)

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", err, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Validate that the policy recommendation scope watch is ready before querying the tier to ensure we utilize the cache.
	if !r.policyRecScopeWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for PolicyRecommendationScope watch to be established", err, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created", err, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			log.Error(err, "Error querying allow-tigera tier")
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Query for the installation object.
	variant, network, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Package up the request parameters needed to reconcile
	req := octrl.NewRequest(request.NamespacedName, r.multiTenant, render.PolicyRecommendationNamespace)
	args := ReconcileArgs{
		Variant:              variant,
		Installation:         network,
		License:              license,
		PolicyRecommendation: instance,
	}
	return r.reconcileInstance(ctx, reqLogger, args, req)
}

type ReconcileArgs struct {
	Variant              operatorv1.ProductVariant
	Installation         *operatorv1.InstallationSpec
	PolicyRecommendation *operatorv1.PolicyRecommendation
	License              v3.LicenseKey
}

func (r *ReconcilePolicyRecommendation) reconcileInstance(ctx context.Context, logc logr.Logger, args ReconcileArgs, request octrl.Request) (reconcile.Result, error) {
	pullSecrets, err := utils.GetNetworkingPullSecrets(args.Installation, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve pull secrets", err, logc)
		return reconcile.Result{}, err
	}

	esClusterConfig, err := utils.GetElasticsearchClusterConfig(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Elasticsearch cluster configuration is not available, waiting for it to become available", err, logc)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get the elasticsearch cluster configuration", err, logc)
		return reconcile.Result{}, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, logc)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, logc)
		return reconcile.Result{}, err
	}

	isManagedCluster := managementClusterConnection != nil

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, logc)
		return reconcile.Result{}, err
	}

	secretsToWatch := []string{
		render.ElasticsearchPolicyRecommendationUserSecret,
	}
	esSecrets, err := utils.ElasticsearchSecrets(ctx, secretsToWatch, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Elasticsearch secrets are not available yet, waiting until they become available", err, logc)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch credentials", err, logc)
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, args.PolicyRecommendation)

	logc.V(3).Info("rendering components")
	policyRecommendationCfg := &render.PolicyRecommendationConfiguration{
		ClusterDomain:   r.clusterDomain,
		ESClusterConfig: esClusterConfig,
		ESSecrets:       esSecrets,
		Installation:    args.Installation,
		ManagedCluster:  isManagedCluster,
		PullSecrets:     pullSecrets,
		Openshift:       r.provider == operatorv1.ProviderOpenShift,
		UsePSP:          r.usePSP,
		Namespace:       request.InstallNamespace(),
	}

	// Render the desired objects from the CRD and create or update them.
	component := render.PolicyRecommendation(policyRecommendationCfg)

	if err = imageset.ApplyImageSet(ctx, r.client, args.Variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
		return reconcile.Result{}, err
	}

	components := []render.Component{
		component,
	}

	if !isManagedCluster {
		certificateManager, err := certificatemanager.Create(r.client, args.Installation, r.clusterDomain, request.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, logc)
			return reconcile.Result{}, err
		}

		var managerInternalTLSSecret certificatemanagement.CertificateInterface
		if managementCluster != nil {
			managerInternalTLSSecret, err = certificateManager.GetCertificate(r.client, render.ManagerInternalTLSSecretName, request.TruthNamespace())
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", render.ManagerInternalTLSSecretName), err, logc)
				return reconcile.Result{}, err
			}
		}

		linseedCertLocation := render.TigeraLinseedSecret
		linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertLocation, request.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve / validate %s", render.TigeraLinseedSecret), err, logc)
			return reconcile.Result{}, err
		} else if linseedCertificate == nil {
			log.Info("Linseed certificate is not available yet, waiting until they become available")
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Linseed certificate is not available yet, waiting until it becomes available", nil, logc)
			return reconcile.Result{}, nil
		}

		trustedBundle := certificateManager.CreateTrustedBundle(managerInternalTLSSecret, linseedCertificate)

		// policyRecommendationKeyPair is the key pair policy recommendation presents to identify itself
		policyRecommendationKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, render.PolicyRecommendationTLSSecretName, request.TruthNamespace(), []string{render.PolicyRecommendationTLSSecretName})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, logc)
			return reconcile.Result{}, err
		}

		certificateManager.AddToStatusManager(r.status, request.InstallNamespace())

		policyRecommendationCfg.TrustedBundle = trustedBundle
		policyRecommendationCfg.PolicyRecommendationCertSecret = policyRecommendationKeyPair

		components = append(components,
			rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
				Namespace:       request.InstallNamespace(),
				TruthNamespace:  request.TruthNamespace(),
				ServiceAccounts: []string{render.PolicyRecommendationName},
				KeyPairOptions: []rcertificatemanagement.KeyPairOption{
					rcertificatemanagement.NewKeyPairOption(policyRecommendationKeyPair, true, true),
				},
				TrustedBundle: trustedBundle,
			}),
		)
	}

	if hasNoLicense := !utils.IsFeatureActive(args.License, common.PolicyRecommendationFeature); hasNoLicense {
		log.V(4).Info("PolicyRecommendation is not activated as part of this license")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, logc)
		return reconcile.Result{}, nil
	}

	for _, cmp := range components {
		if err := handler.CreateOrUpdateOrDelete(context.Background(), cmp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CRD status.
	args.PolicyRecommendation.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, args.PolicyRecommendation); err != nil {
		return reconcile.Result{}, err
	}

	// Fetch any existing PolicyRecommendationScope object
	policyRecommendationScope := &v3.PolicyRecommendationScope{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, policyRecommendationScope)
	if err != nil {
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read policyRecommendationScope", err, logc)
			return reconcile.Result{}, err
		} else {
			// Create the default policy recommendation resource if not found
			if err = r.createDefaultPolicyRecommendationScope(context.Background(), policyRecommendationScope, logc); err != nil {
				return reconcile.Result{}, err
			}
		}
	}
	return reconcile.Result{}, nil
}

// createDefaultPolicyRecommendationScope will create a new default version of the
// PolicyRecommendationScope resource.
func (r *ReconcilePolicyRecommendation) createDefaultPolicyRecommendationScope(ctx context.Context, prs *v3.PolicyRecommendationScope, log logr.Logger) error {
	if prs == nil {
		prs = &v3.PolicyRecommendationScope{}
	}

	prs.ObjectMeta.Name = "default"
	prs.Spec.NamespaceSpec.RecStatus = "Disabled"
	prs.Spec.NamespaceSpec.Selector = "!(projectcalico.org/name starts with 'tigera-') && !(projectcalico.org/name starts with 'calico-') && !(projectcalico.org/name starts with 'kube-')"

	if err := r.client.Create(ctx, prs); err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to Create default PolicyRecommendationScope", err, log)
		return err
	}

	return nil
}
