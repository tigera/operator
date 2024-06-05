// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/tenancy"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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

	c, err := ctrlruntime.NewController(PolicyRecommendationControllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenant clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
		if err = c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("policy-recommendation-controller failed to watch Tenant resource: %w", err)
		}
	}

	installNS, _, watchNamespaces := tenancy.GetWatchNamespaces(opts.MultiTenant, render.PolicyRecommendationNamespace)

	go utils.WaitToAddLicenseKeyWatch(c, k8sClient, log, licenseAPIReady)
	go utils.WaitToAddPolicyRecommendationScopeWatch(c, k8sClient, log, policyRecScopeWatchReady)
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, []types.NamespacedName{
		{Name: render.PolicyRecommendationPolicyName, Namespace: installNS},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: installNS},
	})

	err = c.WatchObject(&operatorv1.PolicyRecommendation{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = c.WatchObject(&operatorv1.Installation{}, eventHandler); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch Installation resource: %w", err)
	}

	if err = c.WatchObject(&operatorv1.ImageSet{}, eventHandler); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch ImageSet: %w", err)
	}

	if err = c.WatchObject(&operatorv1.APIServer{}, eventHandler); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch APIServer resource: %w", err)
	}

	// Watch the given secrets in each both the policy-recommendation and operator namespaces
	for _, namespace := range watchNamespaces {
		for _, secretName := range []string{
			render.ElasticsearchPolicyRecommendationUserSecret,
			certificatemanagement.CASecretName,
			render.ManagerInternalTLSSecretName,
			render.TigeraLinseedSecret,
			render.PolicyRecommendationTLSSecretName,
		} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("policy-recommendation-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	if err = c.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch ManagementCluster resource: %w", err)
	}

	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch ManagementClusterConnection resource: %w", err)
	}

	// Watch for changes to TigeraStatus
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
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
		multiTenant:              opts.MultiTenant,
		externalElastic:          opts.ElasticExternal,
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
	multiTenant              bool
	externalElastic          bool
}

func GetPolicyRecommendation(ctx context.Context, cli client.Client, mt bool, ns string) (*operatorv1.PolicyRecommendation, error) {
	key := client.ObjectKey{Name: "tigera-secure"}
	if mt {
		key.Namespace = ns
	}

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
	helper := utils.NewNamespaceHelper(r.multiTenant, render.PolicyRecommendationNamespace, request.Namespace)
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	logc.Info("Reconciling PolicyRecommendation")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.multiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// Check if this is a tenant-scoped request.
	tenant, _, err := utils.GetTenant(ctx, r.multiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		logc.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, logc)
		return reconcile.Result{}, err
	}

	// Fetch the PolicyRecommendation instance
	policyRecommendation, err := GetPolicyRecommendation(ctx, r.client, r.multiTenant, request.Namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use
			// finalizers.
			// Return and don't requeue.
			logc.Info("PolicyRecommendation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying policy-recommendation", err, logc)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	logc.V(2).Info("Loaded config", "config", policyRecommendation)

	// SetMetaData in the TigeraStatus such as observedGenerations
	defer r.status.SetMetaData(&policyRecommendation.ObjectMeta)

	if !utils.IsAPIServerReady(r.client, logc) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, logc)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", err, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Validate that the policy recommendation scope watch is ready before querying the tier to ensure we utilize the cache.
	if !r.policyRecScopeWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for PolicyRecommendationScope watch to be established", err, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created, see the 'tiers' TigeraStatus for more information", err, logc)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			log.Error(err, "Error querying allow-tigera tier")
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, logc)
			return reconcile.Result{}, err
		}
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, logc)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Query for the installation object.
	variant, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, logc)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, logc)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve pull secrets", err, logc)
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

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, policyRecommendation)

	// Determine the namespaces to which we must bind the cluster role.
	// For multi-tenant, the cluster role will be bind to the service account in the tenant namespace
	// For single-tenant or zero-tenant, the cluster role will be bind to the service account in the tigera-policy-recommendation
	// namespace
	bindNamespaces, err := helper.TenantNamespaces(r.client)
	if err != nil {
		return reconcile.Result{}, err
	}

	logc.V(3).Info("rendering components")
	var policyRecommendationKeyPair certificatemanagement.KeyPairInterface
	var trustedBundleRO certificatemanagement.TrustedBundleRO
	var trustedBundleRW certificatemanagement.TrustedBundle
	var components []render.Component

	if !isManagedCluster {
		opts := []certificatemanager.Option{
			certificatemanager.WithLogger(logc),
			certificatemanager.WithTenant(tenant),
		}
		certificateManager, err := certificatemanager.Create(r.client, installation, r.clusterDomain, helper.TruthNamespace(), opts...)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, logc)
			return reconcile.Result{}, err
		}

		var managerInternalTLSSecret certificatemanagement.CertificateInterface
		if managementCluster != nil {
			managerInternalTLSSecret, err = certificateManager.GetCertificate(r.client, render.ManagerInternalTLSSecretName, helper.TruthNamespace())
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", render.ManagerInternalTLSSecretName), err, logc)
				return reconcile.Result{}, err
			}
		}

		linseedCertLocation := render.TigeraLinseedSecret
		linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertLocation, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve / validate %s", render.TigeraLinseedSecret), err, logc)
			return reconcile.Result{}, err
		} else if linseedCertificate == nil {
			log.Info("Linseed certificate is not available yet, waiting until they become available")
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Linseed certificate is not available yet, waiting until it becomes available", nil, logc)
			return reconcile.Result{}, nil
		}

		// policyRecommendationKeyPair is the key pair policy recommendation presents to identify itself
		policyRecommendationKeyPair, err = certificateManager.GetOrCreateKeyPair(r.client, render.PolicyRecommendationTLSSecretName, helper.TruthNamespace(), []string{render.PolicyRecommendationTLSSecretName})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, logc)
			return reconcile.Result{}, err
		}

		certificateManager.AddToStatusManager(r.status, helper.InstallNamespace())

		if !r.multiTenant {
			// Zero-tenant and single tenant setups install resources inside tigera-policy-recommendation namespace. Thus,
			// we need to create a tigera-ca-bundle inside this namespace in order to allow communication with Linseed
			trustedBundleRW = certificateManager.CreateTrustedBundle(managerInternalTLSSecret, linseedCertificate)
			trustedBundleRO = trustedBundleRW.(certificatemanagement.TrustedBundleRO)
		} else {
			// Multi-tenant setups need to load the bundle the created by pkg/controller/secrets/tenant_controller.go
			trustedBundleRO, err = certificateManager.LoadTrustedBundle(ctx, r.client, helper.InstallNamespace())
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, logc)
				return reconcile.Result{}, err
			}
		}

		components = append(components,
			rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
				Namespace:       helper.InstallNamespace(),
				TruthNamespace:  helper.TruthNamespace(),
				ServiceAccounts: []string{render.PolicyRecommendationName},
				KeyPairOptions: []rcertificatemanagement.KeyPairOption{
					rcertificatemanagement.NewKeyPairOption(policyRecommendationKeyPair, true, true),
				},
				// Zero and single tenant setups need to create tigera-ca-bundle configmap because we install resources
				// in namespace tigera-policy-recommendation
				// Multi-tenant setups need to use the config map that was created by pkg/controller/secrets/tenant_controller.go
				// in the tenant namespace. This parameter needs to be nil in this case
				TrustedBundle: trustedBundleRW,
			}),
		)
	}

	if hasNoLicense := !utils.IsFeatureActive(license, common.PolicyRecommendationFeature); hasNoLicense {
		log.V(4).Info("PolicyRecommendation is not activated as part of this license")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, logc)
		return reconcile.Result{}, nil
	}

	policyRecommendationCfg := &render.PolicyRecommendationConfiguration{
		ClusterDomain:                  r.clusterDomain,
		Installation:                   installation,
		ManagedCluster:                 isManagedCluster,
		PullSecrets:                    pullSecrets,
		OpenShift:                      r.provider.IsOpenShift(),
		Namespace:                      helper.InstallNamespace(),
		Tenant:                         tenant,
		BindingNamespaces:              bindNamespaces,
		ExternalElastic:                r.externalElastic,
		TrustedBundle:                  trustedBundleRO,
		PolicyRecommendationCertSecret: policyRecommendationKeyPair,
		PolicyRecommendation:           policyRecommendation,
	}

	// Render the desired objects from the CRD and create or update them.
	component := render.PolicyRecommendation(policyRecommendationCfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
		return reconcile.Result{}, err
	}

	// Prepend PolicyRecommendation before certificate creation
	components = append([]render.Component{component}, components...)
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
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Everything is available - update the CRD status.
	policyRecommendation.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, policyRecommendation); err != nil {
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
	if r.provider.IsOpenShift() {
		prs.Spec.NamespaceSpec.Selector += " && !(projectcalico.org/name starts with 'openshift-')"
	}

	if err := r.client.Create(ctx, prs); err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to Create default PolicyRecommendationScope", err, log)
		return err
	}

	return nil
}
