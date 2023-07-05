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

	reconciler := newReconciler(mgr, opts, licenseAPIReady, tierWatchReady)

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

	go utils.WaitToAddLicenseKeyWatch(policyRecController, k8sClient, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, policyRecController, k8sClient, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(policyRecController, k8sClient, log, []types.NamespacedName{
		{Name: render.PolicyRecommendationPolicyName, Namespace: render.PolicyRecommendationNamespace},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.PolicyRecommendationNamespace},
	})

	return add(policyRecController)
}

// newReconciler returns a new *reconcile.Reconciler.
func newReconciler(
	mgr manager.Manager,
	opts options.AddOptions,
	licenseAPIReady *utils.ReadyFlag,
	tierWatchReady *utils.ReadyFlag,
) reconcile.Reconciler {
	r := &ReconcilePolicyRecommendation{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "policy-recommendation", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
		usePSP:          opts.UsePSP,
	}

	r.status.Run(opts.ShutdownContext)

	return r
}

// add adds watches for resources that are available at startup.
func add(c controller.Controller) error {
	var err error

	// Watch for changes to primary resource PolicyRecommendation
	err = c.Watch(&source.Kind{Type: &operatorv1.PolicyRecommendation{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource PolicyRecommendationScope
	err = c.Watch(&source.Kind{Type: &v3.PolicyRecommendationScope{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch policy recommendation scope resource: %w", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch Network resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddAPIServerWatch(c); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch APIServer resource: %w", err)
	}

	// Watch the given secrets in each both the policy-recommendation and operator namespaces
	for _, namespace := range []string{common.OperatorNamespace(), render.PolicyRecommendationNamespace} {
		for _, secretName := range []string{
			relasticsearch.PublicCertSecret,
			render.ElasticsearchPolicyRecommendationUserSecret,
			certificatemanagement.CASecretName,
			render.ManagerInternalTLSSecretName,
			render.TigeraLinseedSecret,
		} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("policy-recommendation-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch the ConfigMap resource: %w", err)
	}

	// Watch for changes to primary resource ManagementCluster
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to TigeraStatus
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("policy-recommendation-controller failed to watch policy-recommendation Tigerastatus: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcilePolicyRecommendation implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcilePolicyRecommendation{}

// ReconcilePolicyRecommendation reconciles a PolicyRecommendation object
type ReconcilePolicyRecommendation struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	clusterDomain   string
	licenseAPIReady *utils.ReadyFlag
	scheme          *runtime.Scheme
	status          status.StatusManager
	tierWatchReady  *utils.ReadyFlag
	provider        operatorv1.Provider
	usePSP          bool
}

func GetPolicyRecommendation(ctx context.Context, cli client.Client) (*operatorv1.PolicyRecommendation, error) {
	instance := &operatorv1.PolicyRecommendation{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
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

	// Fetch the PolicyRecommendation instance
	instance, err := GetPolicyRecommendation(ctx, r.client)
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

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	esClusterConfig, err := utils.GetElasticsearchClusterConfig(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Elasticsearch cluster configuration is not available, waiting for it to become available", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get the elasticsearch cluster configuration", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	isManagedCluster := managementClusterConnection != nil

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, err
	}

	secretsToWatch := []string{
		render.ElasticsearchPolicyRecommendationUserSecret,
	}
	esSecrets, err := utils.ElasticsearchSecrets(ctx, secretsToWatch, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Elasticsearch secrets are not available yet, waiting until they become available", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch credentials", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	reqLogger.V(3).Info("rendering components")
	policyRecommendationCfg := &render.PolicyRecommendationConfiguration{
		ClusterDomain:   r.clusterDomain,
		ESClusterConfig: esClusterConfig,
		ESSecrets:       esSecrets,
		Installation:    network,
		ManagedCluster:  isManagedCluster,
		PullSecrets:     pullSecrets,
		Openshift:       r.provider == operatorv1.ProviderOpenShift,
		UsePSP:          r.usePSP,
	}

	// Render the desired objects from the CRD and create or update them.
	component := render.PolicyRecommendation(policyRecommendationCfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	components := []render.Component{
		component,
	}

	if !isManagedCluster {
		certificateManager, err := certificatemanager.Create(r.client, network, r.clusterDomain, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
			return reconcile.Result{}, err
		}

		var managerInternalTLSSecret certificatemanagement.CertificateInterface
		if managementCluster != nil {
			managerInternalTLSSecret, err = certificateManager.GetCertificate(r.client, render.ManagerInternalTLSSecretName, common.OperatorNamespace())
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", render.ManagerInternalTLSSecretName), err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		linseedCertLocation := render.TigeraLinseedSecret
		linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertLocation, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve / validate %s", render.TigeraLinseedSecret), err, reqLogger)
			return reconcile.Result{}, err
		} else if linseedCertificate == nil {
			log.Info("Linseed certificate is not available yet, waiting until they become available")
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Linseed certificate are not available yet, waiting until they become available", nil, reqLogger)
			return reconcile.Result{}, nil
		}

		trustedBundle := certificateManager.CreateTrustedBundle(managerInternalTLSSecret, linseedCertificate)

		// policyRecommendationKeyPair is the key pair policy recommendation presents to identify itself
		policyRecommendationKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, render.PolicyRecommendationTLSSecretName, common.OperatorNamespace(), []string{render.PolicyRecommendationTLSSecretName})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}

		certificateManager.AddToStatusManager(r.status, render.PolicyRecommendationNamespace)

		policyRecommendationCfg.TrustedBundle = trustedBundle
		policyRecommendationCfg.PolicyRecommendationCertSecret = policyRecommendationKeyPair

		components = append(components,
			rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
				Namespace:       render.PolicyRecommendationNamespace,
				ServiceAccounts: []string{render.PolicyRecommendationName},
				KeyPairOptions: []rcertificatemanagement.KeyPairOption{
					rcertificatemanagement.NewKeyPairOption(policyRecommendationKeyPair, true, true),
				},
				TrustedBundle: trustedBundle,
			}),
		)
	}

	if hasNoLicense := !utils.IsFeatureActive(license, common.PolicyRecommendationFeature); hasNoLicense {
		log.V(4).Info("PolicyRecommendation is not activated as part of this license")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	for _, cmp := range components {
		if err := handler.CreateOrUpdateOrDelete(context.Background(), cmp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
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
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}

	// Fetch any existing PolicyRecommendationScope object
	policyRecommendationScope := &v3.PolicyRecommendationScope{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, policyRecommendationScope)
	if err != nil {
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read policyRecommendationScope", err, reqLogger)
			return reconcile.Result{}, err
		} else {
			// Create the default policy recommendation resource if not found
			if err = r.createDefaultPolicyRecommendationScope(context.Background(), policyRecommendationScope, reqLogger); err != nil {
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
