// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

package manager

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
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
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/compliance"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const ResourceName = "manager"

var log = logf.Log.WithName("controller_manager")

// Add creates a new Manager Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}

	licenseAPIReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}

	// create the reconciler
	reconciler := newReconciler(mgr, opts, licenseAPIReady, tierWatchReady)

	// Create a new controller
	managerController, err := controller.New("cmanager-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create manager-controller: %w", err)
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
	}

	// Make a helper for determining which namespaces to use based on tenancy mode.
	helper := utils.NewNamespaceHelper(opts.MultiTenant, render.ManagerNamespace, "")

	if err := utils.AddSecretsWatch(managerController, render.VoltronLinseedTLS, helper.InstallNamespace()); err != nil {
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(managerController, k8sClient, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, managerController, k8sClient, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(managerController, k8sClient, log, []types.NamespacedName{
		{Name: render.ManagerPolicyName, Namespace: helper.InstallNamespace()},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: helper.InstallNamespace()},
	})

	// Watch for changes to primary resource Manager
	err = managerController.Watch(&source.Kind{Type: &operatorv1.Manager{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}

	// Watch for other operator.tigera.io resources.
	if err = managerController.Watch(&source.Kind{Type: &operatorv1.Installation{}}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch Installation resource: %w", err)
	}
	if err = managerController.Watch(&source.Kind{Type: &operatorv1.APIServer{}}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch APIServer resource: %w", err)
	}
	if err = managerController.Watch(&source.Kind{Type: &operatorv1.Compliance{}}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch APIServer resource: %w", err)
	}
	if err = managerController.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}
	if err = managerController.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}
	if err = managerController.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(managerController, ResourceName); err != nil {
		return fmt.Errorf("manager-controller failed to watch manager Tigerastatus: %w", err)
	}
	if err = managerController.Watch(&source.Kind{Type: &operatorv1.ImageSet{}}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch ImageSet: %w", err)
	}
	if opts.MultiTenant {
		if err = managerController.Watch(&source.Kind{Type: &operatorv1.Tenant{}}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("manager-controller failed to watch Tenant resource: %w", err)
		}
	}

	// Watch any secrets that this controller depends upon.
	namespacesToWatch := []string{helper.TruthNamespace(), helper.InstallNamespace()}
	if helper.TruthNamespace() == helper.InstallNamespace() {
		namespacesToWatch = []string{helper.InstallNamespace()}
	}
	for _, namespace := range namespacesToWatch {
		for _, secretName := range []string{
			render.ManagerTLSSecretName, relasticsearch.PublicCertSecret, render.ElasticsearchManagerUserSecret,
			render.VoltronTunnelSecretName, render.ComplianceServerCertSecret, render.PacketCaptureServerCert,
			render.ManagerInternalTLSSecretName, monitor.PrometheusTLSSecretName, certificatemanagement.CASecretName,
		} {
			if err = utils.AddSecretsWatch(managerController, secretName, namespace); err != nil {
				return fmt.Errorf("manager-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	if err = utils.AddConfigMapWatch(managerController, tigerakvc.StaticWellKnownJWKSConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("manager-controller failed to watch ConfigMap resource %s: %w", tigerakvc.StaticWellKnownJWKSConfigMapName, err)
	}

	if err = utils.AddConfigMapWatch(managerController, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), eventHandler); err != nil {
		return fmt.Errorf("compliance-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err = utils.AddNamespaceWatch(managerController, common.TigeraPrometheusNamespace); err != nil {
		return fmt.Errorf("manager-controller failed to watch the '%s' namespace: %w", common.TigeraPrometheusNamespace, err)
	}

	if err = utils.AddConfigMapWatch(managerController, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %v", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions, licenseAPIReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	c := &ReconcileManager{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "manager", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
		usePSP:          opts.UsePSP,
		multiTenant:     opts.MultiTenant,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

var _ reconcile.Reconciler = &ReconcileManager{}

// ReconcileManager reconciles a Manager object.
type ReconcileManager struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	licenseAPIReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
	usePSP          bool

	// Whether or not the operator is running in multi-tenant mode.
	multiTenant bool
}

// GetManager returns the default manager instance with defaults populated.
func GetManager(ctx context.Context, cli client.Client, mt bool, ns string) (*operatorv1.Manager, error) {
	key := client.ObjectKey{Name: "tigera-secure"}
	if mt {
		key.Namespace = ns
	}

	// Fetch the manager instance. We only support a single instance named "tigera-secure".
	instance := &operatorv1.Manager{}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, err
	}
	if instance.Spec.Auth != nil && instance.Spec.Auth.Type != operatorv1.AuthTypeToken {
		return nil, fmt.Errorf("auth types other than 'Token' can no longer be configured using the Manager CR, " +
			"please use the Authentication CR instead")
	}
	return instance, nil
}

// Reconcile reads that state of the cluster for a Manager object and makes changes based on the state read
// and what is in the Manager.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileManager) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	// Perform any common preparation that needs to be done for single-tenant and multi-tenant scenarios.
	helper := utils.NewNamespaceHelper(r.multiTenant, render.ManagerNamespace, request.Namespace)
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	logc.Info("Reconciling Manager")

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

	// Fetch the Manager instance that corresponds with this reconcile trigger.
	instance, err := GetManager(ctx, r.client, r.multiTenant, request.Namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			logc.Info("Manager object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Manager", err, logc)
		return reconcile.Result{}, err
	}
	logc.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating Manager status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create Manager status conditions.")
			return reconcile.Result{}, err
		}
	}

	if !utils.IsAPIServerReady(r.client, logc) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, logc)
		return reconcile.Result{}, nil
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created", err, logc)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, logc)
			return reconcile.Result{}, err
		}
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// TODO: Do we need a license per-tenant in the management cluster?
	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, logc)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	variant, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, logc)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, logc)
		return reconcile.Result{}, err
	}

	// When creating the certificate manager, pass in the logger and tenant (if one exists).
	opts := []certificatemanager.Option{
		certificatemanager.WithLogger(logc),
		certificatemanager.WithTenant(tenant),
	}
	certificateManager, err := certificatemanager.Create(r.client, installation, r.clusterDomain, helper.TruthNamespace(), opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, logc)
		return reconcile.Result{}, err
	}

	// Get or create a certificate for clients of the manager pod es-proxy container.
	tlsSecret, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		render.ManagerTLSSecretName,
		helper.TruthNamespace(),
		[]string{"localhost"})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting or creating manager TLS certificate", err, logc)
		return reconcile.Result{}, err
	}

	// Get or create a certificate for the manager pod to use within the cluster.
	dnsNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, r.clusterDomain)
	internalTrafficSecret, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		render.ManagerInternalTLSSecretName,
		helper.TruthNamespace(),
		dnsNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.CertificateError, fmt.Sprintf("Error ensuring internal manager TLS certificate %q exists and has valid DNS names", render.ManagerInternalTLSSecretName), err, logc)
		return reconcile.Result{}, err
	}

	// Determine if compliance is enabled.
	complianceLicenseFeatureActive := utils.IsFeatureActive(license, common.ComplianceFeature)
	complianceCR, err := compliance.GetCompliance(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying compliance: ", err, logc)
		return reconcile.Result{}, err
	}

	// Build a trusted bundle containing all of the certificates of components that communicate with the manager pod.
	// This bundle contains the root CA used to sign all operator-generated certificates, as well as the explicitly named
	// certificates, in case the user has provided their own cert in lieu of the default certificate.
	var authenticationCR *operatorv1.Authentication
	var trustedSecretNames []string
	if !r.multiTenant {
		// For multi-tenant systems, we don't support user-provided certs for all components. So, we don't need to include these,
		// and the bundle will simply use the root CA for the tenant. For single-tenant systems, we need to include these in case
		// any of them haven't been signed by the root CA.
		trustedSecretNames = []string{
			render.PacketCaptureServerCert,
			monitor.PrometheusTLSSecretName,
			relasticsearch.PublicCertSecret,
			render.ProjectCalicoAPIServerTLSSecretName(installation.Variant),
			render.TigeraLinseedSecret,
		}

		if complianceLicenseFeatureActive && complianceCR != nil {
			// Check that compliance is running.
			if complianceCR.Status.State != operatorv1.TigeraStatusReady {
				r.status.SetDegraded(operatorv1.ResourceNotReady, "Compliance is not ready", nil, logc)
				return reconcile.Result{}, nil
			}
			trustedSecretNames = append(trustedSecretNames, render.ComplianceServerCertSecret)
		}

		// Fetch the Authentication spec. If present, we use to configure user authentication.
		authenticationCR, err = utils.GetAuthentication(ctx, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, logc)
			return reconcile.Result{}, err
		}
		if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready authenticationCR status: %s", authenticationCR.Status.State), nil, logc)
			return reconcile.Result{}, nil
		} else if authenticationCR != nil {
			trustedSecretNames = append(trustedSecretNames, render.DexTLSSecretName)
		}
	}

	bundleMaker := certificateManager.CreateTrustedBundle()
	for _, secret := range trustedSecretNames {
		certificate, err := certificateManager.GetCertificate(r.client, secret, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.CertificateError, fmt.Sprintf("Failed to retrieve %s", secret), err, logc)
			return reconcile.Result{}, err
		} else if certificate == nil {
			logc.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secret))
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret '%s' to become available", secret), nil, logc)
			return reconcile.Result{}, nil
		}
		bundleMaker.AddCertificates(certificate)
	}
	certificateManager.AddToStatusManager(r.status, helper.InstallNamespace())

	// Check that Prometheus is running
	// TODO: We'll need to run an instance of Prometheus per-tenant? Or do we use labels to delimit metrics?
	//       Probably the former.
	ns := &corev1.Namespace{}
	if err = r.client.Get(ctx, client.ObjectKey{Name: common.TigeraPrometheusNamespace}, ns); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "tigera-prometheus namespace does not exist Dependency on tigera-prometheus not satisfied", nil, logc)
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying prometheus", err, logc)
		}
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, logc)
		return reconcile.Result{}, err
	}

	clusterConfig, err := utils.GetElasticsearchClusterConfig(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Elasticsearch cluster configuration is not available, waiting for it to become available", err, logc)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get the elasticsearch cluster configuration", err, logc)
		return reconcile.Result{}, err
	}

	var esSecrets []*corev1.Secret
	if !r.multiTenant {
		// Get secrets used by the manager to authenticate with Elasticsearch. This is used for Kibana login, and isn't
		// needed for multi-tenant installations since currently Kibana is not supported in that mode.
		esSecrets, err = utils.ElasticsearchSecrets(ctx, []string{render.ElasticsearchManagerUserSecret}, r.client)
		if err != nil {
			if errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceNotFound, "Elasticsearch secrets are not available yet, waiting until they become available", err, logc)
				return reconcile.Result{}, nil
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch credentials", err, logc)
			return reconcile.Result{}, err
		}
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

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, logc)
		return reconcile.Result{}, err
	}

	// Es-proxy needs to trust Voltron for cross-cluster requests.
	bundleMaker.AddCertificates(internalTrafficSecret)

	var linseedVoltronServerCert certificatemanagement.KeyPairInterface
	var tunnelServerCert certificatemanagement.KeyPairInterface
	var tunnelSecretPassthrough render.Component

	if managementCluster != nil {
		preDefaultPatchFrom := client.MergeFrom(managementCluster.DeepCopy())
		fillDefaults(managementCluster)

		// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
		// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
		if err := r.client.Patch(ctx, managementCluster, preDefaultPatchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "", err, logc)
			return reconcile.Result{}, err
		}

		// Create a certificate for Voltron to use when serving TLS connections from managed clusters destined
		// to Linseed. This certificate is used only for connections received over Voltron's mTLS tunnel targeting tigera-linseed.
		// The public cert from this keypair is sent by es-kube-controllers to managed clusters so that linseed clients in those clusters
		// can authenticate the certificate presented by Voltron.
		linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, render.ElasticsearchNamespace, r.clusterDomain)
		linseedVoltronServerCert, err = certificateManager.GetOrCreateKeyPair(
			r.client,
			render.VoltronLinseedTLS,
			helper.TruthNamespace(),
			linseedDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting or creating Voltron Linseed TLS certificate", err, logc)
			return reconcile.Result{}, err
		}

		// Query the tunnel server certificate used by Voltron to serve mTLS connections from managed clusters.
		tunnelSecretName := managementCluster.Spec.TLS.SecretName
		// For multi-tenant clusters, ensure that we have a CA that can be used to sign the tunnel server cert within this tenant's namespace.
		// For single-tenant cluster, ensure that we have a CA that can be used to sign the tunnel server cert in operator namespace.
		// This certificate will also be presented by Voltron to prove its identity to managed clusters.
		tunnelCASecret, err := utils.GetSecret(ctx, r.client, tunnelSecretName, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to fetch the tunnel secret", err, logc)
			return reconcile.Result{}, err
		}

		// Single tenant MCM clusters will use "voltron" as a server name to establish mTLS connection
		serverName := "voltron"
		if r.multiTenant {
			// Multi-tenant MCM clusters will use the tenat ID as a server name to establish mTLS connection
			serverName = tenant.Spec.ID
		}

		if tunnelCASecret == nil {
			tunnelCASecret, err = certificatemanagement.CreateSelfSignedSecret(tunnelSecretName, helper.TruthNamespace(), "tigera-voltron", []string{serverName})
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the tunnel secret", err, logc)
				return reconcile.Result{}, err
			}
		}

		// We use the CA as the server cert.
		tunnelServerCert = certificatemanagement.NewKeyPair(tunnelCASecret, nil, "")
		tunnelSecretPassthrough = render.NewPassthrough(tunnelCASecret)
	}

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Failed to process the authentication CR.", err, logc)
		return reconcile.Result{}, err
	}

	var elasticLicenseType render.ElasticsearchLicenseType
	if managementClusterConnection == nil {
		if elasticLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, logc); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch license", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Create a component handler to manage the rendered component.
	componentHandler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Set replicas to 1 for management or managed clusters.
	// TODO Remove after MCM tigera-manager HA deployment is supported.
	var replicas *int32 = installation.ControlPlaneReplicas
	if managementCluster != nil || managementClusterConnection != nil {
		var mcmReplicas int32 = 1
		replicas = &mcmReplicas
	}

	trustedBundle := bundleMaker.(certificatemanagement.TrustedBundleRO)
	if r.multiTenant {
		// for multi-tenant systems, we load the pre-created bundle for this tenant instead of using the one we built here.
		trustedBundle, err = certificateManager.LoadTrustedBundle(ctx, r.client, helper.InstallNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, logc)
			return reconcile.Result{}, err
		}
		bundleMaker = nil
	}

	// Determine the namespaces to which we must bind the cluster role.
	namespaces, err := helper.TenantNamespaces(r.client)
	if err != nil {
		return reconcile.Result{}, err
	}

	managerCfg := &render.ManagerConfiguration{
		KeyValidatorConfig:      keyValidatorConfig,
		ESSecrets:               esSecrets,
		TrustedCertBundle:       trustedBundle,
		ClusterConfig:           clusterConfig,
		TLSKeyPair:              tlsSecret,
		VoltronLinseedKeyPair:   linseedVoltronServerCert,
		PullSecrets:             pullSecrets,
		Openshift:               r.provider == operatorv1.ProviderOpenShift,
		Installation:            installation,
		ManagementCluster:       managementCluster,
		TunnelServerCert:        tunnelServerCert,
		InternalTLSKeyPair:      internalTrafficSecret,
		ClusterDomain:           r.clusterDomain,
		ESLicenseType:           elasticLicenseType,
		Replicas:                replicas,
		Compliance:              complianceCR,
		ComplianceLicenseActive: complianceLicenseFeatureActive,
		UsePSP:                  r.usePSP,
		Namespace:               helper.InstallNamespace(),
		TruthNamespace:          helper.TruthNamespace(),
		Tenant:                  tenant,
		BindingNamespaces:       namespaces,
	}

	// Render the desired objects from the CRD and create or update them.
	component, err := render.Manager(managerCfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering Manager", err, logc)
		return reconcile.Result{}, err
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
		return reconcile.Result{}, err
	}

	components := []render.Component{
		// Install manager components.
		component,

		// Installs KeyPairs and trusted bundle (if not pre-installed)
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       helper.InstallNamespace(),
			TruthNamespace:  helper.TruthNamespace(),
			ServiceAccounts: []string{render.ManagerServiceAccount},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(tlsSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(linseedVoltronServerCert, true, true),
				rcertificatemanagement.NewKeyPairOption(internalTrafficSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(tunnelServerCert, false, true),
			},
			TrustedBundle: bundleMaker,
		}),
	}

	if tunnelSecretPassthrough != nil {
		components = append(components, tunnelSecretPassthrough)
	}

	for _, component := range components {
		if err := componentHandler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	instance.Status.State = operatorv1.TigeraStatusReady
	if r.status.IsAvailable() {
		if err = r.client.Status().Update(ctx, instance); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func fillDefaults(mc *operatorv1.ManagementCluster) {
	if mc.Spec.TLS == nil {
		mc.Spec.TLS = &operatorv1.TLS{}
	}
	if mc.Spec.TLS.SecretName == "" {
		mc.Spec.TLS.SecretName = render.VoltronTunnelSecretName
	}
}
