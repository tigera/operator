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
	"time"

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

	"github.com/go-logr/logr"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	octrl "github.com/tigera/operator/pkg/controller"
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
	controller, err := controller.New("cmanager-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return fmt.Errorf("failed to create manager-controller: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	// The namespace(s) we need to monitor depend upon what tenancy mode we're running in.
	// For single-tenant, everything is installed in the tigera-manager namespace.
	installNS := render.ManagerNamespace
	truthNS := common.OperatorNamespace()
	watchNamespaces := []string{installNS, truthNS}
	if opts.MultiTenant {
		// For multi-tenant, the manager could be installed in any number of namespaces.
		// So, we need to watch the resources we care about across all namespaces.
		installNS = ""
		truthNS = ""
		watchNamespaces = []string{""}
	}

	err = utils.AddSecretsWatch(controller, render.VoltronLinseedTLS, installNS)
	if err != nil {
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(controller, k8sClient, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, controller, k8sClient, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(controller, k8sClient, log, []types.NamespacedName{
		{Name: render.ManagerPolicyName, Namespace: installNS},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: installNS},
	})

	// Watch for changes to primary resource Manager
	err = controller.Watch(&source.Kind{Type: &operatorv1.Manager{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}

	err = utils.AddAPIServerWatch(controller)
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch APIServer resource: %w", err)
	}

	err = utils.AddComplianceWatch(controller)
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch compliance resource: %w", err)
	}

	// Watch any secrets that this controller depends upon.
	for _, namespace := range watchNamespaces {
		for _, secretName := range []string{
			render.ManagerTLSSecretName, relasticsearch.PublicCertSecret, render.ElasticsearchManagerUserSecret,
			render.VoltronTunnelSecretName, render.ComplianceServerCertSecret, render.PacketCaptureServerCert,
			render.ManagerInternalTLSSecretName, monitor.PrometheusTLSSecretName, certificatemanagement.CASecretName,
		} {
			if err = utils.AddSecretsWatch(controller, secretName, namespace); err != nil {
				return fmt.Errorf("manager-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	// This may or may not exist, it depends on what the OIDC type is in the Authentication CR.
	if err = utils.AddConfigMapWatch(controller, tigerakvc.StaticWellKnownJWKSConfigMapName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("manager-controller failed to watch ConfigMap resource %s: %w", tigerakvc.StaticWellKnownJWKSConfigMapName, err)
	}

	if err = utils.AddConfigMapWatch(controller, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("compliance-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err = utils.AddNetworkWatch(controller); err != nil {
		return fmt.Errorf("manager-controller failed to watch Network resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(controller); err != nil {
		return fmt.Errorf("manager-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddNamespaceWatch(controller, common.TigeraPrometheusNamespace); err != nil {
		return fmt.Errorf("manager-controller failed to watch the '%s' namespace: %w", common.TigeraPrometheusNamespace, err)
	}

	// Watch for changes to primary resource ManagementCluster
	err = controller.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = controller.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}

	err = controller.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch resource: %w", err)
	}

	if err = utils.AddConfigMapWatch(controller, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace); err != nil {
		return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %v", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(controller, ResourceName); err != nil {
		return fmt.Errorf("manager-controller failed to watch manager Tigerastatus: %w", err)
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
func GetManager(ctx context.Context, cli client.Client, ns string) (*operatorv1.Manager, error) {
	key := client.ObjectKey{Name: "tigera-secure", Namespace: ns}

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
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	logc.Info("Reconciling Manager")

	if r.multiTenant && request.Namespace == "" {
		// For now, if we're running in multi-tenant mode, just skip any non-namespaced triggers.
		// A potential improvement here would be to reconcile multiple Manager instances.
		return reconcile.Result{}, nil
	}

	// In single-tenant mode, the manager is always global scoped. However, for multi-tenant mode
	// the manager instance will belong to a particualr namespace.
	ns := ""
	if r.multiTenant {
		ns = request.Namespace
	}

	// Fetch the Manager instance that corresponds with this reconcile trigger.
	instance, err := GetManager(ctx, r.client, ns)
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
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created", err, logc)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, logc)
			return reconcile.Result{}, err
		}
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, logc)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// TODO: Do we need a license per-tenant in the management cluster?
	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, logc)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, logc)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
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

	// Package up the request parameters needed to reconcile
	common := octrl.NewRequest(request.NamespacedName, r.multiTenant, render.ManagerNamespace)
	args := ReconcileArgs{
		Manager:      instance,
		Variant:      variant,
		Installation: installation,
		License:      license,
	}
	return r.reconcileInstance(ctx, logc, args, common)
}

type ReconcileArgs struct {
	Variant      operatorv1.ProductVariant
	Installation *operatorv1.InstallationSpec
	Manager      *operatorv1.Manager
	License      v3.LicenseKey
}

func (r *ReconcileManager) reconcileInstance(ctx context.Context, logc logr.Logger, args ReconcileArgs, request octrl.Request) (reconcile.Result, error) {
	certificateManager, err := certificatemanager.Create(r.client, args.Installation, r.clusterDomain, request.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, logc)
		return reconcile.Result{}, err
	}

	// Get or create a certificate for clients of the manager pod es-proxy container.
	svcDNSNames := append(dns.GetServiceDNSNames(render.ManagerServiceName, request.InstallNamespace(), r.clusterDomain), "localhost")
	tlsSecret, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		render.ManagerTLSSecretName,
		request.TruthNamespace(),
		svcDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting or creating manager TLS certificate", err, logc)
		return reconcile.Result{}, err
	}

	// Determine if compliance is enabled.
	complianceLicenseFeatureActive := utils.IsFeatureActive(args.License, common.ComplianceFeature)
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
			render.ProjectCalicoAPIServerTLSSecretName(args.Installation.Variant),
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

	// TODO: Trusted bundle for all components will be in the same namespace for multi-tenancy.
	// So, we'll need to refactor this. I think for multi-tenancy, we can simplify the trusted-bundle generation
	// altogether so that we only ever need a single cert for it. In single-tenant, we need more complexity in order
	// to support BYO certs.
	//
	// That said, it's probably a good idea to move certificate management to its own controller anyway so that
	// it's not so scattered!
	trustedBundle := certificateManager.CreateTrustedBundle()
	for _, secret := range trustedSecretNames {
		certificate, err := certificateManager.GetCertificate(r.client, secret, request.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.CertificateError, fmt.Sprintf("Failed to retrieve %s", secret), err, logc)
			return reconcile.Result{}, err
		} else if certificate == nil {
			logc.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secret))
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret '%s' to become available", secret), nil, logc)
			return reconcile.Result{}, nil
		}
		trustedBundle.AddCertificates(certificate)
	}
	certificateManager.AddToStatusManager(r.status, request.InstallNamespace())

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

	pullSecrets, err := utils.GetNetworkingPullSecrets(args.Installation, r.client)
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

	// We expect that the secret that holds the certificates for internal communication within the management
	// cluster is already created by kube-controllers.
	internalTrafficSecret, err := certificateManager.GetKeyPair(r.client, render.ManagerInternalTLSSecretName, request.TruthNamespace())
	if internalTrafficSecret == nil {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret %s in namespace %s to be available", render.ManagerInternalTLSSecretName, request.TruthNamespace()), nil, logc)
		return reconcile.Result{}, err
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error fetching TLS secret %s in namespace %s", render.ManagerInternalTLSSecretName, request.TruthNamespace()), err, logc)
		return reconcile.Result{}, nil
	}

	// Es-proxy needs to trust Voltron for cross-cluster requests.
	trustedBundle.AddCertificates(internalTrafficSecret)

	var linseedVoltronSecret certificatemanagement.KeyPairInterface
	var tunnelSecret certificatemanagement.KeyPairInterface

	if managementCluster != nil {
		preDefaultPatchFrom := client.MergeFrom(managementCluster.DeepCopy())
		fillDefaults(managementCluster)

		// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
		// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
		if err := r.client.Patch(ctx, managementCluster, preDefaultPatchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "", err, logc)
			return reconcile.Result{}, err
		}

		// Create a certificate for Voltron to use for TLS connections from the managed cluster destined
		// to Linseed. This certificate is used only for connections received over Voltron's mTLS tunnel targeting tigera-linseed.
		linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, render.ElasticsearchNamespace, r.clusterDomain)
		linseedVoltronSecret, err = certificateManager.GetOrCreateKeyPair(
			r.client,
			render.VoltronLinseedTLS,
			request.TruthNamespace(),
			linseedDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting or creating Voltron Linseed TLS certificate", err, logc)
			return reconcile.Result{}, err
		}

		// We expect that the secret that holds the certificates for tunnel certificate generation
		// is already created by the API server.
		// TODO: Need to make sure this secret is generated in per-tenant namespace by the tigera-apiserver.
		tunnelSecret, err = certificateManager.GetKeyPair(r.client, render.VoltronTunnelSecretName, request.TruthNamespace())
		if tunnelSecret == nil {
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret %s in namespace %s to be available", render.VoltronTunnelSecretName, request.TruthNamespace()), nil, logc)
			return reconcile.Result{}, err
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error fetching TLS secret %s in namespace %s", render.VoltronTunnelSecretName, request.TruthNamespace()), err, logc)
			return reconcile.Result{}, nil
		}
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
	handler := utils.NewComponentHandler(log, r.client, r.scheme, args.Manager)

	// Set replicas to 1 for management or managed clusters.
	// TODO Remove after MCM tigera-manager HA deployment is supported.
	var replicas *int32 = args.Installation.ControlPlaneReplicas
	if managementCluster != nil || managementClusterConnection != nil {
		var mcmReplicas int32 = 1
		replicas = &mcmReplicas
	}

	managerCfg := &render.ManagerConfiguration{
		KeyValidatorConfig:      keyValidatorConfig,
		ESSecrets:               esSecrets,
		TrustedCertBundle:       trustedBundle,
		ClusterConfig:           clusterConfig,
		TLSKeyPair:              tlsSecret,
		VoltronLinseedKeyPair:   linseedVoltronSecret,
		PullSecrets:             pullSecrets,
		Openshift:               r.provider == operatorv1.ProviderOpenShift,
		Installation:            args.Installation,
		ManagementCluster:       managementCluster,
		TunnelSecret:            tunnelSecret,
		InternalTLSKeyPair:      internalTrafficSecret,
		ClusterDomain:           r.clusterDomain,
		ESLicenseType:           elasticLicenseType,
		Replicas:                replicas,
		Compliance:              complianceCR,
		ComplianceLicenseActive: complianceLicenseFeatureActive,
		UsePSP:                  r.usePSP,
		Namespace:               request.InstallNamespace(),
		MultiTenant:             r.multiTenant,
	}

	// Render the desired objects from the CRD and create or update them.
	component, err := render.Manager(managerCfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering Manager", err, logc)
		return reconcile.Result{}, err
	}
	clusterScopedComponent, err := render.ManagerClusterScoped(managerCfg, []string{request.InstallNamespace()}) // TODO: All namespaces.
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering Manager", err, logc)
		return reconcile.Result{}, err
	}

	if err = imageset.ApplyImageSet(ctx, r.client, args.Variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
		return reconcile.Result{}, err
	}

	components := []render.Component{
		component,
		clusterScopedComponent,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       request.InstallNamespace(),
			TruthNamespace:  request.TruthNamespace(),
			ServiceAccounts: []string{render.ManagerServiceAccount},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				// We need to render the certificate manager CA cert again in case we're running in multi-tenant mode.
				// For single-tenant, this cert is created once by the core controller. For multi-tenant, we
				// provision a unique CA per-tenant, and so we need to make sure to create it here.
				//
				// TODO: We probably want a separate tenant controller managing the creation of of this instead, so
				// that individual controllers don't need to do this.
				rcertificatemanagement.NewKeyPairOption(certificateManager.KeyPair(), true, false),
				rcertificatemanagement.NewKeyPairOption(tlsSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(linseedVoltronSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(internalTrafficSecret, false, true),
				rcertificatemanagement.NewKeyPairOption(tunnelSecret, false, true),
			},
			TrustedBundle: trustedBundle,
		}),
	}
	for _, component := range components {
		if err := handler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	args.Manager.Status.State = operatorv1.TigeraStatusReady
	if r.status.IsAvailable() {
		if err = r.client.Status().Update(ctx, args.Manager); err != nil {
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
