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

package secrets

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/tigera/operator/pkg/common"
	octrl "github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_logstorage_secrets")

// SecretSubController is a sub controller for managing secrets related to Elasticsearch and log storage components.
// It provisions secrets and the trusted bundle into the requisite namespace(s) for other controllers to consume.
type SecretSubController struct {
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	clusterDomain string
	multiTenant   bool
}

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// Create the reconciler
	r := &SecretSubController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		clusterDomain: opts.ClusterDomain,
		multiTenant:   opts.MultiTenant,
		status:        status.New(mgr.GetClient(), "log-storage-secrets", opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-secrets-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenatn clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Network resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, "log-storage-secrets"); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if opts.MultiTenant {
		if err = c.Watch(&source.Kind{Type: &operatorv1.Tenant{}}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch Tenant resource: %w", err)
		}
	}

	// The namespace(s) we need to monitor depend upon what tenancy mode we're running in.
	installNS := render.ElasticsearchNamespace
	truthNS := common.OperatorNamespace()
	if opts.MultiTenant {
		// For multi-tenant, the manager could be installed in any number of namespaces.
		// So, we need to watch the resources we care about across all namespaces.
		installNS = ""
		truthNS = ""
	}

	// Watch all the elasticsearch user secrets in the operator namespace.
	// TODO: In the future, we may want put this logic in the utils folder where the other watch logic is.
	if err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Object.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return (truthNS == "" || e.Object.GetNamespace() == truthNS) && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.ObjectNew.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return (truthNS == "" || e.ObjectNew.GetNamespace() == truthNS) && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Object.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return (truthNS == "" || e.Object.GetNamespace() == truthNS) && hasLabel
		},
	}); err != nil {
		return err
	}

	// Watch all the secrets created by this controller so we can regenerate any that are deleted
	for _, secretName := range []string{
		render.TigeraElasticsearchGatewaySecret,
		render.TigeraKibanaCertSecret,
		esmetrics.ElasticsearchMetricsServerTLSSecret,
		render.TigeraLinseedSecret,
	} {
		if err = utils.AddSecretsWatch(c, secretName, truthNS); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
		}
	}

	// Watch trusted bundle configmaps.
	if err = utils.AddConfigMapWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace(), eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ConfigMap resource: %w", err)
	}
	if err = utils.AddConfigMapWatch(c, certificatemanagement.TenantCASecretName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ConfigMap resource: %w", err)
	}

	// Catch if something modifies the resources that this controller consumes.
	if err = utils.AddSecretsWatchWithHandler(c, relasticsearch.PublicCertSecret, truthNS, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}
	if err = utils.AddSecretsWatchWithHandler(c, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}
	if err = utils.AddSecretsWatchWithHandler(c, monitor.PrometheusClientTLSSecretName, truthNS, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}
	if err := utils.AddServiceWatchWithHandler(c, render.ElasticsearchServiceName, render.ElasticsearchNamespace, eventHandler); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, esgateway.ServiceName, installNS); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, render.LinseedServiceName, installNS); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	return nil
}

func (r *SecretSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - Secrets")

	// Get LogStorage resource.
	ls := &operatorv1.LogStorage{}
	key := utils.DefaultTSEEInstanceKey
	err := r.client.Get(ctx, key, ls)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for LogStorage to exist", err, reqLogger)
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	}

	// We found the LogStorage instance.
	r.status.OnCRFound()

	// When running in multi-tenant mode, we need to install Linseed in tenant Namespaces. However, the LogStorage
	// resource is still cluster-scoped (since ES is a cluster-wide resource), so we need to look elsewhere to determine
	// which tenant namespaces require a Linseed instance. We use the tenant API to determine the set of namespaces that should have a Linseed.
	var tenant *operatorv1.Tenant
	if r.multiTenant {
		if request.Namespace == "" {
			// In multi-tenant mode, we only handle namespaced reconcile triggers.
			return reconcile.Result{}, nil
		}

		// Check if there is a manager in this namespace.
		tenant, err = utils.GetTenant(ctx, r.client, request.Namespace)
		if errors.IsNotFound(err) {
			// No tenant in this namespace. Ignore the update.
			reqLogger.Info("No Tenant in this Namespace, skip")
			return reconcile.Result{}, nil
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Generate keys for Tigera components if we're running in multi-tenant mode and this is a reconcile
	// for a particular tenant, or if not in multi-tenant mode.
	reconcileTigeraSecrets := !r.multiTenant || r.multiTenant && tenant != nil

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if ls.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Get Installation resource.
	_, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Secrets only need to be provisioned into management or standalone clusters.
	if managementClusterConnection != nil {
		return reconcile.Result{}, nil
	}

	// Build the tenant-aware request object.
	req := octrl.NewRequest(request.NamespacedName, r.multiTenant, "tigera-elasticsearch")
	reqLogger = reqLogger.WithValues("installNS", req.InstallNamespace(), "truthNS", req.TruthNamespace())

	// In a multi-tenant system, secrets are organized in the following way:
	// - Each tenant has its own CA, in that tenant's namespace, used for signing tenant certificates.
	// - Elasticsearch has its own CA and KeyPair, that is global.
	// So, we create two certificate managers - one for managing per-tenant keypairs signed with the per-tenant CA,
	// and another for cluster-scoped keypairs signed with the root operator CA.
	var clusterCM, appCM certificatemanager.CertificateManager

	// Cluster-scoped certificate manager, used for managing Elasticsearch secrets.
	clusterCM, err = certificatemanager.CreateWithOptions(r.client, install, r.clusterDomain, common.OperatorNamespace(), certificatemanager.WithLogger(reqLogger))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	clusterCM.AddToStatusManager(r.status, render.ElasticsearchNamespace)

	// Determine if Kibana should be enabled for this cluster.
	kibanaEnabled := !operatorv1.IsFIPSModeEnabled(install.FIPSMode) && !r.multiTenant

	// Generate Elasticsearch / Kibana secrets as needed.
	elasticKeys, err := r.generateClusterSecrets(reqLogger, kibanaEnabled, clusterCM)
	if err != nil {
		return reconcile.Result{}, err
	}

	// For single-tenant systems, we use the same certificate manager for all certs.
	appCM = clusterCM
	if r.multiTenant {
		// Override with a tenant-scoped certificate manager which uses the CA in the tenant's namespace.
		opts := []certificatemanager.Option{
			certificatemanager.WithLogger(reqLogger),
			certificatemanager.WithTenant(tenant),
		}
		appCM, err = certificatemanager.CreateWithOptions(r.client, install, r.clusterDomain, req.InstallNamespace(), opts...)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create CA", err, reqLogger)
			return reconcile.Result{}, err
		}
		appCM.AddToStatusManager(r.status, render.ElasticsearchNamespace)
	}

	// Provision secrets and the trusted bundle into the cluster.
	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)

	// Before we can create secrets, we need to ensure the tigera-elasticsearch namespace exists.
	esNamespace := render.CreateNamespace(render.ElasticsearchNamespace, install.KubernetesProvider, render.PSSPrivileged)
	if err = hdler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(esNamespace), r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create Elasticsearch secrets.
	esTrustedBundle := elasticKeys.trustedBundle(clusterCM)
	if err = hdler.CreateOrUpdateOrDelete(ctx, elasticKeys.component(esTrustedBundle), r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	if kibanaEnabled {
		// Create the Namespace.
		kbNamespace := render.CreateNamespace(render.KibanaNamespace, install.KubernetesProvider, render.PSSPrivileged)
		if err = hdler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(kbNamespace), r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Render the key pair and trusted bundle into the Kibana namespace.
		if err = hdler.CreateOrUpdateOrDelete(ctx, elasticKeys.kibanaComponent(esTrustedBundle), r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Check if we need to reconcile Tigera secrets for this trigger.
	if !reconcileTigeraSecrets {
		reqLogger.Info("Skipping render of secrets for Tigera ES components")
		return reconcile.Result{}, nil
	}
	reqLogger.Info("Rendering secrets for Tigera ES components")

	// Create secrets for Tigera components.
	keyPairs, err := r.generateNamespacedSecrets(reqLogger, req, appCM)
	if err != nil {
		// Status manager is handled already, so we can just return
		return reconcile.Result{}, err
	}
	if keyPairs == nil {
		// Waiting for keys to be ready.
		reqLogger.Info("Waiting for key pairs to be ready")
		return reconcile.Result{}, nil
	}
	trustedBundle := keyPairs.trustedBundle(appCM)

	// TODO: Think more about this. It might actually make sense that the ES secrets for all tenants are owned by the LogStorage instance.
	// that way, deleting / re-creating a tenant doesn't delete all of their secrets (thus invalidating all clients).
	// If we're running in multi-tenant mode, these should be owned by the
	// Tenant instance for that tenant. Otherwise, it's owned by the LogStorage instance.
	// if r.multiTenant {
	// 	// For multi-tenant mode, secrets are owned by the tenant instance.
	// 	hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, tenant)
	// }

	if err = hdler.CreateOrUpdateOrDelete(ctx, keyPairs.component(trustedBundle, req), r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: 60 * time.Second}, nil
}

// generateClusterSecrets generates secrets that are cluster-scoped in a multi-tenant environment
// and shared by all tenants. For example, Elasticsearch is a shared resource and so only a single set of certificates
// is needed.
func (r *SecretSubController) generateClusterSecrets(log logr.Logger, kibana bool, cm certificatemanager.CertificateManager) (*elasticKeyPairCollection, error) {
	collection := elasticKeyPairCollection{log: log}

	// Generate a keypair for elasticsearch.
	//
	// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	// Elasticsearch is always in the tigera-elasticsearch namespace, and is shared across tenants, so should always be stored in the
	// tigera-operator namespace.
	esDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	elasticKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), esDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Elasticsearch secrets", err, log)
		return nil, err
	}
	collection.elastic = elasticKeyPair

	if !r.multiTenant {
		// Generate a keypair for Kibana.
		//
		// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
		// It will be provisioned into the cluster in the render stage later on.
		if kibana {
			kbDNSNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, r.clusterDomain)
			kibanaKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraKibanaCertSecret, common.OperatorNamespace(), kbDNSNames)
			if err != nil {
				log.Error(err, err.Error())
				r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Kibana secrets", err, log)
				return nil, err
			}
			collection.kibana = kibanaKeyPair
		}
	}

	return &collection, nil
}

// generateNamespacedSecrets creates keypairs for components that are provisioned per-tenant in a multi-tenant system.
func (r *SecretSubController) generateNamespacedSecrets(log logr.Logger, req octrl.Request, cm certificatemanager.CertificateManager) (*keyPairCollection, error) {
	// Start by collecting upstream certificates that we need to trust, before generating keypairs.
	collection, err := r.collectUpstreamCerts(log, req, cm)
	if err != nil {
		return nil, err
	}

	if !r.multiTenant {
		// Create a server key pair for the ES metrics server.
		metricsDNSNames := dns.GetServiceDNSNames(esmetrics.ElasticsearchMetricsName, req.InstallNamespace(), r.clusterDomain)
		metricsServerKeyPair, err := cm.GetOrCreateKeyPair(r.client, esmetrics.ElasticsearchMetricsServerTLSSecret, req.TruthNamespace(), metricsDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error finding or creating TLS certificate", err, log)
			return nil, err
		}
		collection.keypairs = append(collection.keypairs, metricsServerKeyPair)

		// ES gateway keypair.
		gatewayDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, req.InstallNamespace(), r.clusterDomain)
		gatewayDNSNames = append(gatewayDNSNames, dns.GetServiceDNSNames(esgateway.ServiceName, req.InstallNamespace(), r.clusterDomain)...)
		gatewayKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, req.TruthNamespace(), gatewayDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
			return nil, err
		}
		collection.keypairs = append(collection.keypairs, gatewayKeyPair)
	}

	// Create a server key pair for Linseed to present to clients.
	//
	// This fetches the existing key pair from the truth namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, req.InstallNamespace(), r.clusterDomain)
	linseedKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedSecret, req.TruthNamespace(), linseedDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.keypairs = append(collection.keypairs, linseedKeyPair)

	// Create a key pair for Linseed to use for tokens.
	linseedTokenKP, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedTokenSecret, req.TruthNamespace(), []string{"localhost"})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.keypairs = append(collection.keypairs, linseedTokenKP)

	return collection, nil
}

// collectUpstreamCerts collects certificates generated by upstream components to be added to the trusted bundle
// provisioned by this controller.
func (r *SecretSubController) collectUpstreamCerts(log logr.Logger, req octrl.Request, cm certificatemanager.CertificateManager) (*keyPairCollection, error) {
	collection := keyPairCollection{log: log}

	// Get upstream certificates that we depend on, but aren't created by this controller. Some of these are
	// only relevant for certain cluster types, so we will build the collection even if they aren't present and
	// add them in later if they appear.
	//
	// These certificates are used as part of the trusted bundle for verifying TLS connections. Generally, these will be
	// redundant because all certificates will be signed by the root CA. However, in some scenarios custom certificates may
	// be used, in which case they must be present in the bundle.
	//
	// Each entry is the name of the secret, and the value is the Namespace to query it from.
	certs := map[string]string{
		// Get certificate for TLS on Prometheus metrics endpoints. This is created in the monitor controller.
		monitor.PrometheusClientTLSSecretName: common.OperatorNamespace(),

		// Get certificate for es-proxy, which Linseed and es-gateway need to trust.
		render.ManagerTLSSecretName: req.TruthNamespace(),

		// Get certificate for fluentd, which Linseed needs to trust in a standalone or management cluster.
		render.FluentdPrometheusTLSSecretName: common.OperatorNamespace(),

		// Get certificate for intrusion detection controller, which Linseed needs to trust in a standalone or management cluster.
		render.IntrusionDetectionTLSSecretName: common.OperatorNamespace(),
		render.AnomalyDetectorTLSSecretName:    common.OperatorNamespace(),

		// Get certificate for DPI, which Linseed needs to trust in a standalone or management cluster.
		render.DPITLSSecretName: common.OperatorNamespace(),

		// Get compliance certificates, which Linseed needs to trust.
		render.ComplianceServerCertSecret:  common.OperatorNamespace(),
		render.ComplianceSnapshotterSecret: common.OperatorNamespace(),
		render.ComplianceBenchmarkerSecret: common.OperatorNamespace(),
		render.ComplianceReporterSecret:    common.OperatorNamespace(),

		// Get certificate for policy-recommendation, which Linseed needs to trust.
		render.PolicyRecommendationTLSSecretName: common.OperatorNamespace(),

		// Linseed and es-gateway need to trust the
		render.TigeraElasticsearchInternalCertSecret: common.OperatorNamespace(),

		// es-gateay and Linseed need to trust certificates signed by the root tigera-operator CA.
		// TODO: Why is this needed in addition to the elasticsearch internal cert above?
		certificatemanagement.CASecretName: common.OperatorNamespace(),
	}

	for certName, certNamespace := range certs {
		cert, err := cm.GetCertificate(r.client, certName, certNamespace)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get certificate", err, log)
			return nil, err
		} else if cert == nil {
			msg := fmt.Sprintf("%s/%s secret not available yet, will add it if/when it becomes available", certNamespace, certName)
			log.Info(msg)
		} else {
			log.V(2).Info("Adding upstream certificate", "cert", certName)
			collection.upstreamCerts = append(collection.upstreamCerts, cert)
		}
	}

	return &collection, nil
}

// elasticKeyPairCollection is a helper struct for managing elastic and kibana key pairs.
type elasticKeyPairCollection struct {
	// Context logger to use.
	log logr.Logger

	elastic       certificatemanagement.KeyPairInterface
	kibana        certificatemanagement.KeyPairInterface
	upstreamCerts []certificatemanagement.CertificateInterface
}

// trustedBundle creates a certificate bundle using the keypairs and certificates from the collection.
func (c *elasticKeyPairCollection) trustedBundle(cm certificatemanager.CertificateManager) certificatemanagement.TrustedBundle {
	certs := []certificatemanagement.CertificateInterface{
		// TODO: For mTLS with Elastic, we need to include Linseed certs as well.
		// TODO: For mTLS Kibana support, we need to include es-proxy cert.
		c.elastic, c.kibana,
	}
	certs = append(certs, c.upstreamCerts...)
	return cm.CreateTrustedBundle(certs...)
}

func (c *elasticKeyPairCollection) component(bundle certificatemanagement.TrustedBundle) render.Component {
	return rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      render.ElasticsearchNamespace,
		TruthNamespace: common.OperatorNamespace(),
		ServiceAccounts: []string{
			render.ElasticsearchName,
		},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			// We do not want to delete the elastic keypair secret from the tigera-elasticsearch namespace when CertificateManagement is
			// enabled. Instead, it will be replaced with a dummy secret that serves merely to pass ECK's validation checks.
			rcertificatemanagement.NewKeyPairOption(c.elastic, true, c.elastic != nil && !c.elastic.UseCertificateManagement()),
		},
		TrustedBundle: bundle,
	})
}

func (c *elasticKeyPairCollection) kibanaComponent(bundle certificatemanagement.TrustedBundle) render.Component {
	return rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       render.KibanaNamespace,
		ServiceAccounts: []string{render.KibanaName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			// We do not want to delete the secret from the tigera-elasticsearch when CertificateManagement is
			// enabled. Instead, it will be replaced with a TLS secret that serves merely to pass ECK's validation
			// checks.
			rcertificatemanagement.NewKeyPairOption(c.kibana, true, c.kibana != nil && !c.kibana.UseCertificateManagement()),
		},
		TrustedBundle: bundle,
	})
}

// A helper struct for managing the multitude of Tigera component secrets that are managed by or
// used by this controller.
type keyPairCollection struct {
	// Context logger to use.
	log logr.Logger

	// Certificates that need to be added to the trusted bundle, but
	// aren't actually generated by this controller.
	// Prometheus, es-proxy, fluentd, all compliance components.
	upstreamCerts []certificatemanagement.CertificateInterface

	// Key pairs that are generated by this controller. These need to be
	// provisioned into a namespace, as well as added to the trusted bundle.
	keypairs []certificatemanagement.KeyPairInterface
}

// trustedBundle creates a certificate bundle using the keypairs and certificates from the collection.
func (c *keyPairCollection) trustedBundle(cm certificatemanager.CertificateManager) certificatemanagement.TrustedBundle {
	certs := []certificatemanagement.CertificateInterface{}
	for _, key := range c.keypairs {
		certs = append(certs, key.(certificatemanagement.CertificateInterface))
	}
	certs = append(certs, c.upstreamCerts...)
	return cm.CreateTrustedBundle(certs...)
}

func (c keyPairCollection) component(bundle certificatemanagement.TrustedBundle, request octrl.Request) render.Component {
	// Create a render.Component to provision or update key pairs and the trusted bundle.
	kpos := []rcertificatemanagement.KeyPairOption{}

	// For each keypair collection provided, create a KeyPairOption to provision the keys into the namespace.
	for _, kp := range c.keypairs {
		kpos = append(kpos, rcertificatemanagement.NewKeyPairOption(kp, true, true))
	}

	return rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      request.InstallNamespace(),
		TruthNamespace: request.TruthNamespace(),
		ServiceAccounts: []string{
			// TODO: Dynamically build serviceaccounts list.
			linseed.ServiceAccountName,
			esgateway.ServiceAccountName,
			esmetrics.ElasticsearchMetricsName,
			render.IntrusionDetectionName,
			dpi.DeepPacketInspectionName,
			render.AnomalyDetectorsName,
		},
		KeyPairOptions: kpos,
		TrustedBundle:  bundle,
	})
}
