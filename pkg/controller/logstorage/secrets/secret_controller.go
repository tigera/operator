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

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Network resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, "log-storage-secrets"); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}

	// Watch all the elasticsearch user secrets in the operator namespace.
	// TODO: In the future, we may want put this logic in the utils folder where the other watch logic is.
	if err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Object.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.Object.GetNamespace() == common.OperatorNamespace() && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.ObjectNew.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.ObjectNew.GetNamespace() == common.OperatorNamespace() && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Object.GetLabels()[logstoragecommon.TigeraElasticsearchUserSecretLabel]
			return e.Object.GetNamespace() == common.OperatorNamespace() && hasLabel
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
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
		}
	}

	// Catch if something modifies the resources that this controller consumes.
	if err = utils.AddSecretsWatch(c, relasticsearch.PublicCertSecret, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}
	if err = utils.AddSecretsWatch(c, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}
	if err = utils.AddSecretsWatch(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, render.ElasticsearchServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, esgateway.ServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, render.LinseedServiceName, render.ElasticsearchNamespace); err != nil {
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
		// Not finding the LogStorage CR is not an error, as a Managed cluster will not have this CR available but
		// there are still "LogStorage" related items that need to be set up
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}
		ls = nil
		r.status.OnCRNotFound()
	}

	// We found the LogStorage instance.
	// TODO: Wait for defaults to be filled before continuing.
	r.status.OnCRFound()

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

	certificateManager, err := certificatemanager.Create(r.client, install, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	certificateManager.AddToStatusManager(r.status, render.ElasticsearchNamespace)

	// Gather all the secrets we need.
	// TODO: Right now, we're hardcoding multi-tenancy to false.
	common := octrl.NewCommonRequest(request.NamespacedName, false, "tigera-elasticsearch")
	keyPairs, err := r.generateSecrets(reqLogger, certificateManager, install.FIPSMode, common)
	if err != nil {
		// Status manager is handled in r.generateSecrets, so we can just return
		return reconcile.Result{}, err
	}
	if keyPairs == nil {
		// Waiting for keys to be ready.
		return reconcile.Result{}, nil
	}
	trustedBundle := keyPairs.trustedBundle(certificateManager)

	// Provision secrets and the trusted bundle into the cluster.
	if managementClusterConnection == nil {
		hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)

		// Before we can create secrets, we need to ensure the tigera-elasticsearch and tigera-kibana namespaces exist.
		// TODO: tigera-kibana isn't always needed.
		esNamespace := render.CreateNamespace(render.ElasticsearchNamespace, install.KubernetesProvider, render.PSSPrivileged)
		kbNamespace := render.CreateNamespace(render.KibanaNamespace, install.KubernetesProvider, render.PSSPrivileged)
		if err = hdler.CreateOrUpdateOrDelete(ctx, render.NewPassthrough(esNamespace, kbNamespace), r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Create secrets in the tigera-elasticsearch namespace. We need to do this before the proceed check below,
		// since ES becoming ready is dependent on the secrets created by this component.
		if err = hdler.CreateOrUpdateOrDelete(ctx, keyPairs.component(trustedBundle, common), r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}

		if !operatorv1.IsFIPSModeEnabled(install.FIPSMode) {
			// Render the key pair and trusted bundle into the Kibana namespace, which should be created by the log storage component above.
			c := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
				Namespace:       render.KibanaNamespace,
				ServiceAccounts: []string{render.KibanaName},
				KeyPairOptions: []rcertificatemanagement.KeyPairOption{
					// We do not want to delete the secret from the tigera-elasticsearch when CertificateManagement is
					// enabled. Instead, it will be replaced with a TLS secret that serves merely to pass ECK's validation
					// checks.
					rcertificatemanagement.NewKeyPairOption(keyPairs.kibana, true, keyPairs.kibana != nil && !keyPairs.kibana.UseCertificateManagement()),
				},
				TrustedBundle: trustedBundle,
			})

			if err = hdler.CreateOrUpdateOrDelete(ctx, c, r.status); err != nil {
				r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
				return reconcile.Result{}, err
			}
		}
	}
	return reconcile.Result{}, nil
}

// generateSecrets generates all the necessary secrets for the tigera-elasticsearch namespace. Namely:
// - A trusted certificate bundle used by all components created in the tigera-elasticsearch namespace.
// - Individual keypairs for Linseed, es-gateway, es-metrics, and Elasticsearch itself.
func (r *SecretSubController) generateSecrets(
	log logr.Logger,
	cm certificatemanager.CertificateManager,
	fipsMode *operatorv1.FIPSMode,
	req octrl.CommonRequest,
) (*keyPairCollection, error) {
	collection := keyPairCollection{log: log}

	// Get upstream certificates that we depend on, but aren't created by this controller. Some of these are
	// only relevant for certain cluster types, so we will build the collection even if they aren't present and
	// add them in later if they appear.
	certs := []string{
		// Get certificate for TLS on Prometheus metrics endpoints. This is created in the monitor controller.
		monitor.PrometheusClientTLSSecretName,

		// Get certificate for es-proxy, which Linseed and es-gateway need to trust.
		render.ManagerTLSSecretName,

		// Get certificate for fluentd, which Linseed needs to trust in a standalone or management cluster.
		render.FluentdPrometheusTLSSecretName,

		// Get certificate for intrusion detection controller, which Linseed needs to trust in a standalone or management cluster.
		render.IntrusionDetectionTLSSecretName,
		render.AnomalyDetectorTLSSecretName,

		// Get certificate for DPI, which Linseed needs to trust in a standalone or management cluster.
		render.DPITLSSecretName,

		// Get compliance certificates, which Linseed needs to trust.
		render.ComplianceServerCertSecret,
		render.ComplianceSnapshotterSecret,
		render.ComplianceBenchmarkerSecret,
		render.ComplianceReporterSecret,

		// Get certificate for policy-recommendation, which Linseed needs to trust.
		render.PolicyRecommendationTLSSecretName,
	}
	for _, certName := range certs {
		cert, err := cm.GetCertificate(r.client, certName, req.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get certificate", err, log)
			return nil, err
		} else if cert == nil {
			msg := fmt.Sprintf("tigera-operator/%s secret not available yet, will add it if/when it becomes available", certName)
			log.Info(msg)
		} else {
			log.V(2).Info("Adding upstream certificate", "cert", certName)
			collection.upstreamCerts = append(collection.upstreamCerts, cert)
		}
	}

	// Generate a keypair for elasticsearch.
	// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	// Elasticsearch is always in the tigera-elasticsearch namespace.
	esDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	elasticKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchInternalCertSecret, req.TruthNamespace(), esDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Elasticsearch secrets", err, log)
		return nil, err
	}
	collection.elastic = elasticKeyPair

	if !r.multiTenant {
		// Generate a keypair for Kibana.
		// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
		// It will be provisioned into the cluster in the render stage later on.
		if !operatorv1.IsFIPSModeEnabled(fipsMode) {
			kbDNSNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, r.clusterDomain)
			kibanaKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraKibanaCertSecret, req.TruthNamespace(), kbDNSNames)
			if err != nil {
				log.Error(err, err.Error())
				r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Kibana secrets", err, log)
				return nil, err
			}
			collection.kibana = kibanaKeyPair
		}
	}

	// Create a server key pair for Linseed to present to clients.
	// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, req.InstallNamespace(), r.clusterDomain)
	linseedKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedSecret, req.TruthNamespace(), linseedDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.linseed = linseedKeyPair

	// Create a key pair for Linseed to use for tokens.
	linseedTokenKP, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedTokenSecret, req.TruthNamespace(), []string{"localhost"})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.linseedTokenKeyPair = linseedTokenKP

	// Create a server key pair for the ES metrics server.
	metricsDNSNames := dns.GetServiceDNSNames(esmetrics.ElasticsearchMetricsName, req.InstallNamespace(), r.clusterDomain)
	metricsServerKeyPair, err := cm.GetOrCreateKeyPair(r.client, esmetrics.ElasticsearchMetricsServerTLSSecret, req.TruthNamespace(), metricsDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error finding or creating TLS certificate", err, log)
		return nil, err
	}
	collection.metricsServer = metricsServerKeyPair

	// ES gateway keypair.
	gatewayDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, req.InstallNamespace(), r.clusterDomain)
	gatewayDNSNames = append(gatewayDNSNames, dns.GetServiceDNSNames(esgateway.ServiceName, req.InstallNamespace(), r.clusterDomain)...)
	gatewayKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, req.TruthNamespace(), gatewayDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.gateway = gatewayKeyPair

	return &collection, nil
}

// A helper struct for managing the multitude of secrets that are managed by or
// used by this controller.
type keyPairCollection struct {
	// Context logger to use.
	log logr.Logger

	// Certificates that need to be added to the trusted bundle, but
	// aren't actually generated by this controller.
	// Prometheus, es-proxy, fluentd, all compliance components.
	upstreamCerts []certificatemanagement.CertificateInterface

	// Key pairs that are generated by this controller. These need to be
	// provisioned into the namespace, as well as added to the trusted bundle.
	elastic       certificatemanagement.KeyPairInterface
	kibana        certificatemanagement.KeyPairInterface
	metricsServer certificatemanagement.KeyPairInterface
	gateway       certificatemanagement.KeyPairInterface

	// Certificate and key for Linseed to identify itself.
	linseed certificatemanagement.KeyPairInterface

	// Certificate and key for Linseed to provision and verify access tokens.
	linseedTokenKeyPair certificatemanagement.KeyPairInterface
}

func (c *keyPairCollection) trustedBundle(cm certificatemanager.CertificateManager) certificatemanagement.TrustedBundle {
	c.log.V(1).WithValues("keyPairs", c).Info("Generating a trusted bundle for tigera-elasticsearch")
	certs := []certificatemanagement.CertificateInterface{
		// Add certs that we ourselves are generating.
		c.elastic,
		c.kibana,
		c.linseed,
		c.metricsServer,
		c.gateway,
	}
	// Add certs that we need to trust from other controllers.
	return cm.CreateTrustedBundle(append(certs, c.upstreamCerts...)...)
}

func (c *keyPairCollection) component(bundle certificatemanagement.TrustedBundle, request octrl.CommonRequest) render.Component {
	// Create a render.Component to provision or update key pairs and the trusted bundle.
	c.log.V(1).WithValues("keyPairs", c).Info("Generating a certificate management component for tigera-elasticsearch")
	return rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      request.InstallNamespace(),
		TruthNamespace: request.TruthNamespace(),
		ServiceAccounts: []string{
			render.ElasticsearchName,
			linseed.ServiceAccountName,
			esgateway.ServiceAccountName,
			esmetrics.ElasticsearchMetricsName,
			render.IntrusionDetectionName,
			dpi.DeepPacketInspectionName,
			render.AnomalyDetectorsName,
		},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			// We do not want to delete the elastic keypair secret from the tigera-elasticsearch namespace when CertificateManagement is
			// enabled. Instead, it will be replaced with a dummy secret that serves merely to pass ECK's validation checks.
			rcertificatemanagement.NewKeyPairOption(c.elastic, true, c.elastic != nil && !c.elastic.UseCertificateManagement()),
			rcertificatemanagement.NewKeyPairOption(c.linseed, true, true),
			rcertificatemanagement.NewKeyPairOption(c.linseedTokenKeyPair, true, true),
			rcertificatemanagement.NewKeyPairOption(c.gateway, true, true),
			rcertificatemanagement.NewKeyPairOption(c.metricsServer, true, true),
		},
		TrustedBundle: bundle,
	})
}
