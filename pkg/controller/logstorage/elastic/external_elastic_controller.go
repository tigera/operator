// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package elastic

import (
	"context"
	"fmt"
	"net/url"

	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage/externalelasticsearch"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ExternalESController struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client         client.Client
	scheme         *runtime.Scheme
	status         status.StatusManager
	provider       operatorv1.Provider
	tierWatchReady *utils.ReadyFlag
	clusterDomain  string
	usePSP         bool
	multiTenant    bool
}

func AddExternalES(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}
	if !opts.ElasticExternal {
		return nil
	}

	// Create the reconciler
	r := &ExternalESController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		status:        status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageElastic, opts.KubernetesVersion),
		usePSP:        opts.UsePSP,
		clusterDomain: opts.ClusterDomain,
		provider:      opts.DetectedProvider,
		multiTenant:   opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("log-storage-external-es-controllerr", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenant clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.WatchObject(&operatorv1.LogStorage{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch Installation resource: %w", err)
	}
	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ImageSet: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, initializer.TigeraStatusLogStorageElastic); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch logstorage Tigerastatus: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, "cloud-kibana-config", common.OperatorNamespace(), eventHandler); err != nil {
		return fmt.Errorf("log-storage-external-es-controller failed to watch the ConfigMap resource: %w", err)
	}

	if opts.MultiTenant {
		k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
		if err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to establish a connection to k8s: %w", err)
		}

		// Establish a watch for any tenant related changes
		if err = c.WatchObject(&operatorv1.Tenant{}, eventHandler); err != nil {
			return fmt.Errorf("log-storage-access-controller failed to watch Tenant resource: %w", err)
		}
		// Establish a watch on the tenant CA secret across all namespaces if multi-tenancy is enabled.
		if err = utils.AddSecretsWatch(c, certificatemanagement.TenantCASecretName, ""); err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to watch Secret resource: %w", err)
		}

		// The namespace(s) we need to monitor depend upon what tenancy mode we're running in.
		// For single-tenant, everything is installed in the tigera-manager namespace.
		// Make a helper for determining which namespaces to use based on tenancy mode.
		kibanaNamespaceHelper := utils.NewNamespaceHelper(opts.MultiTenant, kibana.Namespace, "")

		// Start goroutines to establish watches against projectcalico.org/v3 resources.
		go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, r.tierWatchReady)
		go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, []types.NamespacedName{
			{Name: kibana.PolicyName, Namespace: kibanaNamespaceHelper.InstallNamespace()},
			{Name: eck.OperatorPolicyName, Namespace: eck.OperatorNamespace},
			{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: kibanaNamespaceHelper.InstallNamespace()},
		})

		if err = c.WatchObject(&apps.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: eck.OperatorNamespace, Name: eck.OperatorName},
		}, eventHandler); err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to watch StatefulSet resource: %w", err)
		}

		if err = utils.AddConfigMapWatch(c, eck.LicenseConfigMapName, eck.OperatorNamespace, eventHandler); err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to watch ConfigMap resource: %w", err)
		}

		if err = c.WatchObject(&kbv1.Kibana{
			ObjectMeta: metav1.ObjectMeta{Namespace: kibanaNamespaceHelper.InstallNamespace(), Name: kibana.CRName},
		}, eventHandler); err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to watch Kibana resource: %w", err)
		}

		for _, secretName := range []string{
			kibana.TigeraKibanaCertSecret,
		} {
			if err = utils.AddSecretsWatch(c, secretName, kibanaNamespaceHelper.TruthNamespace()); err != nil {
				return fmt.Errorf("log-storage-elastic-controller failed to watch Secret resource: %w", err)
			}
		}

		if r.multiTenant {
			for _, secretName := range []string{
				kibana.MultiTenantCredentialsSecretName,
			} {
				if err = utils.AddSecretsWatch(c, secretName, kibanaNamespaceHelper.TruthNamespace()); err != nil {
					return fmt.Errorf("log-storage-elastic-controller failed to watch Secret resource: %w", err)
				}
			}
		}
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, eventHandler)
	if err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (r *ExternalESController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	kibanaHelper := utils.NewNamespaceHelper(r.multiTenant, kibana.Namespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.multiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// When running in multi-tenant mode, we need to install Kibana in tenant Namespaces. However, the LogStorage
	// resource is still cluster-scoped (since ES is a cluster-wide resource), so we need to look elsewhere to determine
	// which tenant namespaces require a Kibana instance. We use the tenant API to determine the set of namespaces that should have Kibana.
	tenant, tenantID, err := utils.GetTenant(ctx, r.multiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		reqLogger.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
		return reconcile.Result{}, err
	}

	ls := &operatorv1.LogStorage{}
	err = r.client.Get(ctx, utils.DefaultTSEEInstanceKey, ls)
	if err != nil {
		if !errors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}
	r.status.OnCRFound()

	variant, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
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
	if managementClusterConnection != nil {
		// LogStorage is not support on a managed cluster.
		r.status.SetDegraded(operatorv1.ResourceNotReady, "LogStorage is not supported on a managed cluster", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(install, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	esLicenseType, err := utils.GetElasticLicenseType(ctx, r.client, reqLogger)
	if err != nil {
		// If LicenseConfigMapName is not found, it means ECK operator is not running yet, log the information and proceed
		if errors.IsNotFound(err) {
			reqLogger.Info("ConfigMap not found yet", "name", eck.LicenseConfigMapName)
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get elastic license", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	var kibanaComponents []render.Component
	var kibanaEnabled = render.KibanaEnabled(tenant, install)
	if r.multiTenant && kibanaEnabled {
		// Collect the certificates we need to provision Kibana.
		// These will have been provisioned already by the ES secrets controller.
		opts := []certificatemanager.Option{
			certificatemanager.WithLogger(reqLogger),
			certificatemanager.WithTenant(tenant),
		}
		cm, err := certificatemanager.Create(r.client, install, r.clusterDomain, kibanaHelper.TruthNamespace(), opts...)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
			return reconcile.Result{}, err
		}

		// We want to retrieve Kibana certificate for all supported configurations
		kbDNSNames := dns.GetServiceDNSNames(kibana.ServiceName, kibanaHelper.InstallNamespace(), r.clusterDomain)
		kibanaKeyPair, err := cm.GetOrCreateKeyPair(r.client, kibana.TigeraKibanaCertSecret, kibanaHelper.TruthNamespace(), kbDNSNames)
		if err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Kibana secrets", err, reqLogger)
			return reconcile.Result{}, err
		}

		kbService, err := getKibanaService(ctx, r.client, kibanaHelper.InstallNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve the Kibana service", err, reqLogger)
			return reconcile.Result{}, err
		}
		kibanaCR, err := getKibana(ctx, r.client, kibanaHelper.InstallNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Kibana", err, reqLogger)
			return reconcile.Result{}, err
		}

		var unusedTLSSecret *corev1.Secret
		if install.CertificateManagement != nil {
			// Eck requires us to provide a TLS secret for Kibana. It will also inspect that it has a
			// certificate and private key. However, when certificate management is enabled, we do not want to use a
			// private key stored in a secret. For this reason, we mount a dummy that the actual Elasticsearch and Kibana
			// pods are never using.
			unusedTLSSecret, err = utils.GetSecret(ctx, r.client, relasticsearch.UnusedCertSecret, common.OperatorNamespace())
			if unusedTLSSecret == nil {
				unusedTLSSecret, err = certificatemanagement.CreateSelfSignedSecret(relasticsearch.UnusedCertSecret, common.OperatorNamespace(), relasticsearch.UnusedCertSecret, []string{})
				unusedTLSSecret.Data[corev1.TLSCertKey] = install.CertificateManagement.CACert
			}
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve secret %s/%s", common.OperatorNamespace(), relasticsearch.UnusedCertSecret), err, reqLogger)
				return reconcile.Result{}, nil
			}
		}

		// Query the trusted bundle from the namespace.
		trustedBundle, err := cm.LoadTrustedBundle(ctx, r.client, tenant.Namespace)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, reqLogger)
			return reconcile.Result{}, err
		}

		// If we're using an external ES, the Tenant resource must specify the ES endpoint.
		if tenant == nil || tenant.Spec.Elastic == nil || tenant.Spec.Elastic.URL == "" {
			reqLogger.Error(nil, "Elasticsearch URL must be specified for this tenant")
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Elasticsearch URL must be specified for this tenant", nil, reqLogger)
			return reconcile.Result{}, nil
		}

		// Determine the host and port from the URL.
		elasticURL, err := url.Parse(tenant.Spec.Elastic.URL)
		if err != nil {
			reqLogger.Error(err, "Elasticsearch URL is invalid")
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Elasticsearch URL is invalid", err, reqLogger)
			return reconcile.Result{}, nil
		}

		var challengerClientCertificate *corev1.Secret
		if tenant.ElasticMTLS() {
			// If mTLS is enabled, get the secret containing the CA and client certificate.
			challengerClientCertificate = &corev1.Secret{}
			err = r.client.Get(ctx, client.ObjectKey{Name: logstorage.ExternalCertsSecret, Namespace: common.OperatorNamespace()}, challengerClientCertificate)
			if err != nil {
				reqLogger.Error(err, "Failed to read external Elasticsearch client certificate secret")
				r.status.SetDegraded(operatorv1.ResourceReadError, "Waiting for external Elasticsearch client certificate secret to be available", err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		clusterIDConfigMap := corev1.ConfigMap{}
		clusterIDConfigMapKey := client.ObjectKey{Name: "cluster-info", Namespace: "tigera-operator"}
		err = r.client.Get(ctx, clusterIDConfigMapKey, &clusterIDConfigMap)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Waiting for ConfigMap %s/%s to be available", clusterIDConfigMapKey.Namespace, clusterIDConfigMapKey.Name),
				nil, reqLogger)
			return reconcile.Result{}, err
		}
		clusterID, ok := clusterIDConfigMap.Data["cluster-id"]
		if !ok {
			err = fmt.Errorf("%s/%s ConfigMap does not contain expected 'cluster-id' key",
				clusterIDConfigMap.Namespace, clusterIDConfigMap.Name)
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("%v", err), err, reqLogger)
			return reconcile.Result{}, err
		}

		kibanaComponents = append(kibanaComponents,
			rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
				Namespace:       kibanaHelper.InstallNamespace(),
				TruthNamespace:  kibanaHelper.TruthNamespace(),
				ServiceAccounts: []string{kibana.ObjectName},
				KeyPairOptions: []rcertificatemanagement.KeyPairOption{
					rcertificatemanagement.NewKeyPairOption(kibanaKeyPair, true, true),
				},
				TrustedBundle: nil,
			}),
			kibana.Kibana(&kibana.Configuration{
				LogStorage:                  ls,
				Installation:                install,
				Kibana:                      kibanaCR,
				KibanaKeyPair:               kibanaKeyPair,
				PullSecrets:                 pullSecrets,
				Provider:                    r.provider,
				KbService:                   kbService,
				ClusterDomain:               r.clusterDomain,
				BaseURL:                     tenant.KibanaBaseURL(),
				TrustedBundle:               trustedBundle,
				UnusedTLSSecret:             unusedTLSSecret,
				UsePSP:                      r.usePSP,
				Enabled:                     kibanaEnabled,
				Tenant:                      tenant,
				Namespace:                   kibanaHelper.InstallNamespace(),
				ChallengerClientCertificate: challengerClientCertificate,
				ExternalElasticURL:          elasticURL,
				KibanaUsername:              utils.KibanaUser(clusterID, tenantID).Username,
			}),
		)
	}

	flowShards := logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
	clusterConfig := relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)

	if !r.multiTenant {
		hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
		externalElasticsearch := externalelasticsearch.ExternalElasticsearch(install, clusterConfig, pullSecrets)
		if err := hdler.CreateOrUpdateOrDelete(ctx, externalElasticsearch, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if r.multiTenant && kibanaEnabled {
		// ECK will be deployed per management cluster and will be configured
		// to watch all namespaces in order to create a Kibana deployment
		eck := eck.ECK(&eck.Configuration{
			LogStorage:         ls,
			Installation:       install,
			ManagementCluster:  managementCluster,
			PullSecrets:        pullSecrets,
			Provider:           r.provider,
			ElasticLicenseType: esLicenseType,
			UsePSP:             r.usePSP,
			Tenant:             tenant,
		})
		hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
		if err := hdler.CreateOrUpdateOrDelete(ctx, eck, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}

		// In standard installs, the LogStorage owns the external elastic. For multi-tenant, it's owned by the Tenant instance.
		tenantHandler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, tenant)
		for _, component := range kibanaComponents {
			if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
				r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
				return reconcile.Result{}, err
			}
			if err := tenantHandler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
				r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
				return reconcile.Result{}, err
			}
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}
