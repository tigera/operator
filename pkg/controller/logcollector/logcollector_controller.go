// Copyright (c) 2020,2022-2023 Tigera, Inc. All rights reserved.

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

package logcollector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

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

	operatorv1 "github.com/tigera/operator/api/v1"
	v1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

const ResourceName = "log-collector"

var log = logf.Log.WithName("controller_logcollector")

// Add creates a new LogCollector Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {

	var licenseAPIReady *utils.ReadyFlag
	var tierWatchReady *utils.ReadyFlag
	if opts.EnterpriseCRDExists {
		licenseAPIReady = &utils.ReadyFlag{}
		tierWatchReady = &utils.ReadyFlag{}
	}

	// create the reconciler
	reconciler := newReconciler(mgr, opts, licenseAPIReady, tierWatchReady)

	// Create a new controller
	controller, err := controller.New("logcollector-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return fmt.Errorf("Failed to create logcollector-controller: %v", err)
	}

	if opts.EnterpriseCRDExists {
		k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
		if err != nil {
			log.Error(err, "Failed to establish a connection to k8s")
			return err
		}
		go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, controller, k8sClient, log, tierWatchReady)
		go utils.WaitToAddLicenseKeyWatch(controller, k8sClient, log, licenseAPIReady)
		go utils.WaitToAddNetworkPolicyWatches(controller, k8sClient, log, []types.NamespacedName{
			{Name: render.FluentdPolicyName, Namespace: render.LogCollectorNamespace},
		})
	}

	if opts.MultiTenant {
		if err = controller.Watch(&source.Kind{Type: &operatorv1.Tenant{}}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("logcollector-controller failed to watch Tenant resource: %w", err)
		}
	}

	return add(mgr, controller, opts.EnterpriseCRDExists)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions, licenseAPIReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	c := &ReconcileLogCollector{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "log-collector", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
		usePSP:          opts.UsePSP,
		multiTenant:     opts.MultiTenant,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// add adds watches for resources that are available at startup
func add(mgr manager.Manager, c controller.Controller, enterpriseCRDExists bool) error {
	var err error

	// Watch for changes to primary resource LogCollector
	err = c.Watch(&source.Kind{Type: &operatorv1.LogCollector{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch primary resource: %v", err)
	}

	err = utils.AddAPIServerWatch(c)
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch APIServer resource: %v", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("logcollector-controller failed to watch Tigera network resource: %v", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch ImageSet: %w", err)
	}

	for _, secretName := range []string{
		relasticsearch.PublicCertSecret, monitor.PrometheusTLSSecretName,
		render.FluentdPrometheusTLSSecretName, render.TigeraLinseedSecret, render.VoltronLinseedPublicCert,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-collector-controller failed to watch the Secret resource(%s): %v", secretName, err)
		}
	}

	if enterpriseCRDExists {
		for _, secretName := range []string{
			render.ElasticsearchEksLogForwarderUserSecret,
			render.S3FluentdSecretName, render.EksLogForwarderSecret,
			render.SplunkFluentdTokenSecretName, render.SplunkFluentdCertificateSecretName,
		} {
			if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
				return fmt.Errorf("log-collector-controller failed to watch the Secret resource(%s): %v", secretName, err)
			}
		}
	}

	for _, configMapName := range []string{render.FluentdFilterConfigMapName, relasticsearch.ClusterConfigConfigMapName} {
		if err = utils.AddConfigMapWatch(c, configMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("logcollector-controller failed to watch ConfigMap %s: %v", configMapName, err)
		}
	}

	err = c.Watch(&source.Kind{Type: &corev1.Node{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch the node resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch log-collector Tigerastatus: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileLogCollector implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogCollector{}

// ReconcileLogCollector reconciles a LogCollector object
type ReconcileLogCollector struct {
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
	multiTenant     bool
}

// GetLogCollector returns the default LogCollector instance with defaults populated.
func GetLogCollector(ctx context.Context, cli client.Client) (*operatorv1.LogCollector, error) {
	// Fetch the instance. We only support a single instance named "tigera-secure".
	instance := &operatorv1.LogCollector{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Syslog != nil {
			_, _, _, err := url.ParseEndpoint(instance.Spec.AdditionalStores.Syslog.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("Syslog config has invalid Endpoint: %s", err)
			}
		}
	}

	return instance, nil
}

// fillDefaults sets the default value of CollectProcessPath, syslog LogTypes, if not set.
// This function returns the fields which were set to a default value in the logcollector instance.
func fillDefaults(instance *operatorv1.LogCollector) []string {
	// Keep track of whether we changed the LogCollector instance during reconcile, so that we know to save it.
	// Keep track of which fields were modified (helpful for error messages)
	modifiedFields := []string{}

	if instance.Spec.CollectProcessPath == nil {
		collectProcessPath := v1.CollectProcessPathEnable
		instance.Spec.CollectProcessPath = &collectProcessPath
		modifiedFields = append(modifiedFields, "CollectProcessPath")
	}
	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Syslog != nil {
			syslog := instance.Spec.AdditionalStores.Syslog
			// Special case: For users that have a Syslog config and are upgrading from an older release
			//  where logTypes field did not exist, we will auto-populate default values for
			// them. This should only happen on upgrade, since logTypes is a required field.
			if syslog.LogTypes == nil || len(syslog.LogTypes) == 0 {
				// Set default log types to everything except for v1.SyslogLogIDSEvents (since this
				// option was not available prior to the logTypes field being introduced). This ensures
				// existing users continue to get the same expected behavior for Syslog forwarding.
				instance.Spec.AdditionalStores.Syslog.LogTypes = []v1.SyslogLogType{
					v1.SyslogLogAudit,
					v1.SyslogLogDNS,
					v1.SyslogLogFlows,
				}
				// Include the field that was modified (in case we need to display error messages)
				modifiedFields = append(modifiedFields, "AdditionalStores.Syslog.LogTypes")
			}
			if len(syslog.Encryption) == 0 {
				instance.Spec.AdditionalStores.Syslog.Encryption = v1.EncryptionNone
				// Include the field that was modified (in case we need to display error messages)
				modifiedFields = append(modifiedFields, "AdditionalStores.Syslog.Encryption")
			}
		}
	}
	return modifiedFields
}

// Reconcile reads that state of the cluster for a LogCollector object and makes changes based on the state read
// and what is in the LogCollector.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogCollector) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogCollector")
	var license v3.LicenseKey
	var err error
	// Fetch the LogCollector instance
	instance, err := GetLogCollector(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("LogCollector object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for LogCollector", err, reqLogger)
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating LogCollector status conditions
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create LogCollector status conditions.")
			return reconcile.Result{}, err
		}
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	variant, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if variant != operatorv1.TigeraSecureEnterprise && (instance.Spec.AdditionalStores != nil || instance.Spec.CollectProcessPath != nil) {
		r.status.SetDegraded(operatorv1.InvalidConfigurationError, "Additional log sources can be configured only in calico enterprise.", nil, reqLogger)
		return reconcile.Result{}, fmt.Errorf("Additional log sources can be configured only in calico enterprise.")
	}

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	if variant == operatorv1.TigeraSecureEnterprise {
		// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
		if !r.tierWatchReady.IsReady() {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}

		// Default fields on the LogCollector instance if needed.
		// Ensure the allow-tigera tier exists, before rendering any network policies within it.
		if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
			if errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created", err, reqLogger)
				return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
			} else {
				log.Error(err, "Error querying allow-tigera tier")
				r.status.SetDegraded(operatorv1.ResourceNotReady, "Error querying allow-tigera tier", err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		preDefaultPatchFrom := client.MergeFrom(instance.DeepCopy())
		modifiedFields := fillDefaults(instance)
		if len(modifiedFields) > 0 {
			if err = r.client.Patch(ctx, instance, preDefaultPatchFrom); err != nil {
				r.status.SetDegraded(operatorv1.ResourcePatchError, fmt.Sprintf("Failed to set defaults for LogCollector fields: [%s]",
					strings.Join(modifiedFields, ", "),
				), err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		if !r.licenseAPIReady.IsReady() {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}

		license, err = utils.FetchLicenseKey(ctx, r.client)
		if err != nil {
			if errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, reqLogger)
				return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}
	var esClusterConfig *relasticsearch.ClusterConfig
	if variant == operatorv1.TigeraSecureEnterprise {
		esClusterConfig, err = utils.GetElasticsearchClusterConfig(ctx, r.client)
		if err != nil {
			if errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceNotReady, "Elasticsearch cluster configuration is not available, waiting for it to become available", err, reqLogger)
				return reconcile.Result{}, nil
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get the elasticsearch cluster configuration", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Try to grab the ManagementClusterConnection CR because we need it for network policy rendering,
	// as well as validation with respect to Syslog.logTypes.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		// Not finding a ManagementClusterConnection CR is not an error, as only a managed cluster will
		// have this CR available, but we should communicate any other kind of error that we encounter.
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "An error occurred while looking for a ManagementClusterConnection", err, reqLogger)
			return reconcile.Result{}, err
		}
	}
	managedCluster := managementClusterConnection != nil

	var managementCluster *operatorv1.ManagementCluster
	if variant == operatorv1.TigeraSecureEnterprise {
		managementCluster, err = utils.GetManagementCluster(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	certificateManager, err := certificatemanager.Create(r.client, installation, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	// fluentdKeyPair is the key pair fluentd presents to identify itself
	fluentdKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, render.FluentdPrometheusTLSSecretName, common.OperatorNamespace(), []string{render.FluentdPrometheusTLSSecretName})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
		return reconcile.Result{}, err
	}

	var prometheusCertificate certificatemanagement.CertificateInterface
	if variant == operatorv1.TigeraSecureEnterprise {
		prometheusCertificate, err = certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get certificate", err, reqLogger)
			return reconcile.Result{}, err
		} else if prometheusCertificate == nil {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Prometheus secrets are not available yet, waiting until they become available", nil, reqLogger)
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		}
	}

	// Determine whether or not this is a multi-tenant management cluster.
	multiTenantManagement := r.multiTenant && managementCluster != nil
	if instance.Spec.MultiTenantManagementClusterNamespace != "" && !multiTenantManagement {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "multiTenantManagementClusterNamespace can only be set on multi-tenant management clusters", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// The name of the Linseed certificate varies based on if this is a managed cluster or not.
	// For standalone and management clusters, we just use Linseed's actual certificate.
	linseedCertName := render.TigeraLinseedSecret
	linseedCertNamespace := common.OperatorNamespace()
	var tenant *operatorv1.Tenant
	if managedCluster {
		// For managed clusters, we need to add the certificate of the Voltron endpoint. This certificate is copied from the
		// management cluster into the managed cluster by kube-controllers.
		linseedCertName = render.VoltronLinseedPublicCert
	} else if multiTenantManagement {
		// For multi-tenant management clusters, the linseed certificate isn't in the tigera-operator namespace. Instead, each Linseed has its own
		// certificate in the namespace of the tenant it belongs to. We need to figure out which Linseed belongs to the management cluster itself,
		// and use that certificate instead. We can find this out by looking at the multiTenantManagementClusterNamespace field.
		if instance.Spec.MultiTenantManagementClusterNamespace == "" {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "multiTenantManagementClusterNamespace is not set", nil, reqLogger)
			return reconcile.Result{}, nil
		}
		linseedCertNamespace = instance.Spec.MultiTenantManagementClusterNamespace

		// Make sure that a tenant actually exists in the configured namespace before continuing.
		tenant, _, err = utils.GetTenant(ctx, r.multiTenant, r.client, instance.Spec.MultiTenantManagementClusterNamespace)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Failed to retrieve tenant in ns %s", instance.Spec.MultiTenantManagementClusterNamespace), err, reqLogger)
			return reconcile.Result{}, err
		}
	}
	linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertName, linseedCertNamespace)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("Failed to retrieve / validate  %s/%s", linseedCertNamespace, linseedCertName), err, reqLogger)
		return reconcile.Result{}, err
	} else if linseedCertificate == nil {
		msg := fmt.Sprintf("Linseed certificate (%s/%s) is not yet available", linseedCertNamespace, linseedCertName)
		log.Info(msg)
		r.status.SetDegraded(operatorv1.ResourceNotReady, msg, nil, reqLogger)
		return reconcile.Result{}, nil
	}

	trustedBundleCerts := []certificatemanagement.CertificateInterface{linseedCertificate}
	if variant == operatorv1.TigeraSecureEnterprise {
		trustedBundleCerts = append(trustedBundleCerts, prometheusCertificate)
	}
	// Fluentd needs to mount system certificates in the case where Splunk, Syslog or AWS are used.
	trustedBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates(trustedBundleCerts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create tigera-ca-bundle configmap", err, reqLogger)
		return reconcile.Result{}, err
	}

	certificateManager.AddToStatusManager(r.status, render.LogCollectorNamespace)

	var s3Credential *render.S3Credential
	var splunkCredential *render.SplunkCredential
	var useSyslogCertificate bool
	if variant == operatorv1.TigeraSecureEnterprise {
		exportLogs := utils.IsFeatureActive(license, common.ExportLogsFeature)
		if !exportLogs && instance.Spec.AdditionalStores != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: export-logs", nil, reqLogger)
			return reconcile.Result{}, err
		}

		if instance.Spec.AdditionalStores != nil {
			if instance.Spec.AdditionalStores.S3 != nil {
				s3Credential, err = getS3Credential(r.client)
				if err != nil {
					r.status.SetDegraded(operatorv1.ResourceValidationError, "Error with S3 credential secret", err, reqLogger)
					return reconcile.Result{}, err
				}
				if s3Credential == nil {
					r.status.SetDegraded(operatorv1.ResourceNotFound, "S3 credential secret does not exist", nil, reqLogger)
					return reconcile.Result{}, nil
				}
			}
		}

		if instance.Spec.AdditionalStores != nil {
			if instance.Spec.AdditionalStores.Splunk != nil {
				splunkCredential, err = getSplunkCredential(r.client)
				if err != nil {
					r.status.SetDegraded(operatorv1.ResourceValidationError, "Error with Splunk credential secret", err, reqLogger)
					return reconcile.Result{}, err
				}
				if splunkCredential == nil {
					r.status.SetDegraded(operatorv1.ResourceNotFound, "Splunk credential secret does not exist", nil, reqLogger)
					return reconcile.Result{}, nil
				}
			}
		}

		if instance.Spec.AdditionalStores != nil {
			if instance.Spec.AdditionalStores.Syslog != nil && instance.Spec.AdditionalStores.Syslog.Encryption == v1.EncryptionTLS {
				syslogCert, err := getSysLogCertificate(r.client)
				if err != nil {
					r.status.SetDegraded(operatorv1.ResourceReadError, "Error loading Syslog certificate", err, reqLogger)
					return reconcile.Result{}, err
				}
				if syslogCert != nil {
					useSyslogCertificate = true
					trustedBundle.AddCertificates(syslogCert)
				}
			}
		}

		if instance.Spec.AdditionalStores != nil {
			if instance.Spec.AdditionalStores.Syslog != nil {
				syslog := instance.Spec.AdditionalStores.Syslog

				// If the user set Syslog.logTypes, we need to ensure that they did not include
				// the v1.SyslogLogIDSEvents option if this is a managed cluster (i.e.
				// ManagementClusterConnection CR is present). This is because IDS events
				// are only forwarded within a non-managed cluster (where LogStorage is present).
				if syslog.LogTypes != nil {
					if err == nil && managedCluster {
						for _, l := range syslog.LogTypes {
							// Set status to degraded to warn user and let them fix the issue themselves.
							if l == v1.SyslogLogIDSEvents {
								r.status.SetDegraded(operatorv1.ResourceValidationError, "IDSEvents option is not supported for Syslog config in a managed cluster", nil, reqLogger)
								return reconcile.Result{}, err
							}
						}
					}
				}
			}
		}
	}

	filters, err := getFluentdFilters(r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving Fluentd filters", err, reqLogger)
		return reconcile.Result{}, err
	}

	var eksConfig *render.EksCloudwatchLogConfig
	if variant == operatorv1.TigeraSecureEnterprise {
		if installation.KubernetesProvider == operatorv1.ProviderEKS {
			log.Info("Managed kubernetes EKS found, getting necessary credentials and config")
			if instance.Spec.AdditionalSources != nil {
				if instance.Spec.AdditionalSources.EksCloudwatchLog != nil {
					eksConfig, err = getEksCloudwatchLogConfig(r.client,
						instance.Spec.AdditionalSources.EksCloudwatchLog.FetchInterval,
						instance.Spec.AdditionalSources.EksCloudwatchLog.Region,
						instance.Spec.AdditionalSources.EksCloudwatchLog.GroupName,
						instance.Spec.AdditionalSources.EksCloudwatchLog.StreamPrefix)
					if err != nil {
						r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving EKS Cloudwatch Logs configuration", err, reqLogger)
						return reconcile.Result{}, err
					}
				}
			}
		}
	} else {
		// patch and get the felix configuration
		_, err = utils.PatchFelixConfiguration(ctx, r.client, func(fc *crdv1.FelixConfiguration) bool {
			patchRequired := false
			if fc.Spec.FlowLogsFileEnabled == nil || !(*fc.Spec.FlowLogsFileEnabled) {
				fc.Spec.FlowLogsFileEnabled = ptr.BoolToPtr(true)
				patchRequired = true
			}

			if fc.Spec.FlowLogsFileIncludeService == nil || !(*fc.Spec.FlowLogsFileIncludeService) {
				fc.Spec.FlowLogsFileIncludeService = ptr.BoolToPtr(true)
				patchRequired = true
			}

			if fc.Spec.FlowLogsFileIncludePolicies == nil || !(*fc.Spec.FlowLogsFileIncludePolicies) {
				fc.Spec.FlowLogsFileIncludePolicies = ptr.BoolToPtr(true)
				patchRequired = true
			}

			if fc.Spec.FlowLogsEnableHostEndpoint == nil || !(*fc.Spec.FlowLogsEnableHostEndpoint) {
				fc.Spec.FlowLogsEnableHostEndpoint = ptr.BoolToPtr(true)
				patchRequired = true
			}

			if fc.Spec.FlowLogsEnableNetworkSets == nil || !(*fc.Spec.FlowLogsEnableNetworkSets) {
				fc.Spec.FlowLogsEnableNetworkSets = ptr.BoolToPtr(true)
				patchRequired = true
			}
			return patchRequired // proceed with this patch
		})
		if err != nil {
			reqLogger.Error(err, "Error patching felix configuration")
			r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching felix configuration", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	fluentdCfg := &render.FluentdConfiguration{
		LogCollector:         instance,
		ESClusterConfig:      esClusterConfig,
		S3Credential:         s3Credential,
		SplkCredential:       splunkCredential,
		Filters:              filters,
		EKSConfig:            eksConfig,
		PullSecrets:          pullSecrets,
		Installation:         installation,
		ClusterDomain:        r.clusterDomain,
		OSType:               rmeta.OSTypeLinux,
		FluentdKeyPair:       fluentdKeyPair,
		TrustedBundle:        trustedBundle,
		ManagedCluster:       managedCluster,
		UsePSP:               r.usePSP,
		UseSyslogCertificate: useSyslogCertificate,
		Tenant:               tenant,
	}
	// Render the fluentd component for Linux
	comp := render.Fluentd(fluentdCfg)
	components := []render.Component{
		comp,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       render.LogCollectorNamespace,
			ServiceAccounts: []string{render.FluentdNodeName},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(fluentdKeyPair, true, true),
			},
			TrustedBundle: trustedBundle,
		}),
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, comp); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, comp := range components {
		if err := handler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Render a fluentd component for Windows if the cluster has Windows nodes.
	if variant == operatorv1.TigeraSecureEnterprise {
		hasWindowsNodes, err := hasWindowsNodes(r.client)
		if err != nil {
			return reconcile.Result{}, err
		}

		if hasWindowsNodes {
			fluentdCfg = &render.FluentdConfiguration{
				LogCollector:         instance,
				ESClusterConfig:      esClusterConfig,
				S3Credential:         s3Credential,
				SplkCredential:       splunkCredential,
				Filters:              filters,
				EKSConfig:            eksConfig,
				PullSecrets:          pullSecrets,
				Installation:         installation,
				ClusterDomain:        r.clusterDomain,
				OSType:               rmeta.OSTypeWindows,
				TrustedBundle:        trustedBundle,
				ManagedCluster:       managedCluster,
				UsePSP:               r.usePSP,
				UseSyslogCertificate: useSyslogCertificate,
				FluentdKeyPair:       fluentdKeyPair,
			}
			comp = render.Fluentd(fluentdCfg)

			if err = imageset.ApplyImageSet(ctx, r.client, variant, comp); err != nil {
				r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
				return reconcile.Result{}, err
			}

			// Create a component handler to manage the rendered component.
			handler = utils.NewComponentHandler(log, r.client, r.scheme, instance)

			if err := handler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
				r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
				return reconcile.Result{}, err
			}
		}
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CR status.
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func hasWindowsNodes(c client.Client) (bool, error) {
	nodes := corev1.NodeList{}
	err := c.List(context.Background(), &nodes, client.MatchingLabels{"kubernetes.io/os": "windows"})
	if err != nil {
		return false, err
	}

	return len(nodes.Items) > 0, nil
}

func getS3Credential(client client.Client) (*render.S3Credential, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      render.S3FluentdSecretName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), secretNamespacedName, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read secret %q: %s", render.S3FluentdSecretName, err)
	}

	var ok bool
	var kId []byte
	if kId, ok = secret.Data[render.S3KeyIdName]; !ok || len(kId) == 0 {
		return nil, fmt.Errorf(
			"Expected secret %q to have a field named %q",
			render.S3FluentdSecretName, render.S3KeyIdName)
	}
	var kSecret []byte
	if kSecret, ok = secret.Data[render.S3KeySecretName]; !ok || len(kSecret) == 0 {
		return nil, fmt.Errorf(
			"Expected secret %q to have a field named %q",
			render.S3FluentdSecretName, render.S3KeySecretName)
	}

	return &render.S3Credential{
		KeyId:     kId,
		KeySecret: kSecret,
	}, nil
}

func getSplunkCredential(client client.Client) (*render.SplunkCredential, error) {
	tokenSecret := &corev1.Secret{}
	tokenNamespacedName := types.NamespacedName{
		Name:      render.SplunkFluentdTokenSecretName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), tokenNamespacedName, tokenSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read secret %q: %s", render.SplunkFluentdTokenSecretName, err)
	}

	var ok bool
	var token []byte
	if token, ok = tokenSecret.Data[render.SplunkFluentdSecretTokenKey]; !ok || len(token) == 0 {
		return nil, fmt.Errorf(
			"Expected secret %q to have a field named %q",
			render.SplunkFluentdTokenSecretName, render.SplunkFluentdSecretTokenKey)
	}

	var certificate []byte
	certificateSecret := &corev1.Secret{}
	certificateNamespacedName := types.NamespacedName{
		Name:      render.SplunkFluentdCertificateSecretName,
		Namespace: common.OperatorNamespace(),
	}

	if err := client.Get(context.Background(), certificateNamespacedName, certificateSecret); err != nil {
		if errors.IsNotFound(err) {
			log.Info(fmt.Sprintf("Splunk certificate secret %v not provided. Assuming http protocol or trusted CA certificate.",
				render.SplunkFluentdCertificateSecretName))
		} else {
			return nil, fmt.Errorf("Failed to read secret %q: %s", render.SplunkFluentdCertificateSecretName, err)
		}
	} else {
		if certificate, ok = certificateSecret.Data[render.SplunkFluentdSecretCertificateKey]; !ok || len(certificate) == 0 {
			return nil, fmt.Errorf("Expected secret %q to have a field named %q",
				render.SplunkFluentdCertificateSecretName, render.SplunkFluentdSecretCertificateKey)
		}
	}

	return &render.SplunkCredential{
		Token:       token,
		Certificate: certificate,
	}, nil
}

func getFluentdFilters(client client.Client) (*render.FluentdFilters, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      render.FluentdFilterConfigMapName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read ConfigMap %q: %s", render.FluentdFilterConfigMapName, err)
	}

	return &render.FluentdFilters{
		Flow: cm.Data[render.FluentdFilterFlowName],
		DNS:  cm.Data[render.FluentdFilterDNSName],
	}, nil
}

func getEksCloudwatchLogConfig(client client.Client, interval int32, region, group, prefix string) (*render.EksCloudwatchLogConfig, error) {
	if region == "" {
		return nil, fmt.Errorf("Missing AWS region info")
	}

	if group == "" {
		return nil, fmt.Errorf("Missing Cloudwatch log group name")
	}

	if prefix == "" {
		prefix = "kube-apiserver-audit-"
	}

	if interval == 0 {
		interval = 60
	}

	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      render.EksLogForwarderSecret,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), secretNamespacedName, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read Secret %q: %s", render.EksLogForwarderSecret, err)
	}

	if len(secret.Data[render.EksLogForwarderAwsId]) == 0 ||
		len(secret.Data[render.EksLogForwarderAwsKey]) == 0 {
		return nil, fmt.Errorf("Incomplete Cloudwatch credentials")
	}

	return &render.EksCloudwatchLogConfig{
		AwsId:         secret.Data[render.EksLogForwarderAwsId],
		AwsKey:        secret.Data[render.EksLogForwarderAwsKey],
		AwsRegion:     region,
		GroupName:     group,
		StreamPrefix:  prefix,
		FetchInterval: interval,
	}, nil
}

func getSysLogCertificate(client client.Client) (certificatemanagement.CertificateInterface, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      render.SyslogCAConfigMapName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if errors.IsNotFound(err) {
			log.Info(fmt.Sprintf("ConfigMap %q is not found, assuming syslog's certificate is signed by publicly trusted CA", render.SyslogCAConfigMapName))
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read ConfigMap %q: %s", render.SyslogCAConfigMapName, err)
	}
	if len(cm.Data[corev1.TLSCertKey]) == 0 {
		log.Info(fmt.Sprintf("ConfigMap %q does not have a field named %q, assuming syslog's certificate is signed by publicly trusted CA", render.SyslogCAConfigMapName, corev1.TLSCertKey))
		return nil, nil
	}
	syslogCert := certificatemanagement.NewCertificate(render.SyslogCAConfigMapName, common.OperatorNamespace(), []byte(cm.Data[corev1.TLSCertKey]), nil)

	return syslogCert, nil
}
