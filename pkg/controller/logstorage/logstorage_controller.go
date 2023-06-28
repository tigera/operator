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

package logstorage

import (
	"context"
	"fmt"
	"time"

	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"

	"github.com/go-logr/logr"

	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_logstorage")

const (
	DefaultElasticsearchStorageClass = "tigera-elasticsearch"
	LogStorageFinalizer              = "tigera.io/eck-cleanup"
	ResourceName                     = "log-storage"

	defaultEckOperatorMemorySetting = "512Mi"
)

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// Create the reconciler
	tierWatchReady := &utils.ReadyFlag{}
	r, err := newReconciler(mgr.GetClient(), mgr.GetScheme(), status.New(mgr.GetClient(), "log-storage", opts.KubernetesVersion), opts, utils.NewElasticClient, tierWatchReady)
	if err != nil {
		return err
	}

	// Create the controller
	c, err := controller.New("log-storage-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("log-storage-controller failed to establish a connection to k8s: %w", err)
	}

	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, []types.NamespacedName{
		{Name: render.ElasticsearchPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: render.EsCuratorPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: render.KibanaPolicyName, Namespace: render.KibanaNamespace},
		{Name: render.ECKOperatorPolicyName, Namespace: render.ECKOperatorNamespace},
		{Name: render.ElasticsearchInternalPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.KibanaNamespace},
		{Name: esgateway.PolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: esmetrics.ElasticsearchMetricsPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: kubecontrollers.EsKubeControllerNetworkPolicyName, Namespace: common.CalicoNamespace},
		{Name: linseed.PolicyName, Namespace: render.ElasticsearchNamespace},
	})

	return add(mgr, c)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	opts options.AddOptions,
	esCliCreator utils.ElasticsearchClientCreator,
	tierWatchReady *utils.ReadyFlag,
) (*ReconcileLogStorage, error) {
	c := &ReconcileLogStorage{
		client:         cli,
		scheme:         schema,
		status:         statusMgr,
		provider:       opts.DetectedProvider,
		esCliCreator:   esCliCreator,
		clusterDomain:  opts.ClusterDomain,
		tierWatchReady: tierWatchReady,
		usePSP:         opts.UsePSP,
	}

	c.status.Run(opts.ShutdownContext)
	return c, nil
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, c controller.Controller) error {
	// Watch for changes to primary resource LogStorage
	err := c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Network resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ImageSet: %w", err)
	}

	if err := addLogStorageWatches(c); err != nil {
		return err
	}

	// Watch all the elasticsearch user secrets in the operator namespace. In the future, we may want put this logic in
	// the utils folder where the other watch logic is.
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
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
	})
	if err != nil {
		return err
	}

	// Watch all the secrets created by this controller so we can regenerate any that are deleted
	for _, secretName := range []string{
		render.TigeraElasticsearchGatewaySecret, render.TigeraKibanaCertSecret,
		render.OIDCSecretName, render.DexObjectName, esmetrics.ElasticsearchMetricsServerTLSSecret,
		render.TigeraLinseedSecret,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
		}
	}

	// Catch if something modifies the certs that this controller creates.
	if err = utils.AddSecretsWatch(c, relasticsearch.PublicCertSecret, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, render.ElasticsearchAdminUserSecret, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
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

	// Watch for changes to primary resource ManagementCluster
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileLogStorage implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogStorage{}

// ReconcileLogStorage reconciles a LogStorage object
type ReconcileLogStorage struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client         client.Client
	scheme         *runtime.Scheme
	status         status.StatusManager
	provider       operatorv1.Provider
	esCliCreator   utils.ElasticsearchClientCreator
	clusterDomain  string
	tierWatchReady *utils.ReadyFlag
	usePSP         bool
}

// fillDefaults populates the default values onto an LogStorage object.
func fillDefaults(opr *operatorv1.LogStorage) {
	if opr.Spec.Retention == nil {
		opr.Spec.Retention = &operatorv1.Retention{}
	}

	if opr.Spec.Retention.Flows == nil {
		var fr int32 = 8
		opr.Spec.Retention.Flows = &fr
	}
	if opr.Spec.Retention.AuditReports == nil {
		var arr int32 = 91
		opr.Spec.Retention.AuditReports = &arr
	}
	if opr.Spec.Retention.Snapshots == nil {
		var sr int32 = 91
		opr.Spec.Retention.Snapshots = &sr
	}
	if opr.Spec.Retention.ComplianceReports == nil {
		var crr int32 = 91
		opr.Spec.Retention.ComplianceReports = &crr
	}
	if opr.Spec.Retention.DNSLogs == nil {
		var dlr int32 = 8
		opr.Spec.Retention.DNSLogs = &dlr
	}
	if opr.Spec.Retention.BGPLogs == nil {
		var bgp int32 = 8
		opr.Spec.Retention.BGPLogs = &bgp
	}

	if opr.Spec.Indices == nil {
		opr.Spec.Indices = &operatorv1.Indices{}
	}

	if opr.Spec.Indices.Replicas == nil {
		var replicas int32 = render.DefaultElasticsearchReplicas
		opr.Spec.Indices.Replicas = &replicas
	}

	if opr.Spec.StorageClassName == "" {
		opr.Spec.StorageClassName = DefaultElasticsearchStorageClass
	}

	if opr.Spec.Nodes == nil {
		opr.Spec.Nodes = &operatorv1.Nodes{Count: 1}
	}

	if opr.Spec.ComponentResources == nil {
		limits := corev1.ResourceList{}
		requests := corev1.ResourceList{}
		limits[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
		requests[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
		opr.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
			{
				ComponentName: operatorv1.ComponentNameECKOperator,
				ResourceRequirements: &corev1.ResourceRequirements{
					Limits:   limits,
					Requests: requests,
				},
			},
		}
	}
}

func validateComponentResources(spec *operatorv1.LogStorageSpec) error {
	if spec.ComponentResources == nil {
		return fmt.Errorf("LogStorage spec.ComponentResources is nil %+v", spec)
	}
	// Currently the only supported component is ECKOperator.
	if len(spec.ComponentResources) > 1 {
		return fmt.Errorf("LogStorage spec.ComponentResources contains unsupported components %+v", spec.ComponentResources)
	}

	if spec.ComponentResources[0].ComponentName != operatorv1.ComponentNameECKOperator {
		return fmt.Errorf("LogStorage spec.ComponentResources.ComponentName %s is not supported", spec.ComponentResources[0].ComponentName)
	}

	return nil
}

func setLogStorageFinalizer(ls *operatorv1.LogStorage) {
	if ls.DeletionTimestamp == nil {
		if !stringsutil.StringInSlice(LogStorageFinalizer, ls.GetFinalizers()) {
			ls.SetFinalizers(append(ls.GetFinalizers(), LogStorageFinalizer))
		}
	}
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

func (c *keyPairCollection) component(bundle certificatemanagement.TrustedBundle) render.Component {
	// Create a render.Component to provision or update key pairs and the trusted bundle.
	c.log.V(1).WithValues("keyPairs", c).Info("Generating a certificate management component for tigera-elasticsearch")
	return rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace: render.ElasticsearchNamespace,
		ServiceAccounts: []string{
			render.ElasticsearchObjectName,
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

// generateSecrets generates all the necessary secrets for the tigera-elasticsearch namespace. Namely:
// - A trusted certificate bundle used by all components created in the tigera-elasticsearch namespace.
// - Individual keypairs for Linseed, es-gateway, es-metrics, and Elasticsearch itself.
func (r *ReconcileLogStorage) generateSecrets(
	log logr.Logger,
	cm certificatemanager.CertificateManager,
	fipsMode *operatorv1.FIPSMode,
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

		// Linseed needs the manager internal cert in order to verify the cert presented by Voltron when provisioning
		// tokens into managed clusters.
		render.ManagerInternalTLSSecretName,

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
		cert, err := cm.GetCertificate(r.client, certName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get certificate", err, log)
			return nil, err
		} else if cert == nil {
			msg := fmt.Sprintf("tigera-operator/%s secret not available yet, will add it if/when it becomes available", certName)
			log.Info(msg)
		} else {
			collection.upstreamCerts = append(collection.upstreamCerts, cert)
		}
	}

	// Generate a keypair for elasticsearch.
	// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	esDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	elasticKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), esDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Elasticsearch secrets", err, log)
		return nil, err
	}
	collection.elastic = elasticKeyPair

	// Generate a keypair for Kibana.
	// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	if !operatorv1.IsFIPSModeEnabled(fipsMode) {
		kbDNSNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, r.clusterDomain)
		kibanaKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraKibanaCertSecret, common.OperatorNamespace(), kbDNSNames)
		if err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Kibana secrets", err, log)
			return nil, err
		}
		collection.kibana = kibanaKeyPair
	}

	// Create a server key pair for Linseed to present to clients.
	// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	linseedKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedSecret, common.OperatorNamespace(), linseedDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.linseed = linseedKeyPair

	// Create a key pair for Linseed to use for tokens.
	linseedTokenKP, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedTokenSecret, common.OperatorNamespace(), []string{"localhost"})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.linseedTokenKeyPair = linseedTokenKP

	// Create a server key pair for the ES metrics server.
	metricsDNSNames := dns.GetServiceDNSNames(esmetrics.ElasticsearchMetricsName, render.ElasticsearchNamespace, r.clusterDomain)
	metricsServerKeyPair, err := cm.GetOrCreateKeyPair(r.client, esmetrics.ElasticsearchMetricsServerTLSSecret, common.OperatorNamespace(), metricsDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error finding or creating TLS certificate", err, log)
		return nil, err
	}
	collection.metricsServer = metricsServerKeyPair

	// ES gateway keypair.
	gatewayDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	gatewayDNSNames = append(gatewayDNSNames, dns.GetServiceDNSNames(esgateway.ServiceName, render.ElasticsearchNamespace, r.clusterDomain)...)
	gatewayKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), gatewayDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.gateway = gatewayKeyPair

	return &collection, nil
}

// Reconcile reads that state of the cluster for a LogStorage object and makes changes based on the state read
// and what is in the LogStorage.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogStorage) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

	var preDefaultPatchFrom client.Patch

	ls := &operatorv1.LogStorage{}
	err := r.client.Get(ctx, utils.DefaultTSEEInstanceKey, ls)
	if err != nil {
		// Not finding the LogStorage CR is not an error, as a Managed cluster will not have this CR available but
		// there are still "LogStorage" related items that need to be set up
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}
		ls = nil
		r.status.OnCRNotFound()
	} else {
		r.status.OnCRFound()

		// create predefaultpatch
		preDefaultPatchFrom = client.MergeFrom(ls.DeepCopy())

		fillDefaults(ls)
		err = validateComponentResources(&ls.Spec)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "An error occurred while validating LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}

		setLogStorageFinalizer(ls)

		// Write the logstorage back to the datastore
		if err = r.client.Patch(ctx, ls, preDefaultPatchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, "Failed to write defaults", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if ls != nil {
		// SetMetaData in the TigeraStatus such as observedGenerations.
		defer r.status.SetMetaData(&ls.ObjectMeta)
		// Changes for updating LogStorage status conditions.
		if request.Name == ResourceName && request.Namespace == "" {
			ts := &operatorv1.TigeraStatus{}
			err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
			if err != nil {
				return reconcile.Result{}, err
			}
			ls.Status.Conditions = status.UpdateStatusCondition(ls.Status.Conditions, ts.Status.Conditions)
			if err := r.client.Status().Update(ctx, ls); err != nil {
				log.WithValues("reason", err).Info("Failed to create LogStorage status conditions.")
				return reconcile.Result{}, err
			}
		}
	}

	variant, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created", err, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, reqLogger)
			return reconcile.Result{}, err
		}
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

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, err
	}

	// These checks ensure that we're in the correct state to continue to the render function without causing a panic
	if variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), nil, reqLogger)
		return reconcile.Result{}, nil
	} else if ls == nil && managementClusterConnection == nil {
		reqLogger.Info("LogStorage must exist for management and standalone clusters that require storage.")
		return reconcile.Result{}, nil
	} else if ls != nil && ls.DeletionTimestamp == nil && managementClusterConnection != nil {
		// Note that we check if the DeletionTimestamp is set as the render function is responsible for any cleanup needed
		// before the LogStorage CR can be deleted, and removing the finalizers from that CR
		r.status.SetDegraded(operatorv1.ResourceValidationError, "LogStorage validation failed - cluster type is managed but LogStorage CR still exists", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(install, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving the pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	esService, err := r.getElasticsearchService(ctx)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve the Elasticsearch service", err, reqLogger)
		return reconcile.Result{}, err
	}

	kbService, err := r.getKibanaService(ctx)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve the Kibana service", err, reqLogger)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, install, r.clusterDomain)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	certificateManager.AddToStatusManager(r.status, render.ElasticsearchNamespace)

	// Gather all the secrets we need.
	keyPairs, err := r.generateSecrets(reqLogger, certificateManager, install.FIPSMode)
	if err != nil {
		// Status manager is handled in r.generateSecrets, so we can just return
		return reconcile.Result{}, err
	}
	if keyPairs == nil {
		// Waiting for keys to be ready.
		return reconcile.Result{}, nil
	}
	trustedBundle := keyPairs.trustedBundle(certificateManager)

	var esAdminUserSecret *corev1.Secret
	var clusterConfig *relasticsearch.ClusterConfig
	var curatorSecrets []*corev1.Secret
	var esLicenseType render.ElasticsearchLicenseType
	var applyTrial bool
	var keyStoreSecret *corev1.Secret

	if managementClusterConnection == nil {
		flowShards := logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
		clusterConfig = relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)

		// Get the admin user secret to copy to the operator namespace.
		esAdminUserSecret, err = utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
		if err != nil {
			reqLogger.Error(err, "failed to get Elasticsearch admin user secret")
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch admin user secret", err, reqLogger)
			return reconcile.Result{}, err
		}
		if esAdminUserSecret != nil {
			esAdminUserSecret = rsecret.CopyToNamespace(common.OperatorNamespace(), esAdminUserSecret)[0]
		}

		curatorSecrets, err = utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchCuratorUserSecret}, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get curator credentials", err, reqLogger)
			return reconcile.Result{}, err
		}
		if operatorv1.IsFIPSModeEnabled(install.FIPSMode) {
			applyTrial, err = r.applyElasticTrialSecret(ctx, install)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get eck trial license", err, reqLogger)
				return reconcile.Result{}, err
			}

			keyStoreSecret = &corev1.Secret{}
			if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchKeystoreSecret, Namespace: common.OperatorNamespace()}, keyStoreSecret); err != nil {
				if errors.IsNotFound(err) {
					// We need to render a new one.
					keyStoreSecret = render.CreateElasticsearchKeystoreSecret()
				} else {
					log.Error(err, "failed to read the Elasticsearch keystore secret")
					r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read the Elasticsearch keystore secret", err, reqLogger)
					return reconcile.Result{}, err
				}
			}
		}
		esLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, reqLogger)
		if err != nil {
			// If ECKLicenseConfigMapName is not found, it means ECK operator is not running yet, log the information and proceed
			if errors.IsNotFound(err) {
				reqLogger.Info("ConfigMap not found yet", "name", render.ECKLicenseConfigMapName)
			} else {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get elastic license", err, reqLogger)
				return reconcile.Result{}, err
			}
		}
	}

	// If this is a Managed cluster ls must be nil to get to this point (unless the DeletionTimestamp is set) so we must
	// create the ComponentHandler from the managementClusterConnection.
	var hdler utils.ComponentHandler
	if ls != nil {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, managementClusterConnection)
	}

	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, reqLogger)
		return reconcile.Result{}, err
	}

	result, proceed, finalizerCleanup, err := r.createLogStorage(
		ls,
		install,
		variant,
		clusterConfig,
		managementCluster,
		managementClusterConnection,
		esAdminUserSecret,
		curatorSecrets,
		esLicenseType,
		esService,
		kbService,
		pullSecrets,
		authentication,
		hdler,
		reqLogger,
		ctx,
		applyTrial,
		keyStoreSecret,
		keyPairs.elastic,
		keyPairs.kibana,
		trustedBundle,
	)
	if ls != nil && ls.DeletionTimestamp != nil && finalizerCleanup {
		ls.SetFinalizers(stringsutil.RemoveStringInSlice(LogStorageFinalizer, ls.GetFinalizers()))

		// Write the logstorage back to the datastore
		if patchErr := r.client.Patch(ctx, ls, preDefaultPatchFrom); patchErr != nil {
			reqLogger.Error(patchErr, "Error patching the log-storage")
			r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching the log-storage", patchErr, reqLogger)
			return reconcile.Result{}, patchErr
		}
	}
	log.WithValues("proceed", proceed, "error", err).V(1).Info("createLogStorage result")
	if err != nil {
		return result, err
	}

	if managementClusterConnection == nil {
		// Create secrets in the tigera-elasticsearch namespace. We need to do this before the proceed check below,
		// since ES becoming ready is dependent on the secrets created by this component.
		if err = hdler.CreateOrUpdateOrDelete(ctx, keyPairs.component(trustedBundle), r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if !proceed {
		return result, err
	}

	if managementClusterConnection == nil {
		result, proceed, err = r.createESKubeControllers(
			install,
			hdler,
			reqLogger,
			managementCluster,
			authentication,
			esLicenseType,
			ctx,
		)
		if err != nil || !proceed {
			return result, err
		}
		result, proceed, err = r.createESGateway(
			install,
			variant,
			pullSecrets,
			esAdminUserSecret,
			hdler,
			reqLogger,
			ctx,
			keyPairs.gateway,
			trustedBundle,
			r.usePSP,
		)
		if err != nil || !proceed {
			return result, err
		}

		result, proceed, err = r.createLinseed(
			install,
			variant,
			pullSecrets,
			hdler,
			reqLogger,
			ctx,
			keyPairs.linseed,
			keyPairs.linseedTokenKeyPair,
			trustedBundle,
			managementCluster != nil,
			r.usePSP,
			clusterConfig,
		)
		if err != nil || !proceed {
			return result, err
		}

		result, proceed, err = r.applyILMPolicies(ls, reqLogger, ctx)
		if err != nil || !proceed {
			return result, err
		}

		result, proceed, err = r.validateLogStorage(curatorSecrets, esLicenseType, reqLogger, ctx)
		if err != nil || !proceed {
			return result, err
		}

		result, proceed, err = r.createESMetrics(
			install,
			variant,
			pullSecrets,
			reqLogger,
			clusterConfig,
			ctx,
			hdler,
			keyPairs.metricsServer,
			trustedBundle,
			r.usePSP,
		)
		if err != nil || !proceed {
			return result, err
		}
	}

	r.status.ClearDegraded()

	// Since we don't re poll for the object we need to make sure the object wouldn't have been deleted on the patch
	// that may have removed the finalizers.
	// TODO We may want to just return if we remove the finalizers from the LogStorage object.
	if ls != nil && (ls.DeletionTimestamp == nil || len(ls.GetFinalizers()) > 0) {
		ls.Status.State = operatorv1.TigeraStatusReady
		if err := r.client.Status().Update(ctx, ls); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, fmt.Sprintf("Error updating the log-storage status %s", operatorv1.TigeraStatusReady), err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileLogStorage) getElasticsearchService(ctx context.Context) (*corev1.Service, error) {
	svc := corev1.Service{}
	err := r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace}, &svc)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &svc, nil
}

func (r *ReconcileLogStorage) getKibana(ctx context.Context) (*kbv1.Kibana, error) {
	kb := kbv1.Kibana{}
	err := r.client.Get(ctx, client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}, &kb)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &kb, nil
}

// applyElasticTrialSecret returns true if we want to apply a new trial license.
// Overwriting an existing trial license will invalidate the old trial, and revert the cluster back to basic. When a user
// installs a valid Elastic license, the trial will be ignored.
func (r *ReconcileLogStorage) applyElasticTrialSecret(ctx context.Context, installation *operatorv1.InstallationSpec) (bool, error) {
	if !operatorv1.IsFIPSModeEnabled(installation.FIPSMode) {
		return false, nil
	}
	// FIPS mode is a licensed feature for Elasticsearch.
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ECKEnterpriseTrial, Namespace: render.ECKOperatorNamespace}, &corev1.Secret{}); err != nil {
		if errors.IsNotFound(err) {
			return true, nil
		} else {
			return false, err
		}
	}
	return false, nil
}

func (r *ReconcileLogStorage) getKibanaService(ctx context.Context) (*corev1.Service, error) {
	svc := corev1.Service{}
	err := r.client.Get(ctx, client.ObjectKey{Name: render.KibanaServiceName, Namespace: render.KibanaNamespace}, &svc)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &svc, nil
}

func (r *ReconcileLogStorage) checkOIDCUsersEsResource(ctx context.Context) error {
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersConfigMapName, Namespace: render.ElasticsearchNamespace}, &corev1.ConfigMap{}); err != nil {
		return err
	}

	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersEsSecreteName, Namespace: render.ElasticsearchNamespace}, &corev1.Secret{}); err != nil {
		return err
	}
	return nil
}
