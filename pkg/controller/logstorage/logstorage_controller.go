// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/olivere/elastic/v7"
	"io/ioutil"
	apps "k8s.io/api/apps/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"os"
	"regexp"

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	operatorv1 "github.com/tigera/operator/api/v1"

	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

var log = logf.Log.WithName("controller_logstorage")

const (
	defaultResolveConfPath             = "/etc/resolv.conf"
	defaultLocalDNS                    = "svc.cluster.local"
	tigeraElasticsearchUserSecretLabel = "tigera-elasticsearch-user"
	defaultElasticsearchShards         = 1
	DefaultElasticsearchStorageClass   = "tigera-elasticsearch"
	ElasticsearchOperatorUserSecret    = "tigera-ee-operator-elasticsearch-access"
	ElasticsearchRetentionFactor       = 4

	// NumOfIndexNotFlowsDNSBGP is the number of index created that are not flows, dns or bgp.
	NumOfIndexNotFlowsDNSBGP = 6
	// diskDistribution is % of disk to be allocated for log types other than flows, dns and bgp.
	diskDistribution               = 0.1 / NumOfIndexNotFlowsDNSBGP
	TemplateFilePath               = "/usr/local/bin/"
	ElasticsearchConnectionRetries = 10
	DefaultMaxIndexSizeGi          = 30
)

type indexDiskAllocation struct {
	totalDiskPercentage float64
	indexNameSize       map[string]float64
}

// indexDiskMapping gives disk allocation for each log type.
// Allocate 70% of ES disk space to flows, dns and bgp logs and 10% disk space to remaining log types.
// Allocate 90% of the 70% ES disk space to flow logs, 5% of the 70% ES disk space to each dns and bgp logs
// Equally distribute 10% ES disk space among all the other logs
var indexDiskMapping = []indexDiskAllocation{
	{
		totalDiskPercentage: 0.7,
		indexNameSize: map[string]float64{
			"tigera_secure_ee_flows": 0.9,
			"tigera_secure_ee_dns":   0.05,
			"tigera_secure_ee_bgp":   0.05,
		},
	},
	{
		totalDiskPercentage: 0.1,
		indexNameSize: map[string]float64{
			"tigera_secure_ee_audit_ee":           diskDistribution,
			"tigera_secure_ee_audit_kube":         diskDistribution,
			"tigera_secure_ee_snapshots":          diskDistribution,
			"tigera_secure_ee_benchmark_results":  diskDistribution,
			"tigera_secure_ee_compliance_reports": diskDistribution,
			"tigera_secure_ee_events":             diskDistribution,
		},
	},
}

type policy struct {
	Phases struct {
		Hot struct {
			Actions struct {
				Rollover struct {
					MaxSize string `json:"max_size"`
					MaxAge  string `json:"max_age"`
				}
			}
		}
		Delete struct {
			MinAge string `json:"min_age"`
		}
	}
}

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	r, err := newReconciler(mgr.GetClient(), mgr.GetScheme(), status.New(mgr.GetClient(), "log-storage"), defaultResolveConfPath, opts.DetectedProvider)
	if err != nil {
		return err
	}

	return add(mgr, r)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(cli client.Client, schema *runtime.Scheme, statusMgr status.StatusManager, resolvConfPath string, provider operatorv1.Provider) (*ReconcileLogStorage, error) {
	localDNS, err := getLocalDNSName(resolvConfPath)
	if err != nil {
		localDNS = defaultLocalDNS
		log.Error(err, fmt.Sprintf("couldn't find the local dns name from the resolv.conf, defaulting to %s", defaultLocalDNS))
	}

	c := &ReconcileLogStorage{
		client:   cli,
		scheme:   schema,
		status:   statusMgr,
		provider: provider,
		localDNS: localDNS,
	}

	c.status.Run()
	return c, nil
}

// getLocalDNSName parses the path to resolv.conf to find the local DNS name.
func getLocalDNSName(resolvConfPath string) (string, error) {
	var localDNSName string
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	reg := regexp.MustCompile(`^search.*?\s(svc\.[^\s]*)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := reg.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			localDNSName = match[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if localDNSName == "" {
		return "", fmt.Errorf("failed to find local DNS name in resolv.conf")
	}

	return localDNSName, nil
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	c, err := controller.New("log-storage-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource LogStorage
	err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Network resource: %w", err)
	}

	// Watch for changes in storage classes, as new storage classes may be made available for LogStorage.
	err = c.Watch(&source.Kind{
		Type: &storagev1.StorageClass{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-controller failed to watch StorageClass resource: %w", err)
	}

	if err = c.Watch(&source.Kind{Type: &apps.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKOperatorName},
	}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch StatefulSet resource: %w", err)
	}

	if err = c.Watch(&source.Kind{Type: &esv1.Elasticsearch{
		ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.ElasticsearchName},
	}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Elasticsearch resource: %w", err)
	}

	if err = c.Watch(&source.Kind{Type: &kbv1.Kibana{
		ObjectMeta: metav1.ObjectMeta{Namespace: render.KibanaNamespace, Name: render.KibanaName},
	}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Kibana resource: %w", err)
	}

	if err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
	}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Authentication resource: %w", err)
	}

	// Watch all the elasticsearch user secrets in the operator namespace. In the future, we may want put this logic in
	// the utils folder where the other watch logic is.
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Meta.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.Meta.GetNamespace() == render.OperatorNamespace() && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.MetaNew.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.MetaNew.GetNamespace() == render.OperatorNamespace() && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Meta.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.Meta.GetNamespace() == render.OperatorNamespace() && hasLabel
		},
	})
	if err != nil {
		return err
	}

	// Watch all the secrets created by this controller so we can regenerate any that are deleted
	for _, secretName := range []string{
		render.TigeraElasticsearchCertSecret, render.TigeraKibanaCertSecret,
		render.ECKWebhookSecretName, render.OIDCSecretName, render.DexObjectName} {
		if err = utils.AddSecretsWatch(c, secretName, render.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
		}
	}

	if err = utils.AddConfigMapWatch(c, render.ElasticsearchConfigMapName, render.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err := utils.AddServiceWatch(c, render.ElasticsearchServiceName, render.ElasticsearchNamespace); err != nil {
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

	err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-controller failed to watch primary resource: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileLogStorage implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogStorage{}

// ReconcileLogStorage reconciles a LogStorage object
type ReconcileLogStorage struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	status   status.StatusManager
	provider operatorv1.Provider
	localDNS string
	esClient *elastic.Client
}

func GetLogStorage(ctx context.Context, cli client.Client) (*operatorv1.LogStorage, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	fillDefaults(instance)

	return instance, nil
}

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
}

// Reconcile reads that state of the cluster for a LogStorage object and makes changes based on the state read
// and what is in the LogStorage.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogStorage) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

	ctx := context.Background()

	ls, err := GetLogStorage(ctx, r.client)
	if err != nil {
		// Not finding the LogStorage CR is not an error, as a Managed cluster will not have this CR available but
		// there are still "LogStorage" related items that need to be set up
		if !errors.IsNotFound(err) {
			r.status.SetDegraded("An error occurred while querying LogStorage", err.Error())
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
	} else {
		r.status.OnCRFound()
	}

	installationCR, err := installation.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("An error occurred while querying Installation", err.Error())
		return reconcile.Result{}, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		log.Error(err, "Error reading ManagementCluster")
		r.status.SetDegraded("Error reading ManagementCluster", err.Error())
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		log.Error(err, "Error reading ManagementClusterConnection")
		r.status.SetDegraded("Error reading ManagementClusterConnection", err.Error())
		return reconcile.Result{}, err
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		log.Error(err, "")
		r.status.SetDegraded(err.Error(), "")
		return reconcile.Result{}, err
	}

	// These checks ensure that we're in the correct state to continue to the render function without causing a panic
	if installationCR.Status.Variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	} else if ls == nil && managementClusterConnection == nil {
		log.Error(err, "LogStorage must exist for management and standalone clusters")
		return reconcile.Result{}, nil
	} else if ls != nil && ls.DeletionTimestamp == nil && managementClusterConnection != nil {
		// Note that we check if the DeletionTimestamp is set as the render function is responsible for any cleanup needed
		// before the LogStorage CR can be deleted, and removing the finalizers from that CR
		log.Error(err, "cluster type is managed but LogStorage CR still exists")
		r.status.SetDegraded("LogStorage validation failed", "cluster type is managed but LogStorage CR still exists")
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installationCR, r.client)
	if err != nil {
		log.Error(err, "error retrieving pull secrets")
		r.status.SetDegraded("An error occurring while retrieving the pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	esService, err := r.getElasticsearchService(ctx)
	if err != nil {
		log.Error(err, "failed to retrieve Elasticsearch service")
		r.status.SetDegraded("Failed to retrieve the Elasticsearch service", err.Error())
		return reconcile.Result{}, err
	}

	kbService, err := r.getKibanaService(ctx)
	if err != nil {
		log.Error(err, "failed to retrieve Kibana service")
		r.status.SetDegraded("Failed to retrieve the Kibana service", err.Error())
		return reconcile.Result{}, err
	}

	var elasticsearchSecrets, kibanaSecrets, curatorSecrets []*corev1.Secret
	var clusterConfig *render.ElasticsearchClusterConfig
	createWebhookSecret := false
	applyTrial := false

	if managementClusterConnection == nil {

		var flowShards = calculateFlowShards(ls.Spec.Nodes, defaultElasticsearchShards)
		clusterConfig = render.NewElasticsearchClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), defaultElasticsearchShards, flowShards)

		// Check if there is a StorageClass available to run Elasticsearch on.
		if err := r.client.Get(ctx, client.ObjectKey{Name: ls.Spec.StorageClassName}, &storagev1.StorageClass{}); err != nil {
			if errors.IsNotFound(err) {
				err := fmt.Errorf("couldn't find storage class %s, this must be provided", ls.Spec.StorageClassName)
				log.Error(err, err.Error())
				r.status.SetDegraded("Failed to get storage class", err.Error())
				return reconcile.Result{}, nil
			}

			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to get storage class", err.Error())
			return reconcile.Result{}, nil
		}

		if elasticsearchSecrets, err = r.elasticsearchSecrets(ctx); err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to create elasticsearch secrets", err.Error())
			return reconcile.Result{}, err
		}

		if kibanaSecrets, err = r.kibanaSecrets(ctx); err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to create kibana secrets", err.Error())
			return reconcile.Result{}, err
		}

		// The ECK operator requires that we provide it with a secret so it can add certificate information in for its webhooks.
		// If it's created we don't want to overwrite it as we'll lose the certificate information the ECK operator relies on.
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.ECKWebhookSecretName, Namespace: render.ECKOperatorNamespace}, &corev1.Secret{}); err != nil {
			if errors.IsNotFound(err) {
				createWebhookSecret = true
			} else {
				log.Error(err, err.Error())
				r.status.SetDegraded("Failed to read Elasticsearch webhook secret", err.Error())
				return reconcile.Result{}, err
			}
		}

		curatorSecrets, err = utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchCuratorUserSecret}, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded("Failed to get curator credentials", err.Error())
			return reconcile.Result{}, err
		}

		applyTrial, err = r.shouldApplyElasticTrialSecret(ctx)
		if err != nil {
			r.status.SetDegraded("Failed to get eck trial license", err.Error())
			return reconcile.Result{}, err
		}
	}

	elasticsearch, err := r.getElasticsearch(ctx)
	if err != nil {
		log.Error(err, err.Error())
		r.status.SetDegraded("An error occurred trying to retrieve Elasticsearch", err.Error())
		return reconcile.Result{}, err
	}

	kibana, err := r.getKibana(ctx)
	if err != nil {
		log.Error(err, err.Error())
		r.status.SetDegraded("An error occurred trying to retrieve Kibana", err.Error())
		return reconcile.Result{}, err
	}

	// If this is a Managed cluster ls must be nil to get to this point (unless the DeletionTimestamp is set) so we must
	// create the ComponentHandler from the installationCR
	var hdler utils.ComponentHandler
	if ls != nil {
		hdler = utils.NewComponentHandler(log, r.client, r.scheme, ls)
	} else {
		hdler = utils.NewComponentHandler(log, r.client, r.scheme, installationCR)
	}

	// Fetch the Authentication spec. If present, we use it to configure dex as an authentication proxy.
	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded("Error while fetching Authentication", err.Error())
		return reconcile.Result{}, err
	}
	if authentication != nil && authentication.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded("Authentication is not ready", fmt.Sprintf("authentication status: %s", authentication.Status.State))
		return reconcile.Result{}, nil
	}

	var dexCfg render.DexRelyingPartyConfig
	if authentication != nil {
		var dexTLSSecret *corev1.Secret
		dexTLSSecret = &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexTLSSecretName, Namespace: render.OperatorNamespace()}, dexTLSSecret); err != nil {
			r.status.SetDegraded("Failed to read dex tls secret", err.Error())
			return reconcile.Result{}, err
		}
		var dexSecret *corev1.Secret
		if authentication != nil {
			dexSecret = &corev1.Secret{}
			if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexObjectName, Namespace: render.OperatorNamespace()}, dexSecret); err != nil {
				r.status.SetDegraded("Failed to read dex tls secret", err.Error())
				return reconcile.Result{}, err
			}
		}
		dexCfg = render.NewDexRelyingPartyConfig(authentication, dexTLSSecret, dexSecret)
	}

	component := render.LogStorage(
		ls,
		installationCR,
		managementCluster,
		managementClusterConnection,
		elasticsearch,
		kibana,
		clusterConfig,
		elasticsearchSecrets,
		kibanaSecrets,
		createWebhookSecret,
		pullSecrets,
		r.provider,
		curatorSecrets,
		esService,
		kbService,
		r.localDNS,
		applyTrial,
		dexCfg,
	)

	if err := hdler.CreateOrUpdate(ctx, component, r.status); err != nil {
		log.Error(err, err.Error())
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	if managementClusterConnection == nil {

		if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
			r.status.SetDegraded("Waiting for Elasticsearch cluster to be operational", "")
			return reconcile.Result{}, nil
		}

		if kibana == nil || kibana.Status.AssociationStatus != cmnv1.AssociationEstablished {
			r.status.SetDegraded("Waiting for Kibana cluster to be operational", "")
			return reconcile.Result{}, nil
		}

		if len(curatorSecrets) == 0 {
			log.Info("waiting for curator secrets to become available")
			r.status.SetDegraded("Waiting for curator secrets to become available", "")
			return reconcile.Result{}, nil
		}

		if err = r.setupESIndex(ctx, ls); err != nil {
			log.Info("waiting for ES ILM policies and templates to get created")
			r.status.SetDegraded("Waiting for ES ILM policies and templates to get created", err.Error())
			return reconcile.Result{}, err
		}
	}

	r.status.ClearDegraded()

	if ls != nil {
		ls.Status.State = operatorv1.TigeraStatusReady
		if err := r.client.Status().Update(ctx, ls); err != nil {
			reqLogger.Error(err, fmt.Sprintf("Error updating the log-storage status %s", operatorv1.TigeraStatusReady))
			r.status.SetDegraded(fmt.Sprintf("Error updating the log-storage status %s", operatorv1.TigeraStatusReady), err.Error())
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileLogStorage) elasticsearchSecrets(ctx context.Context) ([]*corev1.Secret, error) {
	var secrets []*corev1.Secret
	secret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}, secret); err != nil {
		if errors.IsNotFound(err) {
			secret, err = render.CreateOperatorTLSSecret(nil,
				render.TigeraElasticsearchCertSecret, "tls.key", "tls.crt",
				render.DefaultCertificateDuration, nil, render.ElasticsearchHTTPURL,
			)
		} else {
			return nil, err
		}
	}
	secrets = append(secrets, secret, render.CopySecrets(render.ElasticsearchNamespace, secret)[0])

	secret = &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}, secret); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		log.Info("Elasticsearch public cert secret not found yet")
	} else {
		secrets = append(secrets, render.CopySecrets(render.OperatorNamespace(), secret)...)
	}

	return secrets, nil
}

// Returns true if we want to apply a new trial license. Returns false if there already is a trial license in the cluster.
// Overwriting an existing trial license will invalidate the old trial, and revert the cluster back to basic. When a user
// installs a valid Elastic license, the trial will be ignored.
func (r *ReconcileLogStorage) shouldApplyElasticTrialSecret(ctx context.Context) (bool, error) {
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ECKEnterpriseTrial, Namespace: render.ECKOperatorNamespace}, &corev1.Secret{}); err != nil {
		if errors.IsNotFound(err) {
			return true, nil
		} else {
			return false, err
		}
	}
	return false, nil
}

func (r *ReconcileLogStorage) kibanaSecrets(ctx context.Context) ([]*corev1.Secret, error) {
	var secrets []*corev1.Secret
	secret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}, secret); err != nil {
		if errors.IsNotFound(err) {
			secret, err = render.CreateOperatorTLSSecret(nil,
				render.TigeraKibanaCertSecret, "tls.key", "tls.crt",
				render.DefaultCertificateDuration, nil, render.KibanaHTTPURL,
			)
		} else {
			return nil, err
		}
	}
	secrets = append(secrets, secret, render.CopySecrets(render.KibanaNamespace, secret)[0])

	secret = &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}, secret); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		log.Info("Kibana public cert secret not found yet")
	} else {
		secrets = append(secrets, render.CopySecrets(render.OperatorNamespace(), secret)...)
	}

	return secrets, nil
}

func (r *ReconcileLogStorage) getElasticsearch(ctx context.Context) (*esv1.Elasticsearch, error) {
	es := esv1.Elasticsearch{}
	err := r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, &es)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &es, nil
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

func calculateFlowShards(nodesSpecifications *operatorv1.Nodes, defaultShards int) int {
	if nodesSpecifications == nil || nodesSpecifications.ResourceRequirements == nil || nodesSpecifications.ResourceRequirements.Requests == nil {
		return defaultShards
	}

	var nodes = nodesSpecifications.Count
	var cores, _ = nodesSpecifications.ResourceRequirements.Requests.Cpu().AsInt64()
	var shardPerNode = int(cores) / 4

	if nodes <= 0 || shardPerNode <= 0 {
		return defaultShards
	}

	return int(nodes) * shardPerNode
}

func (r *ReconcileLogStorage) setupESIndex(ctx context.Context, ls *operatorv1.LogStorage) error {

	fmt.Printf("\n--in setupESIndex")
	if r.esClient == nil {
		fmt.Printf("\n--in setupESIndex nil")

		user, password, roots, err := utils.GetClientCredentials(r.client, ctx)
		if err != nil {
			return err
		}

		// TODO: wait and retry ?
		r.esClient, err = utils.NewESClient(user, password, roots)
		if err != nil {
			log.Error(err, "failed to create ES client")
			return err
		}
	}

	defaultStorage := resource.MustParse(fmt.Sprintf("%dGi", render.DefaultElasticStorageGi))
	var totalEsStorage = defaultStorage.Value()
	if ls.Spec.Nodes.ResourceRequirements != nil {
		if val, ok := ls.Spec.Nodes.ResourceRequirements.Requests["storage"]; ok {
			totalEsStorage = val.Value()
		}
	}

	if err := putIlmPolicies(ctx, ls, r.esClient, totalEsStorage); err != nil {
		log.Error(err, "failed to create/update ILM policies")
		return err
	}

	return nil
}

func putIlmPolicies(ctx context.Context, ls *operatorv1.LogStorage, esClient *elastic.Client, totalEsStorage int64) error {

	for _, v := range indexDiskMapping {
		for indexName, p := range v.indexNameSize {
			var retention int
			switch indexName {
			case "tigera_secure_ee_flows":
				retention = int(*ls.Spec.Retention.Flows)
			case "tigera_secure_ee_audit_ee", "tigera_secure_ee_audit_kube":
				retention = int(*ls.Spec.Retention.AuditReports)
			case "tigera_secure_ee_snapshots":
				retention = int(*ls.Spec.Retention.Snapshots)
			case "tigera_secure_ee_compliance_reports":
				retention = int(*ls.Spec.Retention.ComplianceReports)
			// TODO: set these default values in operator.yaml like other values
			case "tigera_secure_ee_benchmark_results", "tigera_secure_ee_events":
				retention = 91
			case "tigera_secure_ee_dns", "tigera_secure_ee_bgp":
				retention = 8
			}

			rolloverAge := retention / ElasticsearchRetentionFactor
			rolloverSize := (float64(totalEsStorage) * v.totalDiskPercentage * p) / ElasticsearchRetentionFactor
			rollover := resource.MustParse(fmt.Sprintf("%dGi", DefaultMaxIndexSizeGi))
			var maxRolloverSize = float64(rollover.Value())

			if rolloverSize > maxRolloverSize {
				rolloverSize = maxRolloverSize
			}
			if err := buildAndApplyIlmPolicy(ctx, esClient, rolloverAge, retention, int64(rolloverSize), indexName); err != nil {
				return err
			}
		}
	}

	return nil
}

func buildAndApplyIlmPolicy(ctx context.Context, esClient *elastic.Client, rolloverAge int, minDeleteAge int, rolloverSize int64, name string) error {
	fmt.Printf("\n buildAndApplyIlmPolicy %#v", name)
	rollover := map[string]interface{}{
		"max_size": fmt.Sprintf("%db", rolloverSize),
		"max_age":  fmt.Sprintf("%dd", rolloverAge),
	}
	hotPriority := map[string]interface{}{
		"priority": 100,
	}
	hotAction := make(map[string]interface{})
	hotAction["rollover"] = rollover
	hotAction["set_priority"] = hotPriority

	warmPriority := map[string]interface{}{
		"priority": 50,
	}
	warmAction := make(map[string]interface{})
	warmAction["readonly"] = make(map[string]interface{})
	warmAction["set_priority"] = warmPriority

	deleteAction := make(map[string]interface{})
	deleteAction["delete"] = make(map[string]interface{})

	minRetentionAge := fmt.Sprintf("%dd", minDeleteAge)
	newPolicy := make(map[string]interface{})
	newPolicy["policy"] = map[string]interface{}{
		"phases": map[string]interface{}{
			"hot": map[string]interface{}{
				"actions": hotAction,
			},
			"warm": map[string]interface{}{
				"actions": warmAction,
			},
			"delete": map[string]interface{}{
				"min_age": minRetentionAge,
				"actions": deleteAction,
			},
		},
	}

	res, err := esClient.XPackIlmGetLifecycle().Policy(name + "_policy").Do(ctx)
	if err != nil {
		return putPolicyTemplate(ctx, esClient, name, newPolicy)
	}

	opp := res[name+"_policy"].Policy
	jsonbody, err := json.Marshal(opp)
	if err != nil {
		return err
	}
	existingPolicy := policy{}
	if err = json.Unmarshal(jsonbody, &existingPolicy); err != nil {
		return err
	}

	currentMaxAge := existingPolicy.Phases.Hot.Actions.Rollover.MaxAge
	currentMaxSize := existingPolicy.Phases.Hot.Actions.Rollover.MaxSize
	currentMinAge := existingPolicy.Phases.Delete.MinAge
	if currentMaxAge != rollover["max_age"] || currentMaxSize != rollover["max_size"] || currentMinAge != minRetentionAge {
		// update
		return putPolicyTemplate(ctx, esClient, name, newPolicy)

	}
	fmt.Printf("\n skipping putPolicyTemplate %#v", name)

	return nil
}

func putPolicyTemplate(ctx context.Context, esClient *elastic.Client, name string, policy map[string]interface{}) error {
	fmt.Printf("\n putPolicyTemplate %#v", name)

	_, err := esClient.XPackIlmPutLifecycle().Policy(name + "_policy").BodyJson(policy).Do(ctx)
	if err != nil {
		log.Error(err, "Error applying Ilm policy")
		return err
	}

	if err := putIndexTemplates(ctx, esClient, name); err != nil {
		log.Error(err, "failed to create/update ES Index templates")
		return err
	}

	// TODO: bootstrap only if there are no write index else rollover and bootstrap
	if err := bootstrapWriteIndex(ctx, esClient, name); err != nil {
		return err
	}
	return nil
}

func putIndexTemplates(ctx context.Context, esClient *elastic.Client, name string) error {
	//TODO: create templates for all managed clusters
	var byteValue []byte
	var err error
	if byteValue, err = ioutil.ReadFile(TemplateFilePath + name + ".json"); err != nil {
		return err
	}
	var result map[string]interface{}
	json.Unmarshal(byteValue, &result)
	// new index will be of form tigera_secure_ee_audit_ee.cluster.20201013-78634000
	// so index_pattern tigera_secure_ee_audit_ee.cluster.*-*, this differentates index that uses ilm and curator
	// TODO: cehck if we need to differentiate between them, is there a problem if managed uses old cluster and management uses ilm
	result["index_patterns"] = name + ".cluster.*"
	settings := result["settings"].(map[string]interface{})
	settings["index.lifecycle.rollover_alias"] = name + ".cluster."

	if _, err = esClient.IndexPutTemplate(name + "_cluster_template").BodyJson(result).Do(ctx); err != nil {
		log.Error(err, "Error applying Index template")
		return err
	}
	return nil
}

func bootstrapWriteIndex(ctx context.Context, esClient *elastic.Client, name string) error {
	//TODO: create templates for all managed clusters
	var result map[string]interface{}
	_, err := esClient.Aliases().Index(name + ".cluster.").Do(ctx)
	if err != nil {
		result = map[string]interface{}{
			"aliases": map[string]interface{}{
				name + ".cluster.": map[string]interface{}{
					"is_write_index": true,
				},
			},
		}
		indexName := "<" + name + ".cluster." + "{now/s{yyyyMMdd-A}}-000000>"
		if _, err := esClient.CreateIndex(indexName).BodyJson(result).Do(ctx); err != nil {
			fmt.Printf("err bootstraping write index %#v", err)
			return err
		}
		fmt.Printf("\nBootstrapped index %#v", name)
		return nil
	}
	rolloverCondition := map[string]interface{}{
		"conditions": map[string]interface{}{
			"max_age": "0ms",
		},
	}
	if _, err = esClient.RolloverIndex(name + ".cluster.").BodyJson(rolloverCondition).Do(ctx); err != nil {
		return err
	}
	fmt.Printf("\nRolloverIndex index %#v", name)

	return nil
}
