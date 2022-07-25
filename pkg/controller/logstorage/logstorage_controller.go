// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"k8s.io/client-go/kubernetes"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/elastic/cloud-on-k8s/pkg/utils/stringsutil"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/monitor"
)

var log = logf.Log.WithName("controller_logstorage")

const (
	defaultEckOperatorMemorySetting  = "512Mi"
	DefaultElasticsearchStorageClass = "tigera-elasticsearch"
	LogStorageFinalizer              = "tigera.io/eck-cleanup"
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
			r.status.SetDegraded("An error occurred while querying LogStorage", err.Error())
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
			r.status.SetDegraded("An error occurred while validating LogStorage", err.Error())
			return reconcile.Result{}, err
		}

		setLogStorageFinalizer(ls)

		// Write the logstorage back to the datastore
		if err = r.client.Patch(ctx, ls, preDefaultPatchFrom); err != nil {
			log.Error(err, "Failed to write defaults")
			r.status.SetDegraded("Failed to write defaults", err.Error())
			return reconcile.Result{}, err
		}
	}

	variant, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("An error occurred while querying Installation", err.Error())
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded("Waiting for Tier watch to be established", "")
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Waiting for allow-tigera tier to be created", err.Error())
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			log.Error(err, "Error querying allow-tigera tier")
			r.status.SetDegraded("Error querying allow-tigera tier", err.Error())
			return reconcile.Result{}, err
		}
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		reqLogger.Error(err, "Error reading ManagementCluster")
		r.status.SetDegraded("Error reading ManagementCluster", err.Error())
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		reqLogger.Error(err, "Error reading ManagementClusterConnection")
		r.status.SetDegraded("Error reading ManagementClusterConnection", err.Error())
		return reconcile.Result{}, err
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		reqLogger.Error(err, "")
		r.status.SetDegraded(err.Error(), "")
		return reconcile.Result{}, err
	}

	// These checks ensure that we're in the correct state to continue to the render function without causing a panic
	if variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	} else if ls == nil && managementClusterConnection == nil {
		reqLogger.Info("LogStorage must exist for management and standalone clusters that require storage.")
		return reconcile.Result{}, nil
	} else if ls != nil && ls.DeletionTimestamp == nil && managementClusterConnection != nil {
		// Note that we check if the DeletionTimestamp is set as the render function is responsible for any cleanup needed
		// before the LogStorage CR can be deleted, and removing the finalizers from that CR
		reqLogger.Error(err, "cluster type is managed but LogStorage CR still exists")
		r.status.SetDegraded("LogStorage validation failed", "cluster type is managed but LogStorage CR still exists")
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(install, r.client)
	if err != nil {
		reqLogger.Error(err, "error retrieving pull secrets")
		r.status.SetDegraded("An error occurring while retrieving the pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	esService, err := r.getElasticsearchService(ctx)
	if err != nil {
		reqLogger.Error(err, "failed to retrieve Elasticsearch service")
		r.status.SetDegraded("Failed to retrieve the Elasticsearch service", err.Error())
		return reconcile.Result{}, err
	}

	kbService, err := r.getKibanaService(ctx)
	if err != nil {
		reqLogger.Error(err, "failed to retrieve Kibana service")
		r.status.SetDegraded("Failed to retrieve the Kibana service", err.Error())
		return reconcile.Result{}, err
	}

	var esAdminUserSecret *corev1.Secret
	var clusterConfig *relasticsearch.ClusterConfig
	var curatorSecrets []*corev1.Secret
	var esLicenseType render.ElasticsearchLicenseType

	if managementClusterConnection == nil {
		flowShards := logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
		clusterConfig = relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)

		// Get the admin user secret to copy to the operator namespace.
		esAdminUserSecret, err = utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
		if err != nil {
			reqLogger.Error(err, "failed to get Elasticsearch admin user secret")
			r.status.SetDegraded("Failed to get Elasticsearch admin user secret", err.Error())
			return reconcile.Result{}, err
		}
		if esAdminUserSecret != nil {
			esAdminUserSecret = rsecret.CopyToNamespace(common.OperatorNamespace(), esAdminUserSecret)[0]
		}

		curatorSecrets, err = utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchCuratorUserSecret}, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded("Failed to get curator credentials", err.Error())
			return reconcile.Result{}, err
		}

		esLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, reqLogger)
		if err != nil {
			// If ECKLicenseConfigMapName is not found, it means ECK operator is not running yet, log the information and proceed
			if errors.IsNotFound(err) {
				reqLogger.Info("ConfigMap not found yet", "name", render.ECKLicenseConfigMapName)
			} else {
				r.status.SetDegraded("Failed to get elastic license", err.Error())
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
		r.status.SetDegraded("Error while fetching Authentication", err.Error())
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, install, r.clusterDomain)
	if err != nil {
		log.Error(err, "unable to create the Tigera CA")
		r.status.SetDegraded("Unable to create the Tigera CA", err.Error())
		return reconcile.Result{}, err
	}
	certificateManager.AddToStatusManager(r.status, render.ElasticsearchNamespace)

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
		certificateManager,
	)

	if ls != nil && ls.DeletionTimestamp != nil && finalizerCleanup {
		ls.SetFinalizers(stringsutil.RemoveStringInSlice(LogStorageFinalizer, ls.GetFinalizers()))

		// Write the logstorage back to the datastore
		if patchErr := r.client.Patch(ctx, ls, preDefaultPatchFrom); patchErr != nil {
			reqLogger.Error(patchErr, "Error patching the log-storage")
			r.status.SetDegraded("Error patching the log-storage", patchErr.Error())
			return reconcile.Result{}, patchErr
		}
	}

	if err != nil || !proceed {
		return result, err
	}

	if managementClusterConnection == nil {
		result, proceed, err = r.createEsKubeControllers(
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

		result, proceed, err = r.createEsGateway(
			install,
			variant,
			pullSecrets,
			esAdminUserSecret,
			hdler,
			reqLogger,
			ctx,
			certificateManager,
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

		result, proceed, err = r.createEsMetrics(
			install,
			variant,
			pullSecrets,
			reqLogger,
			clusterConfig,
			ctx,
			hdler,
			r.clusterDomain,
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
			reqLogger.Error(err, fmt.Sprintf("Error updating the log-storage status %s", operatorv1.TigeraStatusReady))
			r.status.SetDegraded(fmt.Sprintf("Error updating the log-storage status %s", operatorv1.TigeraStatusReady), err.Error())
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
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

func (r *ReconcileLogStorage) checkOIDCUsersEsResource(ctx context.Context) error {
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersConfigMapName, Namespace: render.ElasticsearchNamespace}, &corev1.ConfigMap{}); err != nil {
		return err
	}

	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersEsSecreteName, Namespace: render.ElasticsearchNamespace}, &corev1.Secret{}); err != nil {
		return err
	}
	return nil
}
