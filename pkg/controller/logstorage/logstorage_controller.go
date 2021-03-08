// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	lscomponent "github.com/tigera/operator/pkg/render/logstorage/components"

	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
)

var log = logf.Log.WithName("controller_logstorage")

const (
	tigeraElasticsearchUserSecretLabel = "tigera-elasticsearch-user"
	defaultElasticsearchShards         = 1
	defaultEckOperatorMemorySetting    = "512Mi"
	DefaultElasticsearchStorageClass   = "tigera-elasticsearch"
)

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	r, err := newReconciler(mgr.GetClient(), mgr.GetScheme(), status.New(mgr.GetClient(), "log-storage"), opts.DetectedProvider, utils.NewElasticClient, opts.ClusterDomain)
	if err != nil {
		return err
	}

	return add(mgr, r)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(cli client.Client, schema *runtime.Scheme, statusMgr status.StatusManager, provider operatorv1.Provider, esCliCreator utils.ElasticsearchClientCreator, clusterDomain string) (*ReconcileLogStorage, error) {
	c := &ReconcileLogStorage{
		client:        cli,
		scheme:        schema,
		status:        statusMgr,
		provider:      provider,
		esCliCreator:  esCliCreator,
		clusterDomain: clusterDomain,
	}

	c.status.Run()
	return c, nil
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

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ImageSet: %w", err)
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
			_, hasLabel := e.Object.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.Object.GetNamespace() == rmeta.OperatorNamespace() && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.ObjectNew.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.ObjectNew.GetNamespace() == rmeta.OperatorNamespace() && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Object.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.Object.GetNamespace() == rmeta.OperatorNamespace() && hasLabel
		},
	})
	if err != nil {
		return err
	}

	// Watch all the secrets created by this controller so we can regenerate any that are deleted
	for _, secretName := range []string{
		render.TigeraElasticsearchCertSecret, render.TigeraKibanaCertSecret,
		render.OIDCSecretName, render.DexObjectName} {
		if err = utils.AddSecretsWatch(c, secretName, rmeta.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
		}
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, rmeta.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace); err != nil {
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

	for _, name := range []string{render.OIDCUsersConfigMapName, render.OIDCUsersEsSecreteName,
		render.ElasticsearchAdminUserSecret} {
		if err = utils.AddConfigMapWatch(c, name, render.ElasticsearchNamespace); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
		}
	}

	return nil
}

// blank assignment to verify that ReconcileLogStorage implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogStorage{}

// ReconcileLogStorage reconciles a LogStorage object
type ReconcileLogStorage struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	provider      operatorv1.Provider
	esCliCreator  utils.ElasticsearchClientCreator
	clusterDomain string
}

func GetLogStorage(ctx context.Context, cli client.Client) (*operatorv1.LogStorage, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	fillDefaults(instance)

	if err := validateComponentResources(&instance.Spec); err != nil {
		return nil, err
	}

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

// Reconcile reads that state of the cluster for a LogStorage object and makes changes based on the state read
// and what is in the LogStorage.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogStorage) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

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

	variant, install, err := installation.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("An error occurred while querying Installation", err.Error())
		return reconcile.Result{}, err
	}

	if ls != nil && install.CertificateManagement != nil {
		r.status.SetDegraded("Certificate Management is not yet supported for clusters with LogStorage, please remove the setting from your Installation resource.", "")
		return reconcile.Result{}, fmt.Errorf("certificate management is not yet supported for clusters with LogStorage, please remove the setting from your Installation resource")
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

	var esCertSecret, esCertSecretESCopy, esPubCertSecret, esAdminUserSecret *corev1.Secret
	var kibanaSecrets, curatorSecrets []*corev1.Secret
	var clusterConfig *relasticsearch.ClusterConfig
	var esLicenseType render.ElasticsearchLicenseType
	applyTrial := false

	if managementClusterConnection == nil {
		var flowShards = calculateFlowShards(ls.Spec.Nodes, defaultElasticsearchShards)
		clusterConfig = relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), defaultElasticsearchShards, flowShards)

		// Check if there is a StorageClass available to run Elasticsearch on.
		if err := r.client.Get(ctx, client.ObjectKey{Name: ls.Spec.StorageClassName}, &storagev1.StorageClass{}); err != nil {
			if errors.IsNotFound(err) {
				err := fmt.Errorf("couldn't find storage class %s, this must be provided", ls.Spec.StorageClassName)
				reqLogger.Error(err, err.Error())
				r.status.SetDegraded("Failed to get storage class", err.Error())
				return reconcile.Result{}, nil
			}

			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Failed to get storage class", err.Error())
			return reconcile.Result{}, nil
		}

		// Get the secret - might be nil
		esAdminUserSecret, err = utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
		if err != nil {
			return reconcile.Result{}, err
		}

		if esCertSecretESCopy, esPubCertSecret, esAdminUserSecret, err = r.getElasticsearchCertificateSecrets(ctx); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Failed to create elasticsearch secrets", err.Error())
			return reconcile.Result{}, err
		}

		if kibanaSecrets, err = r.kibanaSecrets(ctx); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Failed to create kibana secrets", err.Error())
			return reconcile.Result{}, err
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

		if esLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, reqLogger); err != nil {
			// If ECKLicenseConfigMapName is not found, it means ECK operator is not running yet, log the information and proceed
			if errors.IsNotFound(err) {
				reqLogger.Info("ConfigMap not found yet", "name", render.ECKLicenseConfigMapName)
			} else {
				r.status.SetDegraded("Failed to get elastic license", err.Error())
				return reconcile.Result{}, err
			}
		}

	}

	elasticsearch, err := r.getElasticsearch(ctx)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("An error occurred trying to retrieve Elasticsearch", err.Error())
		return reconcile.Result{}, err
	}

	kibana, err := r.getKibana(ctx)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("An error occurred trying to retrieve Kibana", err.Error())
		return reconcile.Result{}, err
	}

	// If this is a Managed cluster ls must be nil to get to this point (unless the DeletionTimestamp is set) so we must
	// create the ComponentHandler from the managementClusterConnection.
	var hdler utils.ComponentHandler
	if ls != nil {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, managementClusterConnection)
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
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexTLSSecretName, Namespace: rmeta.OperatorNamespace()}, dexTLSSecret); err != nil {
			r.status.SetDegraded("Failed to read dex tls secret", err.Error())
			return reconcile.Result{}, err
		}
		var dexSecret *corev1.Secret
		if authentication != nil {
			dexSecret = &corev1.Secret{}
			if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexObjectName, Namespace: rmeta.OperatorNamespace()}, dexSecret); err != nil {
				r.status.SetDegraded("Failed to read dex tls secret", err.Error())
				return reconcile.Result{}, err
			}
		}
		dexCfg = render.NewDexRelyingPartyConfig(authentication, dexTLSSecret, dexSecret, r.clusterDomain)
	}

	component := render.LogStorage(
		ls,
		install,
		managementCluster,
		managementClusterConnection,
		elasticsearch,
		kibana,
		clusterConfig,
		[]*corev1.Secret{esCertSecret, esCertSecretESCopy, esPubCertSecret, esAdminUserSecret},
		kibanaSecrets,
		pullSecrets,
		r.provider,
		curatorSecrets,
		esService,
		kbService,
		r.clusterDomain,
		applyTrial,
		dexCfg,
		esLicenseType,
	)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdate(ctx, component, r.status); err != nil {
		reqLogger.Error(err, err.Error())
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
			reqLogger.Info("waiting for curator secrets to become available")
			r.status.SetDegraded("Waiting for curator secrets to become available", "")
			return reconcile.Result{}, nil
		}

		// ES should be in ready phase when execution reaches here, apply ILM polices
		esClient, err := r.esCliCreator(r.client, ctx, relasticsearch.HTTPSEndpoint(component.SupportedOSType(), r.clusterDomain))
		if err != nil {
			reqLogger.Error(err, "failed to create the Elasticsearch client")
			r.status.SetDegraded("Failed to connect to Elasticsearch", err.Error())
			return reconcile.Result{}, err
		}

		if err = esClient.SetILMPolicies(ctx, ls); err != nil {
			reqLogger.Error(err, "failed to create or update Elasticsearch lifecycle policies")
			r.status.SetDegraded("Failed to create or update Elasticsearch lifecycle policies", err.Error())
			return reconcile.Result{}, err
		}

		// kube-controller creates the ConfigMap and Secret needed for SSO into Kibana.
		// If elastisearch uses basic license, degrade logstorage if the ConfigMap and Secret
		// needed for logging user into Kibana is not available.
		if esLicenseType == render.ElasticsearchLicenseTypeBasic {
			if err = r.checkOIDCUsersEsResource(ctx); err != nil {
				r.status.SetDegraded("Failed to get oidc user Secret and ConfigMap", err.Error())
				return reconcile.Result{}, err
			}
		}

		esMetricsSecret, err := utils.GetSecret(context.Background(), r.client, render.ElasticsearchMetricsSecret, rmeta.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded("Failed to retrieve Elasticsearch metrics user secret.", err.Error())
			return reconcile.Result{}, err
		} else if esMetricsSecret == nil {
			r.status.SetDegraded("Waiting for elasticsearch metrics secrets to become available", "")
			return reconcile.Result{}, nil
		}

		if esPubCertSecret == nil {
			r.status.SetDegraded("Waiting for elasticsearch public cert secret to become available", "")
			return reconcile.Result{}, nil
		}

		esMetricsComponent := lscomponent.ElasticsearchMetrics(install, clusterConfig, esMetricsSecret, esPubCertSecret, r.clusterDomain)
		if err = imageset.ApplyImageSet(ctx, r.client, variant, esMetricsComponent); err != nil {
			reqLogger.Error(err, "Error with images from ImageSet")
			r.status.SetDegraded("Error with images from ImageSet", err.Error())
			return reconcile.Result{}, err
		}

		if err := hdler.CreateOrUpdate(ctx, esMetricsComponent, r.status); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Error creating / updating resource", err.Error())
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

// Deletes the given ECK managed cert secret.
func (r *ReconcileLogStorage) deleteInvalidECKManagedPublicCertSecret(ctx context.Context, secret *corev1.Secret) error {
	log.Info(fmt.Sprintf("Deleting invalid cert secret %q in %q namespace", secret.Name, secret.Namespace))
	return r.client.Delete(ctx, secret)
}

func (r *ReconcileLogStorage) getElasticsearchCertificateSecrets(ctx context.Context) (*corev1.Secret, *corev1.Secret, *corev1.Secret, error) {
	svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)

	// Get the secret - might be nil
	certSecret, err := utils.GetSecret(ctx, r.client, render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		return nil, nil, nil, err
	}

	// Ensure that cert is valid.
	certSecret, err = utils.EnsureCertificateSecret(render.TigeraElasticsearchCertSecret, certSecret, "tls.key", "tls.crt", rmeta.DefaultCertificateDuration, svcDNSNames...)
	if err != nil {
		return nil, nil, nil, err
	}

	certSecretESCopy := rsecret.CopyToNamespace(render.ElasticsearchNamespace, certSecret)[0]

	// Get the pub secret - might be nil
	pubSecret, err := utils.GetSecret(ctx, r.client, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace)
	if err != nil {
		return nil, nil, nil, err
	}

	if pubSecret != nil {
		operatorManaged, err := utils.IsOperatorManaged(certSecret, "tls.crt")
		if err != nil {
			return nil, nil, nil, err
		}

		if operatorManaged {
			err = utils.SecretHasExpectedDNSNames(pubSecret, "tls.crt", svcDNSNames)
			if err == utils.ErrInvalidCertDNSNames {
				if err := r.deleteInvalidECKManagedPublicCertSecret(ctx, pubSecret); err != nil {
					return nil, nil, nil, err
				}
			}
		}

		pubSecret = rsecret.CopyToNamespace(rmeta.OperatorNamespace(), pubSecret)[0]
	}

	return certSecret, certSecretESCopy, pubSecret, nil
}

func (r *ReconcileLogStorage) elasticsearchSecrets(ctx context.Context) ([]*corev1.Secret, error) {
	var secrets []*corev1.Secret
	svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)

	// Get the secret - might be nil
	secret, err := utils.GetSecret(ctx, r.client, render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		return nil, err
	}

	// Ensure that cert is valid.
	secret, err = utils.EnsureCertificateSecret(render.TigeraElasticsearchCertSecret, secret, "tls.key", "tls.crt", rmeta.DefaultCertificateDuration, svcDNSNames...)
	if err != nil {
		return nil, err
	}

	secrets = append(secrets, secret, rsecret.CopyToNamespace(render.ElasticsearchNamespace, secret)[0])

	// Get the pub secret - might be nil
	pubSecret, err := utils.GetSecret(ctx, r.client, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace)
	if err != nil {
		return nil, err
	}

	if pubSecret == nil {
		log.Info(fmt.Sprintf("Public cert secret %q not found yet", relasticsearch.PublicCertSecret))
		return secrets, nil
	}

	operatorManaged, err := utils.IsOperatorManaged(secret, "tls.crt")
	if err != nil {
		return nil, err
	}

	if operatorManaged {
		err = utils.SecretHasExpectedDNSNames(pubSecret, "tls.crt", svcDNSNames)
		if err == utils.ErrInvalidCertDNSNames {
			if err := r.deleteInvalidECKManagedPublicCertSecret(ctx, pubSecret); err != nil {
				return nil, err
			}
		}
	}

	// If the cert was not deleted, copy the valid cert to operator namespace.
	secrets = append(secrets, rsecret.CopyToNamespace(rmeta.OperatorNamespace(), pubSecret)...)

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
	svcDNSNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, r.clusterDomain)

	// Get the secret - might be nil
	secret, err := utils.GetSecret(ctx, r.client, render.TigeraKibanaCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		return nil, err
	}

	// Ensure that cert is valid.
	secret, err = utils.EnsureCertificateSecret(render.TigeraKibanaCertSecret, secret, "tls.key", "tls.crt", rmeta.DefaultCertificateDuration, svcDNSNames...)
	if err != nil {
		return nil, err
	}

	secrets = append(secrets, secret, rsecret.CopyToNamespace(render.KibanaNamespace, secret)[0])

	// Get the pub secret - might be nil
	pubSecret, err := utils.GetSecret(ctx, r.client, render.KibanaPublicCertSecret, render.KibanaNamespace)
	if err != nil {
		return nil, err
	}

	if pubSecret == nil {
		log.Info(fmt.Sprintf("Public cert secret %q not found yet", render.KibanaPublicCertSecret))
		return secrets, nil
	}

	operatorManaged, err := utils.IsOperatorManaged(secret, "tls.crt")
	if err != nil {
		return nil, err
	}

	if operatorManaged {
		err = utils.SecretHasExpectedDNSNames(pubSecret, "tls.crt", svcDNSNames)
		if err == utils.ErrInvalidCertDNSNames {
			if err := r.deleteInvalidECKManagedPublicCertSecret(ctx, pubSecret); err != nil {
				return nil, err
			}
		}
	}
	// If the cert was not deleted, copy the valid cert to operator namespace.
	secrets = append(secrets, rsecret.CopyToNamespace(rmeta.OperatorNamespace(), pubSecret)...)

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

func (r *ReconcileLogStorage) checkOIDCUsersEsResource(ctx context.Context) error {
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersConfigMapName, Namespace: render.ElasticsearchNamespace}, &corev1.ConfigMap{}); err != nil {
		return err
	}

	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersEsSecreteName, Namespace: render.ElasticsearchNamespace}, &corev1.Secret{}); err != nil {
		return err
	}
	return nil
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
