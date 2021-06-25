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
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"

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

	r, err := newReconciler(mgr.GetClient(), mgr.GetScheme(), status.New(mgr.GetClient(), "log-storage", opts.KubernetesVersion), opts.DetectedProvider, utils.NewElasticClient, opts.ClusterDomain)
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
		render.OIDCSecretName, render.DexObjectName, relasticsearch.PublicCertSecret,
		render.KibanaPublicCertSecret} {
		if err = utils.AddSecretsWatch(c, secretName, rmeta.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
		}
	}

	if err = utils.AddSecretsWatch(c, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, render.KibanaPublicCertSecret, render.KibanaNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, rmeta.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err := utils.AddServiceWatch(c, render.ElasticsearchInternalServiceName, render.ElasticsearchNamespace); err != nil {
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

	variant, install, err := utils.GetInstallation(context.Background(), r.client)
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

	var esCertSecret, esCertSecretESCopy, esPubCertSecret, kbPubCertSecret, esAdminUserSecret *corev1.Secret
	var kibanaSecrets, curatorSecrets []*corev1.Secret
	var clusterConfig *relasticsearch.ClusterConfig
	var esLicenseType render.ElasticsearchLicenseType

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

		// Get the admin user secret to copy to the operator namespace.
		esAdminUserSecret, err = utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
		if err != nil {
			return reconcile.Result{}, err
		}
		if esAdminUserSecret != nil {
			esAdminUserSecret = rsecret.CopyToNamespace(rmeta.OperatorNamespace(), esAdminUserSecret)[0]
		}

		if esCertSecret, esCertSecretESCopy, esPubCertSecret, kbPubCertSecret, err = r.getElasticsearchCertificateSecrets(ctx, install); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Failed to create elasticsearch secrets", err.Error())
			return reconcile.Result{}, err
		}

		if kibanaSecrets, err = r.kibanaSecrets(ctx, install); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Failed to create kibana secrets", err.Error())
			return reconcile.Result{}, err
		}

		curatorSecrets, err = utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchCuratorUserSecret}, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded("Failed to get curator credentials", err.Error())
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
	// If the authentication CR is available and it is not configured to use the Tigera OIDC type then configure dex.
	if authentication != nil && (authentication.Spec.OIDC == nil || authentication.Spec.OIDC.Type != operatorv1.OIDCTypeTigera) {
		var dexCertSecret *corev1.Secret
		dexCertSecret = &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexCertSecretName, Namespace: rmeta.OperatorNamespace()}, dexCertSecret); err != nil {
			r.status.SetDegraded("Failed to read dex tls secret", err.Error())
			return reconcile.Result{}, err
		}

		dexSecret := &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexObjectName, Namespace: rmeta.OperatorNamespace()}, dexSecret); err != nil {
			r.status.SetDegraded("Failed to read dex tls secret", err.Error())
			return reconcile.Result{}, err
		}
		dexCfg = render.NewDexRelyingPartyConfig(authentication, dexCertSecret, dexSecret, r.clusterDomain)
	}

	component := render.LogStorage(
		ls,
		install,
		managementCluster,
		managementClusterConnection,
		elasticsearch,
		kibana,
		clusterConfig,
		[]*corev1.Secret{esCertSecret, esCertSecretESCopy, esPubCertSecret, esAdminUserSecret, kbPubCertSecret},
		kibanaSecrets,
		pullSecrets,
		r.provider,
		curatorSecrets,
		esService,
		kbService,
		r.clusterDomain,
		dexCfg,
		esLicenseType,
	)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
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

		var kibanaInternalCertSecret *corev1.Secret
		for _, s := range kibanaSecrets {
			if s.Name == render.KibanaInternalCertSecret && s.Namespace == rmeta.OperatorNamespace() {
				kibanaInternalCertSecret = s
			}
		}

		esGatewayComponent := esgateway.EsGateway(ls, install, pullSecrets, esAdminUserSecret, kibanaInternalCertSecret, r.clusterDomain)
		if err = imageset.ApplyImageSet(ctx, r.client, variant, esGatewayComponent); err != nil {
			reqLogger.Error(err, "Error with images from ImageSet")
			r.status.SetDegraded("Error with images from ImageSet", err.Error())
			return reconcile.Result{}, err
		}

		if err := hdler.CreateOrUpdateOrDelete(ctx, esGatewayComponent, r.status); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Error creating / updating resource", err.Error())
			return reconcile.Result{}, err
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

		esMetricsSecret, err := utils.GetSecret(context.Background(), r.client, esmetrics.ElasticsearchMetricsSecret, rmeta.OperatorNamespace())
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

		esMetricsComponent := esmetrics.ElasticsearchMetrics(install, pullSecrets, clusterConfig, esMetricsSecret, esPubCertSecret, r.clusterDomain)
		if err = imageset.ApplyImageSet(ctx, r.client, variant, esMetricsComponent); err != nil {
			reqLogger.Error(err, "Error with images from ImageSet")
			r.status.SetDegraded("Error with images from ImageSet", err.Error())
			return reconcile.Result{}, err
		}

		if err := hdler.CreateOrUpdateOrDelete(ctx, esMetricsComponent, r.status); err != nil {
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

// getElasticsearchCertificateSecrets retrieves Elasticsearch certificate secrets needed for Elasticsearch to run or for
// components to communicate with Elasticsearch. The order of the secrets returned are:
// 1) The certificate secret needed for ES Gateway (in the operator namespace). If the user didn't create this it is
//    created.
// 2) The certificate secret needed for ES Gateway (in the Elasticsearch namespace).
// 3) The certificate mounted by other clients that connect to Elasticsearch (through ES Gateway).
// 4) The certificate mounted by other clients that connect to Kibana (through ES Gateway).
func (r *ReconcileLogStorage) getElasticsearchCertificateSecrets(ctx context.Context, instl *operatorv1.InstallationSpec) (
	oprKeyCert *corev1.Secret,
	esKeyCert *corev1.Secret,
	elasticsearchCertSecret *corev1.Secret,
	kibanaCertSecret *corev1.Secret,
	err error) {

	svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	svcDNSNames = append(svcDNSNames, dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, r.clusterDomain)...)
	//svcDNSNames = append(svcDNSNames, "localhost")

	// Get the secret - might be nil
	oprKeyCert, err = utils.GetSecret(ctx, r.client, render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Ensure that cert is valid.
	oprKeyCert, err = utils.EnsureCertificateSecret(render.TigeraElasticsearchCertSecret, oprKeyCert, corev1.TLSPrivateKeyKey, corev1.TLSCertKey, rmeta.DefaultCertificateDuration, svcDNSNames...)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Three different certificate issuers are possible:
	// - The operator self-signed certificate
	// - A user's BYO keypair for Elastic (uncommon)
	// - The issuer that is provided through the certificate management feature.
	keyCertIssuer, err := utils.GetCertificateIssuer(oprKeyCert.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	customerProvidedCert := !utils.IsOperatorIssued(keyCertIssuer)

	// If Certificate management is enabled, we only want to trust the CA cert and let the init container handle private key generation.
	if instl.CertificateManagement != nil {
		cmCa := instl.CertificateManagement.CACert
		cmIssuer, err := utils.GetCertificateIssuer(cmCa)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		// If the issuer of the current secret is not the same as the certificate management issuer and also is not
		// issued by the tigera-operator, it means that it is added to this cluster by the customer. This is not supported
		// in combination with certificate management.
		if customerProvidedCert && cmIssuer != keyCertIssuer {
			return nil, nil, nil, nil, fmt.Errorf("certificate management does not support custom Elasticsearch secrets, please delete secret %s/%s or disable certificate management", oprKeyCert.Namespace, oprKeyCert.Name)
		}

		oprKeyCert.Data[corev1.TLSCertKey] = instl.CertificateManagement.CACert
		esKeyCert = rsecret.CopyToNamespace(render.ElasticsearchNamespace, oprKeyCert)[0]
		elasticsearchCertSecret = render.CreateCertificateSecret(instl.CertificateManagement.CACert, relasticsearch.PublicCertSecret, rmeta.OperatorNamespace())
		kibanaCertSecret = render.CreateCertificateSecret(instl.CertificateManagement.CACert, render.KibanaPublicCertSecret, rmeta.OperatorNamespace())
	} else {
		esKeyCert = rsecret.CopyToNamespace(render.ElasticsearchNamespace, oprKeyCert)[0]
		// Get the elasticsearch pub secret - might be nil
		elasticsearchPubSecret, err := utils.GetSecret(ctx, r.client, relasticsearch.PublicCertSecret, render.ElasticsearchNamespace)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if elasticsearchPubSecret != nil {
			// If the provided certificate secret (secret) is managed by the operator we need to check if the secret that
			// Elasticsearch creates from that given secret (pubSecret) has the expected DNS name. If it doesn't, delete the
			// public secret so it can get recreated.
			if !customerProvidedCert {
				err = utils.SecretHasExpectedDNSNames(elasticsearchPubSecret, corev1.TLSCertKey, svcDNSNames)
				if err == utils.ErrInvalidCertDNSNames {
					if err := r.deleteInvalidECKManagedPublicCertSecret(ctx, elasticsearchPubSecret); err != nil {
						return nil, nil, nil, nil, err
					}
				}
			}

			elasticsearchCertSecret = rsecret.CopyToNamespace(rmeta.OperatorNamespace(), elasticsearchPubSecret)[0]
		} else {
			elasticsearchCertSecret = render.CreateCertificateSecret(oprKeyCert.Data[corev1.TLSCertKey], relasticsearch.PublicCertSecret, rmeta.OperatorNamespace())
		}

		// Get the kibana pub secret - might be nil
		kibanaPubSecret, err := utils.GetSecret(ctx, r.client, render.KibanaPublicCertSecret, render.KibanaNamespace)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if kibanaPubSecret != nil {
			// If the provided certificate secret (secret) is managed by the operator we need to check if the secret that
			// Elasticsearch creates from that given secret (pubSecret) has the expected DNS name. If it doesn't, delete the
			// public secret so it can get recreated.
			if !customerProvidedCert {
				err = utils.SecretHasExpectedDNSNames(kibanaPubSecret, corev1.TLSCertKey, svcDNSNames)
				if err == utils.ErrInvalidCertDNSNames {
					if err := r.deleteInvalidECKManagedPublicCertSecret(ctx, kibanaPubSecret); err != nil {
						return nil, nil, nil, nil, err
					}
				}
			}

			kibanaCertSecret = rsecret.CopyToNamespace(rmeta.OperatorNamespace(), kibanaPubSecret)[0]
		} else {
			kibanaCertSecret = render.CreateCertificateSecret(oprKeyCert.Data[corev1.TLSCertKey], render.KibanaPublicCertSecret, rmeta.OperatorNamespace())
		}
	}

	return oprKeyCert, esKeyCert, elasticsearchCertSecret, kibanaCertSecret, err
}

func (r *ReconcileLogStorage) kibanaSecrets(ctx context.Context, instl *operatorv1.InstallationSpec) ([]*corev1.Secret, error) {

	var secrets []*corev1.Secret
	svcDNSNames := dns.GetServiceDNSNames(render.KibanaInternalServiceName, render.KibanaNamespace, r.clusterDomain)

	// Get the secret - might be nil
	secret, err := utils.GetSecret(ctx, r.client, render.TigeraKibanaCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		return nil, err
	}

	// Ensure that cert is valid.
	secret, err = utils.EnsureCertificateSecret(render.TigeraKibanaCertSecret, secret, corev1.TLSPrivateKeyKey, corev1.TLSCertKey, rmeta.DefaultCertificateDuration, svcDNSNames...)
	if err != nil {
		return nil, err
	}

	if instl.CertificateManagement != nil {
		return []*corev1.Secret{
			secret,
			rsecret.CopyToNamespace(render.KibanaNamespace, secret)[0],
			render.CreateCertificateSecret(instl.CertificateManagement.CACert, relasticsearch.InternalCertSecret, render.KibanaNamespace),
			render.CreateCertificateSecret(instl.CertificateManagement.CACert, render.KibanaInternalCertSecret, rmeta.OperatorNamespace()),
		}, nil
	}

	secrets = append(secrets, secret, rsecret.CopyToNamespace(render.KibanaNamespace, secret)[0])

	// Get the pub secret - might be nil
	pubSecret, err := utils.GetSecret(ctx, r.client, render.KibanaInternalCertSecret, render.KibanaNamespace)
	if err != nil {
		return nil, err
	}

	if pubSecret == nil {
		log.Info(fmt.Sprintf("Public cert secret %q not found yet", render.KibanaInternalCertSecret))
		return secrets, nil
	}

	issuer, err := utils.GetCertificateIssuer(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}

	if utils.IsOperatorIssued(issuer) {
		err = utils.SecretHasExpectedDNSNames(pubSecret, corev1.TLSCertKey, svcDNSNames)
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
	err := r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchInternalServiceName, Namespace: render.ElasticsearchNamespace}, &svc)
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
	err := r.client.Get(ctx, client.ObjectKey{Name: render.KibanaInternalServiceName, Namespace: render.KibanaNamespace}, &svc)
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
