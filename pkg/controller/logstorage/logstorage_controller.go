package logstorage

import (
	"context"
	"fmt"
	"github.com/elastic/cloud-on-k8s/pkg/utils/stringsutil"
	"time"

	cmneckalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1alpha1"
	esalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1alpha1"
	kibanaalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1alpha1"
	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/elasticsearch"
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_logstorage")

const (
	finalizer                  = "tigera.io/eck-cleanup"
	defaultElasticsearchShards = 5
)

func init() {
	esusers.AddUser(elasticsearch.User{
		Username: render.ElasticsearchUserCurator,
		Roles: []elasticsearch.Role{{
			Name: render.ElasticsearchUserCurator,
			Definition: &elasticsearch.RoleDefinition{
				Cluster: []string{"monitor", "manage_index_templates"},
				Indices: []elasticsearch.RoleIndex{{
					Names:      []string{"tigera_secure_ee_*"},
					Privileges: []string{"all"},
				}},
			},
		}},
	})
}

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, provider operatorv1.Provider, tsee bool) error {
	if !tsee {
		return nil
	}
	return add(mgr, newReconciler(mgr, provider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operatorv1.Provider) reconcile.Reconciler {
	c := &ReconcileLogStorage{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		status:   status.New(mgr.GetClient(), "log-storage"),
		provider: provider,
	}

	c.status.Run()
	return c
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
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
		return fmt.Errorf("log-storage-controller failed to watch Network resource: %v", err)
	}

	if err = c.Watch(&source.Kind{Type: &esalpha1.Elasticsearch{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1.LogStorage{},
	}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Elasticsearch resource: %v", err)
	}

	if err = c.Watch(&source.Kind{Type: &kibanaalpha1.Kibana{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1.LogStorage{},
	}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Kibana resource: %v", err)
	}

	esUsers := esusers.GetUsers()
	var secretsToWatch []string
	for _, user := range esUsers {
		secretsToWatch = append(secretsToWatch, user.SecretName())
	}
	secretsToWatch = append(secretsToWatch, render.TigeraElasticsearchCertSecret, render.TigeraKibanaCertSecret, render.ECKWebhookSecretName)

	// Watch all the secrets created by this controller so we can regenerate any that are deleted
	for _, secretName := range secretsToWatch {
		if err = utils.AddSecretsWatch(c, secretName, render.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %v", err)
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
	client   client.Client
	scheme   *runtime.Scheme
	status   *status.StatusManager
	provider operatorv1.Provider
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
		var arr int32 = 365
		opr.Spec.Retention.AuditReports = &arr
	}
	if opr.Spec.Retention.Snapshots == nil {
		var sr int32 = 365
		opr.Spec.Retention.Snapshots = &sr
	}
	if opr.Spec.Retention.ComplianceReports == nil {
		var crr int32 = 365
		opr.Spec.Retention.ComplianceReports = &crr
	}

	if opr.Spec.Indices == nil {
		opr.Spec.Indices = &operatorv1.Indices{}
	}

	if opr.Spec.Indices.Replicas == nil {
		var replicas int32 = render.DefaultElasticsearchReplicas
		opr.Spec.Indices.Replicas = &replicas
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

	// Fetch the LogStorage instance
	ls, err := GetLogStorage(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("LogStorage resource not found", "")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying LogStorage", err.Error())
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Loaded config", "config", ls)
	r.status.OnCRFound()

	if ls.DeletionTimestamp != nil {
		return r.finalizeDeletion(ctx, ls)
	}

	if !stringsutil.StringInSlice(finalizer, ls.GetFinalizers()) {
		ls.SetFinalizers(append(ls.GetFinalizers(), finalizer))
	}

	// Write back the LogStorage object to update any defaults that were set
	if err = r.client.Update(ctx, ls); err != nil {
		r.status.SetDegraded("Failed to update LogStorage with defaults", err.Error())
		return reconcile.Result{}, err
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	network, err := installation.GetInstallation(context.Background(), r.client, r.provider)
	if err != nil {
		if errors.IsNotFound(err) {
			r.setDegraded(ctx, reqLogger, ls, "Installation not found", err)
			return reconcile.Result{}, err
		}
		r.setDegraded(ctx, reqLogger, ls, "Error querying installation", err)
		return reconcile.Result{}, err
	}

	if network.Status.Variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error retrieving pull secrets", err)
		return reconcile.Result{}, err
	}

	if err := r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchStorageClass}, &storagev1.StorageClass{}); err != nil {
		r.setDegraded(ctx, reqLogger, ls, fmt.Sprintf("Couldn't find storage class %s, this must be provided", render.ElasticsearchStorageClass), err)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	esCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}, esCertSecret); err != nil {
		if errors.IsNotFound(err) {
			esCertSecret = nil
		} else {
			r.setDegraded(ctx, reqLogger, ls, "Failed to read Elasticsearch cert secret", err)
			return reconcile.Result{}, err
		}
	}

	kibanaCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}, kibanaCertSecret); err != nil {
		if errors.IsNotFound(err) {
			kibanaCertSecret = nil
		} else {
			r.setDegraded(ctx, reqLogger, ls, "Failed to read Kibana cert secret", err)
			return reconcile.Result{}, err
		}
	}

	// The ECK operator requires that we provide it with a secret so it can add certificate information in for it's webhooks.
	// If it's created we don't want to overwrite it as we'll lose the certificate information the ECK operator relies on.
	createWebhookSecret := false
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ECKWebhookSecretName, Namespace: render.ECKOperatorNamespace}, &corev1.Secret{}); err != nil {
		if errors.IsNotFound(err) {
			createWebhookSecret = true
		} else {
			r.setDegraded(ctx, reqLogger, ls, "Failed to read Elasticsearch webhook secret", err)
			return reconcile.Result{}, err
		}
	}

	esClusterConfig := render.NewElasticsearchClusterConfig("cluster", ls.Replicas(), defaultElasticsearchShards)

	reqLogger.V(2).Info("Creating Elasticsearch components")
	hdler := utils.NewComponentHandler(log, r.client, r.scheme, ls)
	component, err := render.Elasticsearch(
		ls,
		esClusterConfig,
		esCertSecret,
		kibanaCertSecret,
		createWebhookSecret,
		pullSecrets,
		r.provider,
		network.Spec.Registry,
	)
	if err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error rendering LogStorage", err)
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdate(ctx, component, r.status); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error creating / updating resource", err)
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Checking if Elasticsearch is operational")
	if isReady, err := r.isElasticsearchReady(ctx); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error figuring out if elasticsearch is operational", err)
		return reconcile.Result{}, err
	} else if !isReady {
		r.setDegraded(ctx, reqLogger, ls, "Waiting for Elasticsearch cluster to be operational", nil)
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	reqLogger.V(2).Info("Checking if Kibana is operational")
	if isReady, err := r.isKibanaReady(ctx); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Failed to figure out if Kibana is operational", err)
		return reconcile.Result{}, err
	} else if !isReady {
		r.setDegraded(ctx, reqLogger, ls, "Waiting for Kibana to be operational", nil)
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	reqLogger.V(2).Info("Elasticsearch and Kibana are operational")
	esPublicCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}, esPublicCertSecret); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Failed to read Elasticsearch public cert secret", err)
		return reconcile.Result{}, err
	}

	kibanaPublicCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}, kibanaPublicCertSecret); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Failed to read Kibana public cert secret", err)
		return reconcile.Result{}, err
	}

	updatedESUserSecrets, err := updatedElasticsearchUserSecrets(ctx, esPublicCertSecret, r.client)
	if err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error creating Elasticsearch credentials", err)
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdate(ctx, render.ElasticsearchSecrets(updatedESUserSecrets, esPublicCertSecret, kibanaPublicCertSecret), r.status); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error creating / update resource", err)
		return reconcile.Result{}, err
	}

	esSecrets, err := utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchUserCurator}, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	curatorComponent := render.ElasticCurator(*ls, esSecrets, pullSecrets, network.Spec.Registry, render.DefaultElasticsearchClusterName)
	if err := hdler.CreateOrUpdate(ctx, curatorComponent, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	r.status.SetCronJobs([]types.NamespacedName{{Name: render.EsCuratorName, Namespace: render.ElasticsearchNamespace}})

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	reqLogger.V(2).Info("Elasticsearch users and secrets created for components needing Elasticsearch access")
	if err := r.updateStatus(ctx, reqLogger, ls, operatorv1.LogStorageStatusReady); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileLogStorage) setDegraded(ctx context.Context, reqLogger logr.Logger, ls *operatorv1.LogStorage, message string, err error) {
	if err := r.updateStatus(ctx, reqLogger, ls, operatorv1.LogStorageStatusDegraded); err != nil {
		reqLogger.Error(err, fmt.Sprintf("Failed to update LogStorage status to %s", operatorv1.LogStorageStatusDegraded))
	}
	if err == nil {
		reqLogger.Info(message)
		r.status.SetDegraded(message, "")
	} else {
		reqLogger.Error(err, message)
		r.status.SetDegraded(message, err.Error())
	}
}

func (r *ReconcileLogStorage) updateStatus(ctx context.Context, reqLogger logr.Logger, ls *operatorv1.LogStorage, state string) error {
	ls.Status.State = state
	if err := r.client.Status().Update(ctx, ls); err != nil {
		reqLogger.Error(err, fmt.Sprintf("Error updating the log-storage status %s", state))
		r.status.SetDegraded(fmt.Sprintf("Error updating the log-storage status %s", state), err.Error())
		return err
	}

	return nil
}

func (r *ReconcileLogStorage) isElasticsearchReady(ctx context.Context) (bool, error) {
	if es, err := r.getElasticsearch(ctx); err != nil {
		return false, err
	} else if es.Status.Phase == "Operational" || es.Status.Phase == esalpha1.ElasticsearchReadyPhase {
		return true, nil
	}

	return false, nil
}

func (r *ReconcileLogStorage) isKibanaReady(ctx context.Context) (bool, error) {
	if kb, err := r.getKibana(ctx); err != nil {
		return false, err
	} else if kb.Status.AssociationStatus == cmneckalpha1.AssociationEstablished {
		return true, nil
	}

	return false, nil
}

func elasticsearchKey() client.ObjectKey {
	return client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}
}

func kibanaKey() client.ObjectKey {
	return client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}
}

func (r *ReconcileLogStorage) getElasticsearch(ctx context.Context) (*esalpha1.Elasticsearch, error) {
	es := esalpha1.Elasticsearch{}
	return &es, r.client.Get(ctx, elasticsearchKey(), &es)
}

func (r *ReconcileLogStorage) getKibana(ctx context.Context) (*kibanaalpha1.Kibana, error) {
	kb := kibanaalpha1.Kibana{}
	return &kb, r.client.Get(ctx, kibanaKey(), &kb)
}

// finalizeDeletion makes sure that both kibana and elasticsearch are deleted before removing the finalizers on the LogStorage
// resource. This needs to happen because the eck operator will be deleted when the LogStorage resource is deleted, but
// the eck operator is needed to delete elasticsearch and kibana
func (r *ReconcileLogStorage) finalizeDeletion(ctx context.Context, ls *operatorv1.LogStorage) (reconcile.Result, error) {
	// remove elasticsearch
	if es, err := r.getElasticsearch(ctx); err == nil {
		if err := r.client.Delete(ctx, es); err != nil {
			r.status.SetDegraded("Failed to delete elasticsearch", err.Error())
			return reconcile.Result{}, err
		}
	} else if !errors.IsNotFound(err) {
		return reconcile.Result{}, err
	}

	// remove kibana
	if kb, err := r.getKibana(ctx); err == nil {
		if err := r.client.Delete(ctx, kb); err != nil {
			r.status.SetDegraded("Failed to delete kibana", err.Error())
			return reconcile.Result{}, err
		}
	} else if !errors.IsNotFound(err) {
		return reconcile.Result{}, err
	}

	// remove the finalizer now that elasticsearch and kibana have been deleted
	ls.SetFinalizers(stringsutil.RemoveStringInSlice(finalizer, ls.GetFinalizers()))
	if err := r.client.Update(ctx, ls); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
