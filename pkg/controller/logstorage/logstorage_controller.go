package logstorage

import (
	"context"
	"fmt"
	cmneckalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1alpha1"
	esalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1alpha1"
	kibanaalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1alpha1"
	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
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
	"time"
)

var log = logf.Log.WithName("controller_logstorage")

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

	return instance, nil
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
			reqLogger.Info("LogStorage object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying LogStorage", err.Error())
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Loaded config", "config", ls)
	r.status.OnCRFound()

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

	reqLogger.V(2).Info("Creating Elasticsearch components")
	hdler := utils.NewComponentHandler(log, r.client, r.scheme, ls)
	component, err := render.Elasticsearch(
		ls,
		esCertSecret,
		kibanaCertSecret,
		createWebhookSecret,
		pullSecrets,
		r.provider == operatorv1.ProviderOpenShift,
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
	if isOp, err := r.isElasticsearchOperational(ctx); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error figuring out if elasticsearch is operational", err)
		return reconcile.Result{}, err
	} else if !isOp {
		r.setDegraded(ctx, reqLogger, ls, "Waiting for Elasticsearch cluster to be operational", nil)
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	reqLogger.V(2).Info("Checking if Kibana is operational")
	if isOp, err := r.isKibanaReady(ctx); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Failed to figure out if Kibana is operational", err)
		return reconcile.Result{}, err
	} else if !isOp {
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

func (r *ReconcileLogStorage) isElasticsearchOperational(ctx context.Context) (bool, error) {
	es := &esalpha1.Elasticsearch{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, es); err != nil {
		return false, err
	} else if es.Status.Phase == "Operational" || es.Status.Phase == esalpha1.ElasticsearchReadyPhase {
		return true, nil
	}

	return false, nil
}

func (r *ReconcileLogStorage) isKibanaReady(ctx context.Context) (bool, error) {
	es := &kibanaalpha1.Kibana{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.KibanaName, Namespace: render.KibanaNamespace}, es); err != nil {
		return false, err
	} else if es.Status.AssociationStatus == cmneckalpha1.AssociationEstablished {
		return true, nil
	}

	return false, nil
}
