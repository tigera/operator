package logstorage

import (
	"context"
	"fmt"
	eckv1alpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1alpha1"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
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

	if err = c.Watch(&source.Kind{Type: &eckv1alpha1.Elasticsearch{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operator.LogStorage{},
	}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Elasticsearch resource: %v", err)
	}

	esUsers := esusers.GetUsers()
	var secretsToWatch []string
	for _, user := range esUsers {
		secretsToWatch = append(secretsToWatch, user.SecretName())
	}
	secretsToWatch = append(secretsToWatch, render.TigeraElasticsearchCertSecret, render.ECKWebhookSecretName)

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
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	if network.Status.Variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		log.Error(err, "Error retrieving pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	if err := r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchStorageClass}, &storagev1.StorageClass{}); err != nil {
		reqLogger.Error(err, fmt.Sprintf("Couldn't find storage class %s, this must be provided", render.ElasticsearchStorageClass))
		r.status.SetDegraded(fmt.Sprintf("Couldn't find storage class %s, this must be provided", render.ElasticsearchStorageClass), err.Error())
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	esCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}, esCertSecret); err != nil {
		if errors.IsNotFound(err) {
			esCertSecret = nil
		} else {
			reqLogger.Error(err, "Failed to read Elasticsearch cert secret")
			r.status.SetDegraded("Failed to read Elasticsearch cert secret", err.Error())
			return reconcile.Result{}, err
		}
	}

	// ECK requires that we provide it a secret to put add certificate information in for it's webhooks. If it's created
	// we don't want to overwrite it as we'll lose the certificate information the ECK operator relies on.
	createWebhookSecret := false
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ECKWebhookSecretName, Namespace: render.ECKOperatorNamespace}, &corev1.Secret{}); err != nil {
		if errors.IsNotFound(err) {
			createWebhookSecret = true
		} else {
			reqLogger.Error(err, "Failed to read Elasticsearch webhook secret")
			r.status.SetDegraded("Failed to read Elasticsearch webhook secret", err.Error())
			return reconcile.Result{}, err
		}
	}

	reqLogger.V(2).Info("Creating Elasticsearch components")
	hdler := utils.NewComponentHandler(log, r.client, r.scheme, ls)
	component, err := render.Elasticsearch(
		ls,
		esCertSecret,
		createWebhookSecret,
		pullSecrets,
		r.provider == operatorv1.ProviderOpenShift,
		network.Spec.Registry,
	)
	if err != nil {
		reqLogger.Error(err, "Error rendering LogStorage")
		r.status.SetDegraded("Error rendering LogStorage", err.Error())
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdate(ctx, component, r.status); err != nil {
		reqLogger.Error(err, "Error creating / update resource")
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Checking if Elasticsearch is operational")
	if isOp, err := r.isElasticsearchOperational(ctx); err != nil {
		reqLogger.Error(err, "Error figuring out if elasticsearch is operational")
		r.status.SetDegraded("Error figuring out if elasticsearch is operational", err.Error())
		return reconcile.Result{}, err
	} else if !isOp {
		reqLogger.Info("Waiting for Elasticsearch to be operational")
		r.status.SetDegraded("Waiting for Elasticsearch cluster to be operational", "")

		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	reqLogger.V(2).Info("Elasticsearch is operational, creating elasticsearch users and secrets for components that need Elasticsearch access")

	esPublicCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}, esPublicCertSecret); err != nil {
		reqLogger.Error(err, "Failed to read Elasticsearch public cert secret")
		r.status.SetDegraded("Failed to read Elasticsearch public cert secret", err.Error())
		return reconcile.Result{}, err
	}

	esUsers, err := elasticsearchUsers(ctx, esPublicCertSecret, r.client)
	if err != nil {
		reqLogger.Error(err, "Error creating Elasticsearch credentials")
		r.status.SetDegraded("Error creating Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdate(ctx, render.ElasticsearchSecrets(esUsers, esPublicCertSecret), r.status); err != nil {
		reqLogger.Error(err, "Error creating / update resource")
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	reqLogger.V(2).Info("Elasticsearch users and secrets created for components needing Elasticsearch access")
	ls.Status.State = operatorv1.LogStorageStatusReady
	if err := r.client.Status().Update(ctx, ls); err != nil {
		reqLogger.Error(err, fmt.Sprintf("Error updating the log-storage status %s", operatorv1.LogStorageStatusReady))
		r.status.SetDegraded(fmt.Sprintf("Error updating the log-storage status %s", operatorv1.LogStorageStatusReady), err.Error())
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileLogStorage) isElasticsearchOperational(ctx context.Context) (bool, error) {
	es := &eckv1alpha1.Elasticsearch{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, es); err != nil {
		return false, err
	} else if es.Status.Phase == "Operational" || es.Status.Phase == eckv1alpha1.ElasticsearchReadyPhase {
		return true, nil
	}

	return false, nil
}
