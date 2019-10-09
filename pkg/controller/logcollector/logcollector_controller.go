package logcollector

import (
	"context"
	"fmt"
	"github.com/tigera/operator/pkg/elasticsearch"
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"
	"time"

	corev1 "k8s.io/api/core/v1"
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

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
)

var log = logf.Log.WithName("controller_logcollector")

func init() {
	log.V(2).Info("registering Elasticsearch users for creation")
	esusers.AddUser(elasticsearch.User{
		Username: render.ElasticsearchUserLogCollector,
		Roles: []elasticsearch.Role{{
			Name:    render.ElasticsearchUserLogCollector,
			Cluster: []string{"monitor", "manage_index_templates"},
			Indices: []elasticsearch.RoleIndex{{
				Names:      []string{"tigera_secure_ee_*"},
				Privileges: []string{"create_index", "write"},
			}},
		}},
	})
}

// Add creates a new LogCollector Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, provider operatorv1.Provider, tsee bool) error {
	if !tsee {
		// No need to start this controller.
		return nil
	}
	return add(mgr, newReconciler(mgr, provider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operatorv1.Provider) reconcile.Reconciler {
	c := &ReconcileLogCollector{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: provider,
		status:   status.New(mgr.GetClient(), "log-collector"),
	}
	c.status.Run()
	return c
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("logcollector-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create logcollector-controller: %v", err)
	}

	// Watch for changes to primary resource LogCollector
	err = c.Watch(&source.Kind{Type: &operatorv1.LogCollector{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch primary resource: %v", err)
	}

	err = utils.AddAPIServerWatch(c)
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch APIServer resource: %v", err)
	}

	esUser, err := esusers.GetUser(render.ElasticsearchUserLogCollector)
	if err != nil {
		// this error indicates a programming error, where we are trying to get an Elasticsearch user that hasn't been
		// registered with esusers.AddUser, and if this is the case the Elasticsearch user secret will never exist.
		return err
	}

	if err = utils.AddSecretsWatch(c, esUser.SecretName(), render.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-collector-controller failed to watch the Secret resource: %v", err)
	}

	if err = utils.AddSecretsWatch(c, render.ElasticsearchPublicCertSecret, render.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-collector-controller failed to watch the Secret resource: %v", err)
	}

	if err = utils.AddSecretsWatch(c, render.S3FluentdSecretName, render.OperatorNamespace()); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch Secret %s: %v", render.S3FluentdSecretName, err)
	}

	if err = utils.AddConfigMapWatch(c, render.FluentdFilterConfigMapName, render.OperatorNamespace()); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch ConfigMap %s: %v", render.FluentdFilterConfigMapName, err)
	}

	return nil
}

// blank assignment to verify that ReconcileLogCollector implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogCollector{}

// ReconcileLogCollector reconciles a LogCollector object
type ReconcileLogCollector struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	provider operatorv1.Provider
	status   *status.StatusManager
}

// GetLogCollector returns the default LogCollector instance with defaults populated.
func GetLogCollector(ctx context.Context, cli client.Client) (*operatorv1.LogCollector, error) {
	// Fetch the instance. We only support a single instance named "tigera-secure".
	instance := &operatorv1.LogCollector{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	if instance.Spec.Syslog != nil {
		_, _, _, err := render.ParseEndpoint(instance.Spec.Syslog.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("Syslog config has invalid Endpoint: %s", err)
		}
	}

	return instance, nil
}

// Reconcile reads that state of the cluster for a LogCollector object and makes changes based on the state read
// and what is in the LogCollector.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogCollector) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogCollector")

	// Fetch the LogCollector instance
	instance, err := GetLogCollector(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("LogCollector object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying Manager", err.Error())
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded("Waiting for Tigera API server to be ready", "")
		return reconcile.Result{}, nil
	}

	if err = utils.CheckLicenseKey(context.Background(), r.client); err != nil {
		r.status.SetDegraded("License not found", err.Error())
		return reconcile.Result{RequeueAfter: 10 * time.Second}, err
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	installation, err := installation.GetInstallation(context.Background(), r.client, r.provider)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Retrieving LogStorage resource")

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	clusterName, err := utils.ClusterName(context.Background(), r.client)
	if err != nil {
		log.Error(err, "Failed to get the cluster name")
		r.status.SetDegraded("Failed to get the cluster name", err.Error())
		return reconcile.Result{}, err
	}

	esSecrets, err := utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchUserLogCollector}, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	var s3Credential *render.S3Credential
	if instance.Spec.S3 != nil {
		s3Credential, err = getS3Credential(r.client)
		if err != nil {
			log.Error(err, "Error with S3 credential secret")
			r.status.SetDegraded("Error with S3 credential secret", err.Error())
			return reconcile.Result{}, err
		}
		if s3Credential == nil {
			log.Info("S3 credential secret does not exist")
			r.status.SetDegraded("S3 credential secret does not exist", "")
			return reconcile.Result{}, nil
		}
	}

	filters, err := getFluentdFilters(r.client)
	if err != nil {
		log.Error(err, "Error retrieving Fluentd filters")
		r.status.SetDegraded("Error retrieving Fluentd filters", err.Error())
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	component := render.Fluentd(
		instance,
		esSecrets,
		clusterName,
		s3Credential,
		filters,
		pullSecrets,
		installation,
	)

	if err := handler.CreateOrUpdate(context.Background(), component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CRD status.
	instance.Status.State = operatorv1.LogControllerStatusReady
	if err = r.client.Status().Update(context.Background(), instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func getS3Credential(client client.Client) (*render.S3Credential, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      render.S3FluentdSecretName,
		Namespace: render.OperatorNamespace(),
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

func getFluentdFilters(client client.Client) (*render.FluentdFilters, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      render.FluentdFilterConfigMapName,
		Namespace: render.OperatorNamespace(),
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
