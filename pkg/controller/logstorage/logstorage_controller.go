package logstorage

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"

	esalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1alpha1"
	kibanaalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1alpha1"
	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
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
	defaultResolveConfPath = "/etc/resolv.conf"
	defaultLocalDNS        = "svc.cluster.local"
)

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, provider operatorv1.Provider, tsee bool) error {
	if !tsee {
		return nil
	}

	r, err := newReconciler(mgr.GetClient(), mgr.GetScheme(), status.New(mgr.GetClient(), "log-storage"), defaultResolveConfPath, provider)
	if err != nil {
		return err
	}

	return add(mgr, r)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(cli client.Client, schema *runtime.Scheme, statusMgr *status.StatusManager, resolvConfPath string, provider operatorv1.Provider) (*ReconcileLogStorage, error) {
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

	if err := utils.AddServiceWatch(c, render.ElasticsearchServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Service resource: %v", err)
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
	localDNS string
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

	if network.Spec.ClusterManagementType == operatorv1.ClusterManagementTypeManaged {
		return r.reconcileManaged(ctx, network, reqLogger)
	}

	return r.reconcileUnmanaged(ctx, network, reqLogger)
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
