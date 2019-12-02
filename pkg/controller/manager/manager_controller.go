package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/tigera/operator/pkg/elasticsearch"
	esusers "github.com/tigera/operator/pkg/elasticsearch/users"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/compliance"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

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
)

var log = logf.Log.WithName("controller_manager")

const (
	defaultClusterType = "standalone"
)

func init() {
	esusers.AddUser(elasticsearch.User{Username: render.ElasticsearchUserManager,
		Roles: []elasticsearch.Role{{
			Name: render.ElasticsearchUserManager,
			Definition: &elasticsearch.RoleDefinition{
				Cluster: []string{"monitor"},
				Indices: []elasticsearch.RoleIndex{{
					Names:      []string{"tigera_secure_ee_*", ".kibana"},
					Privileges: []string{"read"},
				}},
			},
		}},
	})
}

// Add creates a new Manager Controller and adds it to the Manager. The Manager will set fields on the Controller
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
	c := &ReconcileManager{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: provider,
		status:   status.New(mgr.GetClient(), "manager"),
	}
	c.status.Run()
	return c

}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("manager-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create manager-controller: %v", err)
	}

	// Watch for changes to primary resource Manager
	err = c.Watch(&source.Kind{Type: &operatorv1.Manager{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %v", err)
	}

	err = utils.AddAPIServerWatch(c)
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch APIServer resource: %v", err)
	}

	err = utils.AddComplianceWatch(c)
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch compliance resource: %v", err)
	}

	err = utils.AddMulticlusterConfigWatch(c)
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch MulticlusterConfig resource: %v", err)
	}

	for _, secretName := range []string{
		render.ManagerTLSSecretName,
		render.ElasticsearchPublicCertSecret,
		render.ElasticsearchUserManager,
		render.KibanaPublicCertSecret,
		render.VoltronTunnelSecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, render.OperatorNamespace()); err != nil {
			return fmt.Errorf("manager-controller failed to watch the Secret resource: %v", err)
		}
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileManager{}

// ReconcileManager reconciles a Manager object
type ReconcileManager struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	provider operatorv1.Provider
	status   *status.StatusManager
}

// GetManager returns the default manager instance with defaults populated.
func GetManager(ctx context.Context, cli client.Client) (*operatorv1.Manager, error) {
	// Fetch the manager instance. We only support a single instance named "default".
	instance := &operatorv1.Manager{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	// Populate the instance with defaults for any fields not provided by the user.
	if instance.Spec.Auth == nil {
		instance.Spec.Auth = &operatorv1.Auth{
			Type:      operatorv1.AuthTypeToken,
			Authority: "",
			ClientID:  "",
		}
	}
	return instance, nil
}

// GetManager returns the default multicluster config with defaults populated.
func getMulticlusterConfig(ctx context.Context, cli client.Client) (*operatorv1.MulticlusterConfig, error) {
	// Fetch the multicluster config instance. We only support a single instance.
	instance := &operatorv1.MulticlusterConfig{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	// Validate the CR
	if instance.Spec.ClusterManagementType == "management" && instance.Spec.ManagementClusterAddr == "" {
		return nil, fmt.Errorf("ManagementClusterAddr is a required field when clusterManagementType='management'")
	}
	if instance.Spec.ClusterManagementType == "management" && instance.Spec.ManagementClusterPort == 0 {
		return nil, fmt.Errorf("ManagementClusterPort is a required field when clusterManagementType='management'")
	}

	// Populate the instance with defaults for any fields not provided by the user.
	if instance.Spec.ClusterManagementType == "" {
		instance.Spec.ClusterManagementType = defaultClusterType
	}

	return instance, nil
}

// Reconcile reads that state of the cluster for a Manager object and makes changes based on the state read
// and what is in the Manager.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileManager) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Manager")
	ctx := context.Background()

	// Fetch the Manager instance
	instance, err := GetManager(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Manager object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying Manager", err.Error())
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	// Write the manager back to the datastore.
	if err = r.client.Update(ctx, instance); err != nil {
		r.status.SetDegraded("Failed to write defaults", err.Error())
		return reconcile.Result{}, err
	}

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded("Waiting for Tigera API server to be ready", "")
		return reconcile.Result{}, nil
	}

	if err = utils.CheckLicenseKey(ctx, r.client); err != nil {
		r.status.SetDegraded("License not found", err.Error())
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	installation, err := installation.GetInstallation(ctx, r.client, r.provider)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	// Check that compliance is running.
	compliance, err := compliance.GetCompliance(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Compliance not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying compliance", err.Error())
		return reconcile.Result{}, err
	}
	if compliance.Status.State != operatorv1.ComplianceStatusReady {
		r.status.SetDegraded("Compliance is not ready", fmt.Sprintf("compliance status: %s", compliance.Status.State))
		return reconcile.Result{}, nil
	}

	// Check that if the manager certpair secret exists that it is valid (has key and cert fields)
	// If it does not exist then this function returns a nil secret but no error and a self-signed
	// certificate will be generated when rendering below.
	tlsSecret, err := utils.ValidateCertPair(r.client,
		render.ManagerTLSSecretName,
		render.ManagerSecretKeyName,
		render.ManagerSecretCertName,
	)
	if err != nil {
		log.Error(err, "Invalid TLS Cert")
		r.status.SetDegraded("Error validating TLS certificate", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	kibanaPublicCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.KibanaPublicCertSecret, Namespace: render.OperatorNamespace()}, kibanaPublicCertSecret); err != nil {
		reqLogger.Error(err, "Failed to read Kibana public cert secret")
		r.status.SetDegraded("Failed to read Kibana public cert secret", err.Error())
		return reconcile.Result{}, err
	}

	clusterName, err := utils.ClusterName(ctx, r.client)
	if err != nil {
		log.Error(err, "Failed to get the cluster name")
		r.status.SetDegraded("Failed to get the cluster name", err.Error())
		return reconcile.Result{}, err
	}

	esSecrets, err := utils.ElasticsearchSecrets(ctx, []string{render.ElasticsearchUserManager}, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	// Check the multi cluster settings
	mcmCfg, err := getMulticlusterConfig(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Continuing without multicluster configuration")
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get multicluster configuration", err.Error())
		return reconcile.Result{}, err
	}

	// If clusterType is not management, clean up unnecessary resources.
	err = cleanUpMcm(mcmCfg, ctx, r.client)
	if err != nil {
		r.status.SetDegraded("Failed to clean up multicluster configuration", err.Error())
		return reconcile.Result{}, err
	}

	// If clusterType is management and the customer brings it's own cert, copy it over to the manager ns.
	tunnelsecret, err := copyTunnelSecret(mcmCfg, ctx, r.client)

	if err != nil {
		r.status.SetDegraded("Failed to copy multicluster tunnel secret", err.Error())
		return reconcile.Result{}, err
	}

	// Calculate the hash that we add as an annotation to the deployment.
	var voltronAnnotation string
	if tunnelsecret != nil {
		voltronAnnotation = render.AnnotationHash(tunnelsecret.Data)
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	component, err := render.Manager(
		instance,
		esSecrets,
		[]*corev1.Secret{kibanaPublicCertSecret},
		clusterName,
		tlsSecret,
		pullSecrets,
		r.provider == operatorv1.ProviderOpenShift,
		installation.Spec.Registry,
		&mcmCfg.Spec,
		voltronAnnotation,
	)
	if err != nil {
		log.Error(err, "Error rendering Manager")
		r.status.SetDegraded("Error rendering Manager", err.Error())
		return reconcile.Result{}, err
	}

	if err := handler.CreateOrUpdate(ctx, component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	if r.status.IsAvailable() {
		instance.Status.Auth = instance.Spec.Auth
		if err = r.client.Status().Update(ctx, instance); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// The user can provide a secret for setting up the tunnel. If it does, we copy it over to the manager namespace,
// otherwise, we proceed and create a new secret. Returns the secret if applicable.
func copyTunnelSecret(config *operatorv1.MulticlusterConfig, ctx context.Context, cli client.Client) (*corev1.Secret, error) {
	if config == nil || config.Spec.ClusterManagementType != "management" {
		// nothing to copy
		return nil, nil
	}
	oprSec, oprSecFound, err := getTunnelSecret(ctx, cli, render.OperatorNamespace())
	if err != nil {
		return nil, err
	}

	mgrSec, mgrSecFound, err := getTunnelSecret(ctx, cli, render.ManagerNamespace)
	if err != nil {
		return nil, err
	}

	if !oprSecFound {
		if !mgrSecFound {
			// No secrets are found in either namespace, so there is nothing to do here.
			return nil, nil
		} else {
			// There is a secret in the manager namespace, so we return it.
			return mgrSec, nil
		}
	}

	// Copy over the secret data to the manager secret.
	mgrSec.Data = oprSec.Data

	if !mgrSecFound {
		mgrSec.Name = render.VoltronTunnelSecretName
		mgrSec.Namespace = render.ManagerNamespace
		return mgrSec, cli.Create(ctx, mgrSec)
	}
	return mgrSec, cli.Update(ctx, mgrSec)
}

func getTunnelSecret(ctx context.Context, cli client.Client, ns string) (*corev1.Secret, bool, error) {
	secret := &corev1.Secret{}
	err := cli.Get(ctx, client.ObjectKey{Name: render.VoltronTunnelSecretName, Namespace: ns}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return secret, false, nil
		}
		return nil, false, err
	}
	return secret, true, nil
}

// If a cluster is no longer of type management, there are resources that should be cleaned up
func cleanUpMcm(config *operatorv1.MulticlusterConfig, ctx context.Context, cli client.Client) error {
	if config != nil && config.Spec.ClusterManagementType == "management" {
		// nothing to clean up
		return nil
	}
	// Remove the unnecessary service if there is one
	svc := &corev1.Service{}
	err := cli.Get(ctx, client.ObjectKey{Name: render.VoltronName, Namespace: render.ManagerNamespace}, svc)
	found := true
	if err != nil {
		if errors.IsNotFound(err) {
			found = false
		} else {
			return err
		}
	}
	if found {
		err = cli.Delete(ctx, svc)
		if err != nil {
			return err
		}
	}
	// Remove unnecessary secret if there is one
	sec := &corev1.Secret{}
	err = cli.Get(ctx, client.ObjectKey{Name: render.VoltronTunnelSecretName, Namespace: render.ManagerNamespace}, sec)
	found = true
	if err != nil {
		if errors.IsNotFound(err) {
			found = false
		} else {
			return err
		}
	}
	if found {
		return cli.Delete(ctx, sec)
	}
	return nil
}
