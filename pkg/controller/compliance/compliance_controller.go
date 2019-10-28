package compliance

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/elasticsearch"
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

var log = logf.Log.WithName("controller_compliance")

func init() {
	esusers.AddUser(elasticsearch.User{
		Username: render.ElasticsearchUserComplianceBenchmarker,
		Roles: []elasticsearch.Role{{
			Name: render.ElasticsearchUserComplianceBenchmarker,
			Definition: &elasticsearch.RoleDefinition{
				Cluster: []string{"monitor", "manage_index_templates"},
				Indices: []elasticsearch.RoleIndex{{
					Names:      []string{"tigera_secure_ee_benchmark_results.*"},
					Privileges: []string{"create_index", "write", "view_index_metadata", "read"},
				}},
			},
		}},
	})
	esusers.AddUser(
		elasticsearch.User{Username: render.ElasticsearchUserComplianceController,
			Roles: []elasticsearch.Role{{
				Name: render.ElasticsearchUserComplianceController,
				Definition: &elasticsearch.RoleDefinition{
					Cluster: []string{"monitor", "manage_index_templates"},
					Indices: []elasticsearch.RoleIndex{{
						Names:      []string{"tigera_secure_ee_compliance_reports.*"},
						Privileges: []string{"read"},
					}},
				},
			}},
		})
	esusers.AddUser(elasticsearch.User{
		Username: render.ElasticsearchUserComplianceReporter,
		Roles: []elasticsearch.Role{{
			Name: render.ElasticsearchUserComplianceReporter,
			Definition: &elasticsearch.RoleDefinition{
				Cluster: []string{"monitor", "manage_index_templates"},
				Indices: []elasticsearch.RoleIndex{
					{
						Names:      []string{"tigera_secure_ee_audit_*"},
						Privileges: []string{"read"},
					},
					{
						Names:      []string{"tigera_secure_ee_snapshots.*"},
						Privileges: []string{"read"},
					},
					{
						Names:      []string{"tigera_secure_ee_benchmark_results.*"},
						Privileges: []string{"read"},
					},
					{
						Names:      []string{"tigera_secure_ee_compliance_reports.*"},
						Privileges: []string{"create_index", "write", "view_index_metadata", "read"},
					},
				},
			},
		}},
	})
	esusers.AddUser(elasticsearch.User{
		Username: render.ElasticsearchUserComplianceSnapshotter,
		Roles: []elasticsearch.Role{{
			Name: render.ElasticsearchUserComplianceSnapshotter,
			Definition: &elasticsearch.RoleDefinition{
				Cluster: []string{"monitor", "manage_index_templates"},
				Indices: []elasticsearch.RoleIndex{{
					Names:      []string{"tigera_secure_ee_snapshots.*"},
					Privileges: []string{"create_index", "write", "view_index_metadata", "read"},
				}},
			},
		}},
	})
	esusers.AddUser(elasticsearch.User{
		Username: render.ElasticsearchUserComplianceServer,
		Roles: []elasticsearch.Role{{
			Name: render.ElasticsearchUserComplianceServer,
			Definition: &elasticsearch.RoleDefinition{
				Cluster: []string{"monitor", "manage_index_templates"},
				Indices: []elasticsearch.RoleIndex{{
					Names:      []string{"tigera_secure_ee_compliance_reports.*"},
					Privileges: []string{"read"},
				}},
			},
		}},
	})
}

// Add creates a new Compliance Controller and adds it to the Manager. The Manager will set fields on the Controller
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
	r := &ReconcileCompliance{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: provider,
		status:   status.New(mgr.GetClient(), "compliance"),
	}
	r.status.Run()
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("compliance-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Compliance
	err = c.Watch(&source.Kind{Type: &operatorv1.Compliance{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("compliance-controller failed to watch Network resource: %v", err)
	}

	if err = utils.AddAPIServerWatch(c); err != nil {
		return fmt.Errorf("compliance-controller failed to watch APIServer resource: %v", err)
	}

	for _, secretName := range []string{
		render.ElasticsearchPublicCertSecret, render.ElasticsearchUserComplianceBenchmarker,
		render.ElasticsearchUserComplianceController, render.ElasticsearchUserComplianceReporter,
		render.ElasticsearchUserComplianceSnapshotter, render.ElasticsearchUserComplianceServer} {
		if err = utils.AddSecretsWatch(c, secretName, render.OperatorNamespace()); err != nil {
			return fmt.Errorf("compliance-controller failed to watch the Secret resource: %v", err)
		}
	}

	return nil
}

// blank assignment to verify that ReconcileCompliance implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileCompliance{}

// ReconcileCompliance reconciles a Compliance object
type ReconcileCompliance struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	provider operatorv1.Provider
	status   *status.StatusManager
}

func GetCompliance(ctx context.Context, cli client.Client) (*operatorv1.Compliance, error) {
	instance := &operatorv1.Compliance{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// Reconcile reads that state of the cluster for a Compliance object and makes changes based on the state read
// and what is in the Compliance.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileCompliance) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Compliance")

	ctx := context.Background()

	// Fetch the Compliance instance
	instance, err := GetCompliance(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("Compliance config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying compliance", err.Error())
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded("Waiting for Tigera API server to be ready", "")
		return reconcile.Result{}, err
	}

	if err = utils.CheckLicenseKey(ctx, r.client); err != nil {
		r.status.SetDegraded("License not found", err.Error())
		return reconcile.Result{RequeueAfter: 10 * time.Second}, err
	}

	// Query for the installation object.
	network, err := installation.GetInstallation(context.Background(), r.client, r.provider)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		log.Error(err, "Failed to retrieve pull secrets")
		r.status.SetDegraded("Failed to retrieve pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	clusterName, err := utils.ClusterName(context.Background(), r.client)
	if err != nil {
		log.Error(err, "Failed to get the cluster name")
		r.status.SetDegraded("Failed to get the cluster name", err.Error())
		return reconcile.Result{}, err
	}

	esSecrets, err := utils.ElasticsearchSecrets(context.Background(), []string{
		render.ElasticsearchUserComplianceBenchmarker, render.ElasticsearchUserComplianceController,
		render.ElasticsearchUserComplianceReporter, render.ElasticsearchUserComplianceSnapshotter,
		render.ElasticsearchUserComplianceServer,
	}, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	reqLogger.V(3).Info("rendering components")
	openshift := r.provider == operatorv1.ProviderOpenShift
	// Render the desired objects from the CRD and create or update them.
	component := render.Compliance(
		esSecrets, network.Spec.Registry, clusterName, pullSecrets, openshift)
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
	instance.Status.State = operatorv1.ComplianceStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
