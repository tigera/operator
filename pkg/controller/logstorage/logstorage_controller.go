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

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
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
)

var log = logf.Log.WithName("controller_logstorage")

const (
	defaultEckOperatorMemorySetting  = "512Mi"
	DefaultElasticsearchStorageClass = "tigera-elasticsearch"
)

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	r, err := newReconciler(mgr.GetClient(), mgr.GetScheme(), status.New(mgr.GetClient(), "log-storage", opts.KubernetesVersion), opts, utils.NewElasticClient)
	if err != nil {
		return err
	}

	return add(mgr, r)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(cli client.Client, schema *runtime.Scheme, statusMgr status.StatusManager, opts options.AddOptions, esCliCreator utils.ElasticsearchClientCreator) (*ReconcileLogStorage, error) {
	c := &ReconcileLogStorage{
		client:        cli,
		scheme:        schema,
		status:        statusMgr,
		provider:      opts.DetectedProvider,
		esCliCreator:  esCliCreator,
		clusterDomain: opts.ClusterDomain,
	}

	c.status.Run(opts.ShutdownContext)
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
		render.TigeraElasticsearchCertSecret, render.TigeraKibanaCertSecret,
		render.OIDCSecretName, render.DexObjectName} {
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

	var esAdminUserSecret *corev1.Secret
	var clusterConfig *relasticsearch.ClusterConfig
	var curatorSecrets []*corev1.Secret
	var esLicenseType render.ElasticsearchLicenseType

	if managementClusterConnection == nil {
		var flowShards = logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
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

	result, proceed, err := r.createLogStorage(
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
	)
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
		)
		if err != nil || !proceed {
			return result, err
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

// getElasticsearchCertificateSecrets retrieves Elasticsearch certificate secrets needed for Elasticsearch to run or for
// ES gateway to communicate with Elasticsearch. The order of the secrets returned are:
// 1) The certificate secret needed for Elasticsearch (in the Elasticsearch namespace). If the user didn't create this it is
//    created.
// 2) The certificate mounted by ES gateway to connect to Elasticsearch.
func (r *ReconcileLogStorage) getElasticsearchCertificateSecrets(ctx context.Context, instl *operatorv1.InstallationSpec) (*corev1.Secret, *corev1.Secret, error) {
	var esKeyCert, certSecret *corev1.Secret
	svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)

	// Get the secret - might be nil
	esKeyCert, err := utils.GetSecret(ctx, r.client, render.TigeraElasticsearchInternalCertSecret, render.ElasticsearchNamespace)
	if err != nil {
		return nil, nil, err
	}

	// Ensure that cert is valid.
	esKeyCert, err = utils.EnsureCertificateSecret(render.TigeraElasticsearchInternalCertSecret, esKeyCert, corev1.TLSPrivateKeyKey, corev1.TLSCertKey, rmeta.DefaultCertificateDuration, svcDNSNames...)
	if err != nil {
		return nil, nil, err
	}

	// Override the Operator namespace set by utils.EnsureCertificateSecret.
	esKeyCert.Namespace = render.ElasticsearchNamespace

	// If Certificate management is enabled, we only want to trust the CA cert and let the init container handle private key generation.
	if instl.CertificateManagement != nil {
		esKeyCert.Data[corev1.TLSCertKey] = instl.CertificateManagement.CACert
		certSecret = render.CreateCertificateSecret(instl.CertificateManagement.CACert, relasticsearch.InternalCertSecret, render.ElasticsearchNamespace)
	} else {
		// Get the internal public cert secret - might be nil.
		certSecret, err = utils.GetSecret(ctx, r.client, relasticsearch.InternalCertSecret, render.ElasticsearchNamespace)
		if err != nil {
			return nil, nil, err
		}

		if certSecret != nil {
			// When the provided certificate secret (secret) is managed by the operator we need to check if the secret that
			// Elasticsearch creates from that given secret (internalSecret) has the expected DNS name. If it doesn't, delete the
			// public secret so it can get recreated.
			err = utils.SecretHasExpectedDNSNames(certSecret, corev1.TLSCertKey, svcDNSNames)
			if err == utils.ErrInvalidCertDNSNames {
				if err := logstoragecommon.DeleteInvalidECKManagedPublicCertSecret(ctx, certSecret, r.client, log); err != nil {
					return nil, nil, err
				}
			}
		} else {
			// TODO: Understand why this is needed. This is creating a secret that it is expected will be created
			// by the ECK operator but the understanding is that this is an optimization. Ideally this can be
			// removed and we can count on the ECK operator to do what is expected.
			certSecret = render.CreateCertificateSecret(esKeyCert.Data[corev1.TLSCertKey], relasticsearch.InternalCertSecret, render.ElasticsearchNamespace)
		}
	}

	return esKeyCert, certSecret, err
}

func (r *ReconcileLogStorage) kibanaInternalSecrets(ctx context.Context, instl *operatorv1.InstallationSpec) ([]*corev1.Secret, error) {

	var secrets []*corev1.Secret
	svcDNSNames := dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, r.clusterDomain)

	// Get the secret - might be nil
	secret, err := utils.GetSecret(ctx, r.client, render.TigeraKibanaCertSecret, common.OperatorNamespace())
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
			render.CreateCertificateSecret(instl.CertificateManagement.CACert, render.KibanaInternalCertSecret, common.OperatorNamespace()),
		}, nil
	}

	secrets = append(secrets, secret, rsecret.CopyToNamespace(render.KibanaNamespace, secret)[0])

	// Get the pub secret - might be nil
	internalSecret, err := utils.GetSecret(ctx, r.client, render.KibanaInternalCertSecret, render.KibanaNamespace)
	if err != nil {
		return nil, err
	}

	if internalSecret == nil {
		log.Info(fmt.Sprintf("Internal cert secret %q not found yet", render.KibanaInternalCertSecret))
		return secrets, nil
	}

	issuer, err := utils.GetCertificateIssuer(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, err
	}

	if utils.IsOperatorIssued(issuer) {
		err = utils.SecretHasExpectedDNSNames(internalSecret, corev1.TLSCertKey, svcDNSNames)
		if err == utils.ErrInvalidCertDNSNames {
			if err := logstoragecommon.DeleteInvalidECKManagedPublicCertSecret(ctx, internalSecret, r.client, log); err != nil {
				return nil, err
			}
		}
	}
	// If the cert was not deleted, copy the valid cert to operator namespace.
	secrets = append(secrets, rsecret.CopyToNamespace(common.OperatorNamespace(), internalSecret)...)

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
