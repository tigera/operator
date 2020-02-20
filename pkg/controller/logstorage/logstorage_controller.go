// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"

	"k8s.io/apimachinery/pkg/types"

	apps "k8s.io/api/apps/v1"
	storagev1 "k8s.io/api/storage/v1"

	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	cmneckalpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/common/v1alpha1"
	esalpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/elasticsearch/v1alpha1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	kibanaalpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/kibana/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	defaultResolveConfPath             = "/etc/resolv.conf"
	defaultLocalDNS                    = "svc.cluster.local"
	tigeraElasticsearchUserSecretLabel = "tigera-elasticsearch-user"
	defaultElasticsearchShards         = 5
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
func newReconciler(cli client.Client, schema *runtime.Scheme, statusMgr status.StatusManager, resolvConfPath string, provider operatorv1.Provider) (*ReconcileLogStorage, error) {
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

	err = c.Watch(&source.Kind{
		Type: &storagev1.StorageClass{
			ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchStorageClass},
		},
	}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-controller failed to watch StorageClass resource: %v", err)
	}

	if err = c.Watch(&source.Kind{Type: &apps.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: render.ECKOperatorNamespace, Name: render.ECKOperatorName},
	}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch StatefulSet resource: %v", err)
	}

	if err = c.Watch(&source.Kind{Type: &esalpha1.Elasticsearch{
		ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.ElasticsearchName},
	}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Elasticsearch resource: %v", err)
	}

	if err = c.Watch(&source.Kind{Type: &kibanaalpha1.Kibana{
		ObjectMeta: metav1.ObjectMeta{Namespace: render.KibanaNamespace, Name: render.KibanaName},
	}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Kibana resource: %v", err)
	}

	// Watch all the elasticsearch user secrets in the operator namespace. In the future, we may want put this logic in
	// the utils folder where the other watch logic is.
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Meta.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.Meta.GetNamespace() == render.OperatorNamespace() && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.MetaNew.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.MetaNew.GetNamespace() == render.OperatorNamespace() && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Meta.GetLabels()[tigeraElasticsearchUserSecretLabel]
			return e.Meta.GetNamespace() == render.OperatorNamespace() && hasLabel
		},
	})
	if err != nil {
		return err
	}

	// Watch all the secrets created by this controller so we can regenerate any that are deleted
	for _, secretName := range []string{
		render.TigeraElasticsearchCertSecret, render.TigeraKibanaCertSecret,
		render.ECKWebhookSecretName} {
		if err = utils.AddSecretsWatch(c, secretName, render.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %v", err)
		}
	}

	if err = utils.AddConfigMapWatch(c, render.ElasticsearchConfigMapName, render.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %v", err)
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
	status   status.StatusManager
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

	installationCR, err := installation.GetInstallation(context.Background(), r.client, r.provider)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("An error occurred while querying Installation", err.Error())
		return reconcile.Result{}, err
	}

	// These checks ensure that we're in the correct state to continue to the render function without causing a panic
	if installationCR.Status.Variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	} else if ls == nil && installationCR.Spec.ClusterManagementType != operatorv1.ClusterManagementTypeManaged {
		err := fmt.Errorf("LogStorage must exist for '%s' cluster type", installationCR.Spec.ClusterManagementType)
		log.Error(err, err.Error())
		return reconcile.Result{}, nil
	} else if ls != nil && ls.DeletionTimestamp == nil && installationCR.Spec.ClusterManagementType == operatorv1.ClusterManagementTypeManaged {
		// Note that we check if the DeletionTimestamp is set as the render function is responsible for any cleanup needed
		// before the LogStorage CR can be deleted, and removing the finalizers from that CR
		err := fmt.Errorf("cluster type is '%s' but LogStorage CR still exists", operatorv1.ClusterManagementTypeManaged)
		log.Error(err, err.Error())
		r.status.SetDegraded("LogStorage validation failed", err.Error())
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installationCR, r.client)
	if err != nil {
		log.Error(err, "error retrieving pull secrets")
		r.status.SetDegraded("An error occurring while retrieving the pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	esService, err := r.getElasticsearchService(ctx)
	if err != nil {
		log.Error(err, "failed to retrieve Elasticsearch service")
		r.status.SetDegraded("Failed to retrieve the Elasticsearch service", err.Error())
		return reconcile.Result{}, err
	}

	var elasticsearchSecrets, kibanaSecrets, curatorSecrets []*corev1.Secret
	var clusterConfig *render.ElasticsearchClusterConfig
	createWebhookSecret := false

	if installationCR.Spec.ClusterManagementType != operatorv1.ClusterManagementTypeManaged {
		clusterConfig = render.NewElasticsearchClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), defaultElasticsearchShards)
		if err := r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchStorageClass}, &storagev1.StorageClass{}); err != nil {
			if errors.IsNotFound(err) {
				err := fmt.Errorf("couldn't find storage class %s, this must be provided", render.ElasticsearchStorageClass)
				log.Error(err, err.Error())
				r.status.SetDegraded("Failed to get storage class", err.Error())
				return reconcile.Result{}, nil
			}

			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to get storage class", err.Error())
			return reconcile.Result{}, nil
		}

		if elasticsearchSecrets, err = r.elasticsearchSecrets(ctx); err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to create elasticsearch secrets", err.Error())
			return reconcile.Result{}, err
		}

		if kibanaSecrets, err = r.kibanaSecrets(ctx); err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to create kibana secrets", err.Error())
			return reconcile.Result{}, err
		}

		// The ECK operator requires that we provide it with a secret so it can add certificate information in for its webhooks.
		// If it's created we don't want to overwrite it as we'll lose the certificate information the ECK operator relies on.
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.ECKWebhookSecretName, Namespace: render.ECKOperatorNamespace}, &corev1.Secret{}); err != nil {
			if errors.IsNotFound(err) {
				createWebhookSecret = true
			} else {
				log.Error(err, err.Error())
				r.status.SetDegraded("Failed to read Elasticsearch webhook secret", err.Error())
				return reconcile.Result{}, err
			}
		}

		curatorSecrets, err = utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchCuratorUserSecret}, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded("Failed to get curator credentials", err.Error())
			return reconcile.Result{}, err
		}
	}

	elasticsearch, err := r.getElasticsearch(ctx)
	if err != nil {
		log.Error(err, err.Error())
		r.status.SetDegraded("An error occurred trying to retrieve Elasticsearch", err.Error())
		return reconcile.Result{}, err
	}

	kibana, err := r.getKibana(ctx)
	if err != nil {
		log.Error(err, err.Error())
		r.status.SetDegraded("An error occurred trying to retrieve Kibana", err.Error())
		return reconcile.Result{}, err
	}

	// If this is a Managed cluster ls must be nil to get to this point (unless the DeletionTimestamp is set) so we must
	// create the ComponentHandler from the installationCR
	var hdler utils.ComponentHandler
	if ls != nil {
		hdler = utils.NewComponentHandler(log, r.client, r.scheme, ls)
	} else {
		hdler = utils.NewComponentHandler(log, r.client, r.scheme, installationCR)
	}

	component := render.LogStorage(
		ls,
		installationCR,
		elasticsearch,
		kibana,
		clusterConfig,
		elasticsearchSecrets,
		kibanaSecrets,
		createWebhookSecret,
		pullSecrets,
		r.provider,
		curatorSecrets,
		esService,
		r.localDNS,
	)

	if err := hdler.CreateOrUpdate(ctx, component, r.status); err != nil {
		log.Error(err, err.Error())
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	if installationCR.Spec.ClusterManagementType != operatorv1.ClusterManagementTypeManaged {
		if elasticsearch == nil || elasticsearch.Status.Phase != esalpha1.ElasticsearchOperationalPhase {
			r.status.SetDegraded("Waiting for Elasticsearch cluster to be operational", "")
			return reconcile.Result{}, nil
		}

		if kibana == nil || kibana.Status.AssociationStatus != cmneckalpha1.AssociationEstablished {
			r.status.SetDegraded("Waiting for Kibana cluster to be operational", "")
			return reconcile.Result{}, nil
		}

		if len(curatorSecrets) == 0 {
			log.Info("waiting for curator secrets to become available")
			r.status.SetDegraded("Waiting for curator secrets to become available", "")
			return reconcile.Result{}, nil
		}
	}

	r.status.ClearDegraded()

	if ls != nil {
		ls.Status.State = operatorv1.LogStorageStatusReady
		if err := r.client.Status().Update(ctx, ls); err != nil {
			reqLogger.Error(err, fmt.Sprintf("Error updating the log-storage status %s", operatorv1.LogStorageStatusReady))
			r.status.SetDegraded(fmt.Sprintf("Error updating the log-storage status %s", operatorv1.LogStorageStatusReady), err.Error())
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileLogStorage) elasticsearchSecrets(ctx context.Context) ([]*corev1.Secret, error) {
	var secrets []*corev1.Secret
	secret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}, secret); err != nil {
		if errors.IsNotFound(err) {
			secret, err = render.CreateOperatorTLSSecret(nil,
				render.TigeraElasticsearchCertSecret, "tls.key", "tls.crt",
				render.DefaultCertificateDuration, nil, render.ElasticsearchHTTPURL,
			)
		} else {
			return nil, err
		}
	}
	secrets = append(secrets, secret, render.CopySecrets(render.ElasticsearchNamespace, secret)[0])

	secret = &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}, secret); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		log.Info("Elasticsearch public cert secret not found yet")
	} else {
		secrets = append(secrets, render.CopySecrets(render.OperatorNamespace(), secret)...)
	}

	return secrets, nil
}

func (r *ReconcileLogStorage) kibanaSecrets(ctx context.Context) ([]*corev1.Secret, error) {
	var secrets []*corev1.Secret
	secret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}, secret); err != nil {
		if errors.IsNotFound(err) {
			secret, err = render.CreateOperatorTLSSecret(nil,
				render.TigeraKibanaCertSecret, "tls.key", "tls.crt",
				render.DefaultCertificateDuration, nil, render.KibanaHTTPURL,
			)
		} else {
			return nil, err
		}
	}
	secrets = append(secrets, secret, render.CopySecrets(render.KibanaNamespace, secret)[0])

	secret = &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}, secret); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		log.Info("Kibana public cert secret not found yet")
	} else {
		secrets = append(secrets, render.CopySecrets(render.OperatorNamespace(), secret)...)
	}

	return secrets, nil
}

func (r *ReconcileLogStorage) getElasticsearch(ctx context.Context) (*esalpha1.Elasticsearch, error) {
	es := esalpha1.Elasticsearch{}
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

func (r *ReconcileLogStorage) getKibana(ctx context.Context) (*kibanaalpha1.Kibana, error) {
	kb := kibanaalpha1.Kibana{}
	err := r.client.Get(ctx, client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}, &kb)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &kb, nil
}
