// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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

package elastic

import (
	"context"
	"fmt"
	"net/url"
	"time"

	cmnv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_logstorage_elastic")

// ElasticSubController is a sub-controller of the main LogStorage controller
// responsible for managing the Elasticsearch service used by Calico.
type ElasticSubController struct {
	client         client.Client
	scheme         *runtime.Scheme
	status         status.StatusManager
	provider       operatorv1.Provider
	esCliCreator   utils.ElasticsearchClientCreator
	clusterDomain  string
	tierWatchReady *utils.ReadyFlag
	usePSP         bool
	multiTenant    bool
}

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// Create the reconciler
	r := &ElasticSubController{
		client:         mgr.GetClient(),
		scheme:         mgr.GetScheme(),
		esCliCreator:   utils.NewElasticClient,
		tierWatchReady: &utils.ReadyFlag{},
		status:         status.New(mgr.GetClient(), "log-storage-elastic", opts.KubernetesVersion),
		usePSP:         opts.UsePSP,
		clusterDomain:  opts.ClusterDomain,
		provider:       opts.DetectedProvider,
		multiTenant:    opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-elastic-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("log-storage-controller failed to establish a connection to k8s: %w", err)
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Network resource: %w", err)
	}
	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ImageSet: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, "log-storage-elastic"); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Authentication resource: %w", err)
	}

	// Start goroutines to establish watches against projectcalico.org/v3 resources.
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, r.tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, []types.NamespacedName{
		{Name: render.ElasticsearchPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: render.EsCuratorPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: render.KibanaPolicyName, Namespace: render.KibanaNamespace},
		{Name: render.ECKOperatorPolicyName, Namespace: render.ECKOperatorNamespace},
		{Name: render.ElasticsearchInternalPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.KibanaNamespace},
		{Name: esgateway.PolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: esmetrics.ElasticsearchMetricsPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: kubecontrollers.EsKubeControllerNetworkPolicyName, Namespace: common.CalicoNamespace},
		{Name: linseed.PolicyName, Namespace: render.ElasticsearchNamespace},
	})

	// Watch for changes in storage classes, as new storage classes may be made available for LogStorage.
	err = c.Watch(&source.Kind{Type: &storagev1.StorageClass{}}, &handler.EnqueueRequestForObject{})
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
	if err = utils.AddSecretsWatch(c, render.TigeraElasticsearchInternalCertSecret, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}
	if err = utils.AddConfigMapWatch(c, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
	}

	for _, name := range []string{
		render.OIDCUsersConfigMapName,
		render.OIDCUsersEsSecreteName,
		render.ElasticsearchAdminUserSecret,
	} {
		if err = utils.AddConfigMapWatch(c, name, render.ElasticsearchNamespace); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
		}
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
		render.TigeraElasticsearchGatewaySecret, render.TigeraKibanaCertSecret,
		render.OIDCSecretName, render.DexObjectName, esmetrics.ElasticsearchMetricsServerTLSSecret,
		render.TigeraLinseedSecret,
	} {
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

	if err = utils.AddSecretsWatch(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, render.ElasticsearchAdminUserSecret, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, render.ElasticsearchCuratorUserSecret, common.OperatorNamespace()); err != nil {
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

	if err := utils.AddServiceWatch(c, render.LinseedServiceName, render.ElasticsearchNamespace); err != nil {
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

func (r *ElasticSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - Elasticsearch")

	// Get LogStorage resource.
	ls := &operatorv1.LogStorage{}
	key := utils.DefaultTSEEInstanceKey
	err := r.client.Get(ctx, key, ls)
	if err != nil {
		// Not finding the LogStorage CR is not an error, as a Managed cluster will not have this CR available but
		// there are still "LogStorage" related items that need to be set up
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}
		ls = nil
		r.status.OnCRNotFound()
	}

	// We found the LogStorage instance.
	r.status.OnCRFound()

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if ls.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Get Installation resource.
	variant, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created", err, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, err
	}

	// These checks ensure that we're in the correct state to continue to the render function without causing a panic
	if variant != operatorv1.TigeraSecureEnterprise {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for network to be %s", operatorv1.TigeraSecureEnterprise), nil, reqLogger)
		return reconcile.Result{}, nil
	} else if ls == nil && managementClusterConnection == nil {
		reqLogger.Info("LogStorage must exist for management and standalone clusters that require storage.")
		return reconcile.Result{}, nil
	} else if ls != nil && ls.DeletionTimestamp == nil && managementClusterConnection != nil {
		// Note that we check if the DeletionTimestamp is set as the render function is responsible for any cleanup needed
		// before the LogStorage CR can be deleted, and removing the finalizers from that CR
		r.status.SetDegraded(operatorv1.ResourceValidationError, "LogStorage validation failed - cluster type is managed but LogStorage CR still exists", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(install, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving the pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// TODO: Is this ever going to be used in multi-tenant?
	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get the keypairs we need for rendering components. These are created separately by the ES secrets controller.
	cm, err := certificatemanager.Create(r.client, install, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	elasticKeyPair, err := cm.GetKeyPair(r.client, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Elasticsearch secrets", err, log)
		return reconcile.Result{}, err
	}
	kibanaKeyPair, err := cm.GetKeyPair(r.client, render.TigeraKibanaCertSecret, common.OperatorNamespace())
	if err != nil {
		log.Error(err, err.Error())
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Kibana secrets", err, log)
		return reconcile.Result{}, err
	}

	kibanaEnabled := !operatorv1.IsFIPSModeEnabled(install.FIPSMode) && !r.multiTenant

	// Wait for dependencies to exist.
	if elasticKeyPair == nil || kibanaEnabled && kibanaKeyPair == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for elastic / kibana secrets to be available", err, log)
		return reconcile.Result{}, nil
	}

	// Create a trusted bundle to pass to the render pacakge. The actual contents of this bundle don't matter - the ConfigMap
	// itself will be managed by the Secret controller. But, we need an interface to use as an argument to render in order
	// to configure volume mounts properly.
	trustedBundle := certificatemanagement.CreateTrustedBundle(elasticKeyPair, kibanaKeyPair)

	// Define variables to be filled in below, conditional on cluster type.
	var esLicenseType render.ElasticsearchLicenseType
	var clusterConfig *relasticsearch.ClusterConfig
	var applyTrial bool
	var keyStoreSecret *corev1.Secret
	var curatorSecrets []*corev1.Secret
	var esAdminUserSecret *corev1.Secret

	if managementClusterConnection == nil {
		flowShards := logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
		clusterConfig = relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)

		// Check if there is a StorageClass available to run Elasticsearch on.
		if err = r.client.Get(ctx, client.ObjectKey{Name: ls.Spec.StorageClassName}, &storagev1.StorageClass{}); err != nil {
			if errors.IsNotFound(err) {
				err := fmt.Errorf("couldn't find storage class %s, this must be provided", ls.Spec.StorageClassName)
				r.status.SetDegraded(operatorv1.ResourceNotFound, "Failed to get storage class", err, reqLogger)
				return reconcile.Result{}, nil
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get storage class", err, reqLogger)
			return reconcile.Result{}, err
		}

		if operatorv1.IsFIPSModeEnabled(install.FIPSMode) {
			applyTrial, err = r.applyElasticTrialSecret(ctx, install)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get eck trial license", err, reqLogger)
				return reconcile.Result{}, err
			}

			keyStoreSecret = &corev1.Secret{}
			if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchKeystoreSecret, Namespace: render.ElasticsearchNamespace}, keyStoreSecret); err != nil {
				if errors.IsNotFound(err) {
					// We need to render a new one.
					keyStoreSecret = render.CreateElasticsearchKeystoreSecret()
				} else {
					log.Error(err, "failed to read the Elasticsearch keystore secret")
					r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read the Elasticsearch keystore secret", err, reqLogger)
					return reconcile.Result{}, err
				}
			}
		}

		// Curator secrets are created by es-kube-controllers
		curatorSecrets, err = utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchCuratorUserSecret}, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get curator credentials", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Get the admin user secret to copy to the operator namespace.
		esAdminUserSecret, err = utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
		if err != nil {
			reqLogger.Error(err, "failed to get Elasticsearch admin user secret")
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch admin user secret", err, reqLogger)
			return reconcile.Result{}, err
		}
		if esAdminUserSecret != nil {
			esAdminUserSecret = rsecret.CopyToNamespace(common.OperatorNamespace(), esAdminUserSecret)[0]
		}

		esLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, reqLogger)
		if err != nil {
			// If ECKLicenseConfigMapName is not found, it means ECK operator is not running yet, log the information and proceed
			if errors.IsNotFound(err) {
				reqLogger.Info("ConfigMap not found yet", "name", render.ECKLicenseConfigMapName)
			} else {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get elastic license", err, reqLogger)
				return reconcile.Result{}, err
			}
		}
	}

	elasticsearch, err := utils.GetElasticsearch(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
		return reconcile.Result{}, err
	}

	var kibana *kbv1.Kibana
	if kibanaEnabled {
		kibana, err = r.getKibana(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Kibana", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// If Authentication spec present, we use it to configure dex as an authentication proxy.
	if authentication != nil && authentication.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready - authentication status: %s", authentication.Status.State), nil, reqLogger)
		return reconcile.Result{}, nil
	}

	var baseURL string
	if authentication != nil && authentication.Spec.ManagerDomain != "" {
		baseURL = authentication.Spec.ManagerDomain
		if u, err := url.Parse(baseURL); err == nil {
			if u.Scheme == "" {
				baseURL = fmt.Sprintf("https://%s", baseURL)
			}
		} else {
			reqLogger.Error(err, "Parsing Authentication ManagerDomain failed so baseUrl is not set")
		}
	}

	var unusedTLSSecret *corev1.Secret
	if install.CertificateManagement != nil {
		// Eck requires us to provide a TLS secret for Kibana and Elasticsearch. It will also inspect that it has a
		// certificate and private key. However, when certificate management is enabled, we do not want to use a
		// private key stored in a secret. For this reason, we mount a dummy that the actual Elasticsearch and Kibana
		// pods are never using.
		unusedTLSSecret, err = utils.GetSecret(ctx, r.client, relasticsearch.UnusedCertSecret, common.OperatorNamespace())
		if unusedTLSSecret == nil {
			unusedTLSSecret, err = certificatemanagement.CreateSelfSignedSecret(relasticsearch.UnusedCertSecret, common.OperatorNamespace(), relasticsearch.UnusedCertSecret, []string{})
			unusedTLSSecret.Data[corev1.TLSCertKey] = install.CertificateManagement.CACert
		}
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve secret %s/%s", common.OperatorNamespace(), relasticsearch.UnusedCertSecret), err, reqLogger)
			return reconcile.Result{}, nil
		}
	}

	esService, err := r.getElasticsearchService(ctx)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve the Elasticsearch service", err, reqLogger)
		return reconcile.Result{}, err
	}

	var kbService *corev1.Service
	if kibanaEnabled {
		// For now, Kibana is only supported in single tenant configurations.
		kbService, err = r.getKibanaService(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve the Kibana service", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Query credentials to be installed into ES. These will be added to the Elasticsearch instance.
	// These credentials are created in other controllers as needed.

	// If this is a Managed cluster ls must be nil to get to this point (unless the DeletionTimestamp is set) so we must
	// create the ComponentHandler from the managementClusterConnection.
	var hdler utils.ComponentHandler
	if ls != nil {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, managementClusterConnection)
	}

	logStorageCfg := &render.ElasticsearchConfiguration{
		LogStorage:                  ls,
		Installation:                install,
		ManagementCluster:           managementCluster,
		ManagementClusterConnection: managementClusterConnection,
		Elasticsearch:               elasticsearch,
		Kibana:                      kibana,
		ClusterConfig:               clusterConfig,
		ElasticsearchUserSecret:     esAdminUserSecret,
		ElasticsearchKeyPair:        elasticKeyPair,
		KibanaKeyPair:               kibanaKeyPair,
		PullSecrets:                 pullSecrets,
		Provider:                    r.provider,
		CuratorSecrets:              curatorSecrets,
		ESService:                   esService,
		KbService:                   kbService,
		ClusterDomain:               r.clusterDomain,
		BaseURL:                     baseURL,
		ElasticLicenseType:          esLicenseType,
		TrustedBundle:               trustedBundle,
		UnusedTLSSecret:             unusedTLSSecret,
		UsePSP:                      r.usePSP,
		ApplyTrial:                  applyTrial,
		KeyStoreSecret:              keyStoreSecret,
		KibanaEnabled:               kibanaEnabled,
	}

	component := render.LogStorage(logStorageCfg)
	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	if managementClusterConnection == nil {
		if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", nil, reqLogger)
			return reconcile.Result{}, nil
		}

		if kibanaEnabled && (kibana == nil || kibana.Status.AssociationStatus != cmnv1.AssociationEstablished) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Kibana cluster to be operational", nil, reqLogger)
			return reconcile.Result{}, nil
		}

		// TODO: Need to handle this gracefully, since these will only succeed after ES is properly running.
		// In multi-tenant mode, and probably single-tenant as well, this should be handled by someone other than the operator.
		// Either out of band, or by Linseed.
		err := r.applyILMPolicies(ls, reqLogger, ctx)
		if err != nil {
			return reconcile.Result{}, err
		}

		err = r.validateLogStorage(curatorSecrets, esLicenseType, reqLogger, ctx)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	return reconcile.Result{}, nil
}

func (r *ElasticSubController) validateLogStorage(curatorSecrets []*corev1.Secret, esLicenseType render.ElasticsearchLicenseType, reqLogger logr.Logger, ctx context.Context) error {
	var err error

	if len(curatorSecrets) == 0 {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for curator secrets to become available", nil, reqLogger)
		return nil
	}

	// kube-controller creates the ConfigMap and Secret needed for SSO into Kibana.
	// If elastisearch uses basic license, degrade logstorage if the ConfigMap and Secret
	// needed for logging user into Kibana is not available.
	if esLicenseType == render.ElasticsearchLicenseTypeBasic {
		if err = r.checkOIDCUsersEsResource(ctx); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get oidc user Secret and ConfigMap", err, reqLogger)
			return err
		}
	}
	return nil
}

func (r *ElasticSubController) checkOIDCUsersEsResource(ctx context.Context) error {
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersConfigMapName, Namespace: render.ElasticsearchNamespace}, &corev1.ConfigMap{}); err != nil {
		return err
	}

	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersEsSecreteName, Namespace: render.ElasticsearchNamespace}, &corev1.Secret{}); err != nil {
		return err
	}
	return nil
}

// TODO: This shouldn't be done in the operator. Linseed should probably handle this for single-tenant setups, and multi-tenant should
// either be handled by Linseed or out-of-band.
func (r *ElasticSubController) applyILMPolicies(ls *operatorv1.LogStorage, reqLogger logr.Logger, ctx context.Context) error {
	// ES should be in ready phase when execution reaches here, apply ILM polices
	esClient, err := r.esCliCreator(r.client, ctx, relasticsearch.ElasticEndpoint())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to connect to Elasticsearch - failed to create the Elasticsearch client", err, reqLogger)
		return err
	}

	if err = esClient.SetILMPolicies(ctx, ls); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to create or update Elasticsearch lifecycle policies", err, reqLogger)
		return err
	}
	return nil
}

func (r *ElasticSubController) getElasticsearchService(ctx context.Context) (*corev1.Service, error) {
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

func (r *ElasticSubController) getKibana(ctx context.Context) (*kbv1.Kibana, error) {
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

func (r *ElasticSubController) getKibanaService(ctx context.Context) (*corev1.Service, error) {
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

// applyElasticTrialSecret returns true if we want to apply a new trial license.
// Overwriting an existing trial license will invalidate the old trial, and revert the cluster back to basic. When a user
// installs a valid Elastic license, the trial will be ignored.
func (r *ElasticSubController) applyElasticTrialSecret(ctx context.Context, installation *operatorv1.InstallationSpec) (bool, error) {
	if !operatorv1.IsFIPSModeEnabled(installation.FIPSMode) {
		return false, nil
	}
	// FIPS mode is a licensed feature for Elasticsearch.
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ECKEnterpriseTrial, Namespace: render.ECKOperatorNamespace}, &corev1.Secret{}); err != nil {
		if errors.IsNotFound(err) {
			return true, nil
		} else {
			return false, err
		}
	}
	return false, nil
}
