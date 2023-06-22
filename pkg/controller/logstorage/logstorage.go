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

package logstorage

import (
	"context"
	"fmt"
	"net/url"

	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	"github.com/tigera/operator/pkg/common"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	apps "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	cmnv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

// createLogStorage Is called by Reconcile() in the Logstorage controller to render its components
//
// It returns 4 values:
// A reconcile.Result to be returned by Reconcile() if the 'proceed' bool is false or if there is an error,
// a 'proceed' bool indicating if the Reconcile function should proceed with the reconcile process,
// a 'finalizerCleanup' bool indicating if it's safe to remove the LogStorage finalizer (only on deletion and after
// kibana and elasticsearch components were successfully removed), and lastly,
// an error if there was any or nil otherwise
func (r *ReconcileLogStorage) createLogStorage(
	ls *operatorv1.LogStorage,
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	clusterConfig *relasticsearch.ClusterConfig,
	managementCluster *operatorv1.ManagementCluster,
	managementClusterConnection *operatorv1.ManagementClusterConnection,
	esAdminUserSecret *corev1.Secret,
	curatorSecrets []*corev1.Secret,
	esLicenseType render.ElasticsearchLicenseType,
	esService *corev1.Service,
	kbService *corev1.Service,
	pullSecrets []*corev1.Secret,
	authentication *operatorv1.Authentication,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	ctx context.Context,
	applyTrial bool,
	keyStoreSecret *corev1.Secret,
	elasticKeyPair certificatemanagement.KeyPairInterface,
	kibanaKeyPair certificatemanagement.KeyPairInterface,
	trustedBundle certificatemanagement.TrustedBundle,
) (reconcile.Result, bool, bool, error) {
	var err error
	finalizerCleanup := false

	if managementClusterConnection == nil {
		// Check if there is a StorageClass available to run Elasticsearch on.
		if err = r.client.Get(ctx, client.ObjectKey{Name: ls.Spec.StorageClassName}, &storagev1.StorageClass{}); err != nil {
			if errors.IsNotFound(err) {
				err := fmt.Errorf("couldn't find storage class %s, this must be provided", ls.Spec.StorageClassName)
				r.status.SetDegraded(operatorv1.ResourceNotFound, "Failed to get storage class", err, reqLogger)
				return reconcile.Result{}, false, finalizerCleanup, nil
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get storage class", err, reqLogger)
			return reconcile.Result{}, false, finalizerCleanup, err
		}
	}

	elasticsearch, err := utils.GetElasticsearch(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
		return reconcile.Result{}, false, finalizerCleanup, err
	}

	var kibana *kbv1.Kibana
	if !operatorv1.IsFIPSModeEnabled(install.FIPSMode) {
		kibana, err = r.getKibana(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Kibana", err, reqLogger)
			return reconcile.Result{}, false, finalizerCleanup, err
		}
	}

	// If Authentication spec present, we use it to configure dex as an authentication proxy.
	if authentication != nil && authentication.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready - authentication status: %s", authentication.Status.State), nil, reqLogger)
		return reconcile.Result{}, false, finalizerCleanup, nil
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
			return reconcile.Result{}, false, finalizerCleanup, nil
		}
	}

	var components []render.Component

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
	}

	logStorageComponent := render.LogStorage(logStorageCfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, logStorageComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, false, finalizerCleanup, err
	}

	components = append(components, logStorageComponent)
	if managementClusterConnection == nil && !operatorv1.IsFIPSModeEnabled(install.FIPSMode) {
		// Render the key pair and trusted bundle into the Kibana namespace, which should be created by the log storage component above.
		components = append(components,
			rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
				Namespace:       render.KibanaNamespace,
				ServiceAccounts: []string{render.KibanaObjectName},
				KeyPairOptions: []rcertificatemanagement.KeyPairOption{
					// We do not want to delete the secret from the tigera-elasticsearch when CertificateManagement is
					// enabled. Instead, it will be replaced with a TLS secret that serves merely to pass ECK's validation
					// checks.
					rcertificatemanagement.NewKeyPairOption(kibanaKeyPair, true, kibanaKeyPair != nil && !kibanaKeyPair.UseCertificateManagement()),
				},
				TrustedBundle: trustedBundle,
			}),
		)
	}

	for _, component := range components {
		if err := hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, false, finalizerCleanup, err
		}
	}

	if ls != nil && ls.DeletionTimestamp != nil && elasticsearch == nil && kibana == nil {
		finalizerCleanup = true
	}

	if managementClusterConnection == nil {
		if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", nil, reqLogger)
			return reconcile.Result{}, false, finalizerCleanup, nil
		}

		if !operatorv1.IsFIPSModeEnabled(install.FIPSMode) && (kibana == nil || kibana.Status.AssociationStatus != cmnv1.AssociationEstablished) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Kibana cluster to be operational", nil, reqLogger)
			return reconcile.Result{}, false, finalizerCleanup, nil
		}
	}

	return reconcile.Result{}, true, finalizerCleanup, nil
}

func (r *ReconcileLogStorage) validateLogStorage(curatorSecrets []*corev1.Secret, esLicenseType render.ElasticsearchLicenseType, reqLogger logr.Logger, ctx context.Context) (reconcile.Result, bool, error) {
	var err error

	if len(curatorSecrets) == 0 {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for curator secrets to become available", nil, reqLogger)
		return reconcile.Result{}, false, nil
	}

	// kube-controller creates the ConfigMap and Secret needed for SSO into Kibana.
	// If elastisearch uses basic license, degrade logstorage if the ConfigMap and Secret
	// needed for logging user into Kibana is not available.
	if esLicenseType == render.ElasticsearchLicenseTypeBasic {
		if err = r.checkOIDCUsersEsResource(ctx); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get oidc user Secret and ConfigMap", err, reqLogger)
			return reconcile.Result{}, false, err
		}
	}
	return reconcile.Result{}, true, nil
}

func (r *ReconcileLogStorage) applyILMPolicies(ls *operatorv1.LogStorage, reqLogger logr.Logger, ctx context.Context) (reconcile.Result, bool, error) {
	// ES should be in ready phase when execution reaches here, apply ILM polices
	esClient, err := r.esCliCreator(r.client, ctx, relasticsearch.HTTPSEndpoint(rmeta.OSTypeLinux, r.clusterDomain))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to connect to Elasticsearch - failed to create the Elasticsearch client", err, reqLogger)
		return reconcile.Result{}, false, err
	}

	if err = esClient.SetILMPolicies(ctx, ls); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to create or update Elasticsearch lifecycle policies", err, reqLogger)
		return reconcile.Result{}, false, err
	}
	return reconcile.Result{}, true, nil
}

func addLogStorageWatches(c controller.Controller) error {
	// Watch for changes in storage classes, as new storage classes may be made available for LogStorage.
	err := c.Watch(&source.Kind{
		Type: &storagev1.StorageClass{},
	}, &handler.EnqueueRequestForObject{})
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

	if err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
	}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch Authentication resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, render.TigeraElasticsearchInternalCertSecret, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the Secret resource: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
	}

	err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-controller failed to watch primary resource: %w", err)
	}

	for _, name := range []string{
		render.OIDCUsersConfigMapName, render.OIDCUsersEsSecreteName,
		render.ElasticsearchAdminUserSecret,
	} {
		if err = utils.AddConfigMapWatch(c, name, render.ElasticsearchNamespace); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
		}
	}

	return nil
}
