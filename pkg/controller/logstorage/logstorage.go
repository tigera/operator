package logstorage

import (
	"context"
	"fmt"

	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	apps "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
)

func (r *ReconcileLogStorage) renderLogStorage(
	ls *operatorv1.LogStorage,
	install *operatorv1.InstallationSpec,
	variant operatorv1.ProductVariant,
	clusterConfig *relasticsearch.ClusterConfig,
	managementCluster *operatorv1.ManagementCluster,
	managementClusterConnection *operatorv1.ManagementClusterConnection,
	esService *corev1.Service,
	kbService *corev1.Service,
	pullSecrets []*corev1.Secret,
	hdler utils.ComponentHandler,
	reqLogger logr.Logger,
	ctx context.Context,
) error {
	var esInternalCertSecret, esAdminUserSecret, esCertSecret *corev1.Secret
	var kibanaSecrets, curatorSecrets []*corev1.Secret
	var esLicenseType render.ElasticsearchLicenseType

	if managementClusterConnection == nil {
		// Get the admin user secret to copy to the operator namespace.
		esAdminUserSecret, err := utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
		if err != nil {
			reqLogger.Error(err, err.Error())
			return err
		}
		if esAdminUserSecret != nil {
			esAdminUserSecret = rsecret.CopyToNamespace(rmeta.OperatorNamespace(), esAdminUserSecret)[0]
		}
		r.esAdminUserSecret = esAdminUserSecret

		// Check if there is a StorageClass available to run Elasticsearch on.
		if err := r.client.Get(ctx, client.ObjectKey{Name: ls.Spec.StorageClassName}, &storagev1.StorageClass{}); err != nil {
			if errors.IsNotFound(err) {
				err := fmt.Errorf("couldn't find storage class %s, this must be provided", ls.Spec.StorageClassName)
				reqLogger.Error(err, err.Error())
				r.status.SetDegraded("Failed to get storage class", err.Error())
				return err
			}
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Failed to get storage class", err.Error())
			return err
		}

		if esCertSecret, esInternalCertSecret, err = r.getElasticsearchCertificateSecrets(ctx, install); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Failed to create Elasticsearch secrets", err.Error())
			return err
		}

		if kibanaSecrets, err = r.kibanaInternalSecrets(ctx, install); err != nil {
			reqLogger.Error(err, err.Error())
			r.status.SetDegraded("Failed to create kibana secrets", err.Error())
			return err
		}

		curatorSecrets, err = utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchCuratorUserSecret}, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded("Failed to get curator credentials", err.Error())
			return err
		}
		r.curatorSecrets = curatorSecrets

		esLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, reqLogger)
		if err != nil {
			// If ECKLicenseConfigMapName is not found, it means ECK operator is not running yet, log the information and proceed
			if errors.IsNotFound(err) {
				reqLogger.Info("ConfigMap not found yet", "name", render.ECKLicenseConfigMapName)
			} else {
				r.status.SetDegraded("Failed to get elastic license", err.Error())
				return err
			}
		}
		r.esLicenseType = esLicenseType
	}

	elasticsearch, err := r.getElasticsearch(ctx)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("An error occurred trying to retrieve Elasticsearch", err.Error())
		return err
	}

	kibana, err := r.getKibana(ctx)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("An error occurred trying to retrieve Kibana", err.Error())
		return err
	}

	// Fetch the Authentication spec. If present, we use it to configure dex as an authentication proxy.
	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded("Error while fetching Authentication", err.Error())
		return err
	}
	if authentication != nil && authentication.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded("Authentication is not ready", fmt.Sprintf("authentication status: %s", authentication.Status.State))
		return nil
	}

	var dexCfg render.DexRelyingPartyConfig
	// If the authentication CR is available and it is not configured to use the Tigera OIDC type then configure dex.
	if authentication != nil && (authentication.Spec.OIDC == nil || authentication.Spec.OIDC.Type != operatorv1.OIDCTypeTigera) {
		var dexCertSecret *corev1.Secret
		dexCertSecret = &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexCertSecretName, Namespace: rmeta.OperatorNamespace()}, dexCertSecret); err != nil {
			r.status.SetDegraded("Failed to read dex tls secret", err.Error())
			return err
		}

		dexSecret := &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexObjectName, Namespace: rmeta.OperatorNamespace()}, dexSecret); err != nil {
			r.status.SetDegraded("Failed to read dex tls secret", err.Error())
			return err
		}
		dexCfg = render.NewDexRelyingPartyConfig(authentication, dexCertSecret, dexSecret, r.clusterDomain)
	}

	component := render.LogStorage(
		ls,
		install,
		managementCluster,
		managementClusterConnection,
		elasticsearch,
		kibana,
		clusterConfig,
		[]*corev1.Secret{esCertSecret, esInternalCertSecret, esAdminUserSecret},
		kibanaSecrets,
		pullSecrets,
		r.provider,
		curatorSecrets,
		esService,
		kbService,
		r.clusterDomain,
		dexCfg,
		r.esLicenseType,
	)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return err
	}

	if err := hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		reqLogger.Error(err, err.Error())
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return err
	}

	if managementClusterConnection == nil {
		if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
			r.status.SetDegraded("Waiting for Elasticsearch cluster to be operational", "")
			return fmt.Errorf("waiting for Elasticsearch cluster to be operational")
		}

		if kibana == nil || kibana.Status.AssociationStatus != cmnv1.AssociationEstablished {
			r.status.SetDegraded("Waiting for Kibana cluster to be operational", "")
			return fmt.Errorf("waiting for Kibana cluster to be operational")
		}
	}

	return nil
}

func (r *ReconcileLogStorage) validateLogStorage(reqLogger logr.Logger, ctx context.Context) error {
	var err error

	if len(r.curatorSecrets) == 0 {
		reqLogger.Info("waiting for curator secrets to become available")
		r.status.SetDegraded("Waiting for curator secrets to become available", "")
		return fmt.Errorf("waiting for curator secrets to become available")
	}

	// kube-controller creates the ConfigMap and Secret needed for SSO into Kibana.
	// If elastisearch uses basic license, degrade logstorage if the ConfigMap and Secret
	// needed for logging user into Kibana is not available.
	if r.esLicenseType == render.ElasticsearchLicenseTypeBasic {
		if err = r.checkOIDCUsersEsResource(ctx); err != nil {
			r.status.SetDegraded("Failed to get oidc user Secret and ConfigMap", err.Error())
			return err
		}
	}
	return nil
}

func (r *ReconcileLogStorage) applyILMPolicies(ls *operatorv1.LogStorage, reqLogger logr.Logger, ctx context.Context) error {
	// ES should be in ready phase when execution reaches here, apply ILM polices
	esClient, err := r.esCliCreator(r.client, ctx, relasticsearch.HTTPSEndpoint(rmeta.OSTypeLinux, r.clusterDomain))
	if err != nil {
		reqLogger.Error(err, "failed to create the Elasticsearch client")
		r.status.SetDegraded("Failed to connect to Elasticsearch", err.Error())
		return err
	}

	if err = esClient.SetILMPolicies(ctx, ls); err != nil {
		reqLogger.Error(err, "failed to create or update Elasticsearch lifecycle policies")
		r.status.SetDegraded("Failed to create or update Elasticsearch lifecycle policies", err.Error())
		return err
	}
	return nil
}

func addLogStorageWatches(c controller.Controller) error {
	// Watch for changes in storage classes, as new storage classes may be made available for LogStorage.
	err := c.Watch(&source.Kind{
		Type: &storagev1.StorageClass{}}, &handler.EnqueueRequestForObject{})
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

	for _, name := range []string{render.OIDCUsersConfigMapName, render.OIDCUsersEsSecreteName,
		render.ElasticsearchAdminUserSecret} {
		if err = utils.AddConfigMapWatch(c, name, render.ElasticsearchNamespace); err != nil {
			return fmt.Errorf("log-storage-controller failed to watch the ConfigMap resource: %w", err)
		}
	}

	return nil
}
