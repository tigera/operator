// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package imageassurance

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/imageassurance/configsync"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/imageassurance"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_image_assurance")

// names of service account, secret tokens created by kube-controller for image assurance components for API access
var apiAccessResources = []string{
	imageassurance.ScannerAPIAccessResourceName,
	imageassurance.RuntimeCleanerAPIAccessResourceName,
}

// Add creates a new ImageAssurance Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	var licenseAPIReady = &utils.ReadyFlag{}

	reconciler := newReconciler(mgr, opts, licenseAPIReady)

	c, err := controller.New("imageassurance-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return err
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(c, k8sClient, log, licenseAPIReady)

	return add(mgr, c)
}

// newReconciler returns a new *reconcile.Reconciler.
func newReconciler(mgr manager.Manager, opts options.AddOptions, licenseAPIReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileImageAssurance{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "imageassurance", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
	}

	r.configSyncer = configsync.NewSyncer(opts.ShutdownContext, rcimageassurance.APIEndpoint, r.client)

	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup.
func add(mgr manager.Manager, c controller.Controller) error {
	var err error

	// Watch for changes to primary resource ImageAssurance.
	err = c.Watch(&source.Kind{Type: &operatorv1.ImageAssurance{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("ImageAssurance-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("ImageAssurance-controller failed to watch Tigera network resource: %v", err)
	}

	// Watch configmaps created for postgres in operator namespace.
	for _, cm := range []string{rcimageassurance.ConfigurationConfigMapName} {
		if err = utils.AddConfigMapWatch(c, cm, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("ImageAssurance-controller failed to watch ConfigMap %s: %v", cm, err)
		}
	}

	// Watch secrets created for postgres and API access (by kube controllers) in operator namespace.
	var watchedSecrets []string
	watchedSecrets = append(watchedSecrets, []string{imageassurance.APICertSecretName, render.ManagerInternalTLSSecretName, certificatemanagement.CASecretName}...)
	watchedSecrets = append(watchedSecrets, apiAccessResources...)
	for _, s := range watchedSecrets {
		if err = utils.AddSecretsWatch(c, s, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("ImageAssurance-controller failed to watch Secret %s: %v", s, err)
		}
	}

	// watch for service accounts created in operator namespace by kube-controllers for image assurance.
	for _, sa := range apiAccessResources {
		if err = utils.AddServiceAccountWatch(c, sa, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("ImageAssurance-controller failed to watch ServiceAccount %s: %v", sa, err)
		}
	}

	if err = utils.AddJobWatch(c, imageassurance.ResourceNameImageAssuranceDBMigrator, imageassurance.NameSpaceImageAssurance); err != nil {
		return fmt.Errorf("ImageAssurance-controller failed to watch Job %s: %v", imageassurance.ResourceNameImageAssuranceDBMigrator, err)
	}

	for _, role := range []string{imageassurance.ScannerAPIAccessResourceName, imageassurance.AdmissionControllerAPIClusterRoleName,
		imageassurance.RuntimeCleanerAPIAccessResourceName} {
		if err = utils.AddClusterRoleWatch(c, role); err != nil {
			return fmt.Errorf("ImageAssurance-controller failed to watch Cluster role %s: %v", role, err)
		}
	}
	// Watch for changes to authentication
	err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("ImageAssurance-controller failed to watch resource: %w", err)
	}

	return nil
}

// Blank assignment to verify that ReconcileImageAssurance implements reconcile.Reconciler.
var _ reconcile.Reconciler = &ReconcileImageAssurance{}

// ReconcileImageAssurance reconciles a ImageAssurance object.
type ReconcileImageAssurance struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	licenseAPIReady *utils.ReadyFlag
	configSyncer    configsync.Syncer
}

// Reconcile reads that state of the cluster for a ImageAssurance object and makes changes
// based on the state read and what is in the ImageAssurance.Spec.
func (r *ReconcileImageAssurance) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ImageAssurance")

	ia, err := utils.GetImageAssurance(ctx, r.client)

	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("ImageAssurance object not found")

			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "Error querying for ImageAssurance")
		r.SetDegraded("Error querying for ImageAssurance", err.Error())
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	variant, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "Installation not found")
			r.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "Error querying installation")
		r.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		reqLogger.Error(err, "Error retrieving image pull secrets")
		r.SetDegraded("Error retrieving image pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	configurationConfigMap, err := utils.GetImageAssuranceConfigurationConfigMap(r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, fmt.Sprintf("%s ConfigMap not found", rcimageassurance.ConfigurationConfigMapName))
			r.SetDegraded(fmt.Sprintf("%s ConfigMap not found", rcimageassurance.ConfigurationConfigMapName), err.Error())
			return reconcile.Result{}, nil
		}

		reqLogger.Error(err, "Error retrieving image assurance configuration")
		r.SetDegraded("Error retrieving image assurance configuration", err.Error())
		return reconcile.Result{}, err
	}

	if ia.Spec.APIProxyURL == "" {
		err := fmt.Errorf("APIProxyURL cannot be nil or empty")
		reqLogger.Error(err, "APIProxyURL cannot be nil or empty")
		r.SetDegraded("APIProxyURL cannot be nil or empty", err.Error())
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, installation, r.clusterDomain)
	if err != nil {
		log.Error(err, "unable to create the Tigera CA")
		r.SetDegraded("Unable to create the Tigera CA", err.Error())
		return reconcile.Result{}, err
	}
	internalMgrSecret, err := certificateManager.GetCertificate(r.client, render.ManagerInternalTLSSecretName, common.OperatorNamespace())

	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error retrieving internal manager tls secret", err.Error())
		return reconcile.Result{}, err
	}

	trustedBundle := certificateManager.CreateTrustedBundle(internalMgrSecret)

	if internalMgrSecret == nil {
		reqLogger.Info("Waiting for internal manager tls certificate to be available")
		r.SetDegraded("Waiting for internal manager tls certificate to be available", "")
		return reconcile.Result{}, nil
	}

	tlsSecret, err := getAPICertSecret(r.client, r.clusterDomain)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error in ensuring TLS certificate for image-assurance api", err.Error())
		return reconcile.Result{}, err
	}

	scannerAPIToken, err := utils.GetImageAssuranceAPIAccessToken(r.client, imageassurance.ScannerAPIAccessResourceName)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error in retrieving scanner API access token", err.Error())
		return reconcile.Result{}, err
	}

	if scannerAPIToken == nil {
		reqLogger.Info("Waiting for scanner API access service account secret to be available")
		r.SetDegraded("Waiting for scanner API access service account secret to be available", "")
		return reconcile.Result{}, nil
	}

	runtimeCleanerAPIToken, err := utils.GetImageAssuranceAPIAccessToken(r.client, imageassurance.RuntimeCleanerAPIAccessResourceName)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error in retrieving runtime cleaner API access token", err.Error())
		return reconcile.Result{}, err
	}

	if runtimeCleanerAPIToken == nil {
		reqLogger.Info("Waiting for runtime cleaner API access service account secret to be available")
		r.SetDegraded("Waiting for runtime cleaner API access service account secret to be available", "")
		return reconcile.Result{}, nil
	}

	imageSet, err := imageset.GetImageSet(ctx, r.client, variant)
	if err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error retrieving image set", err.Error())
		return reconcile.Result{}, err
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		reqLogger.Error(err, err.Error())
		r.SetDegraded("Error validating image set", err.Error())
		return reconcile.Result{}, err
	}

	ch := utils.NewComponentHandler(log, r.client, r.scheme, ia)

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.SetDegraded("Error querying Authentication", err.Error())
		return reconcile.Result{}, err
	}

	if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
		r.SetDegraded("Authentication is not ready", fmt.Sprintf("authenticationCR status: %s", authenticationCR.Status.State))
		return reconcile.Result{}, nil
	}

	kvc, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain)
	if err != nil {
		log.Error(err, "Failed to process the authentication CR.")
		r.SetDegraded("Failed to process the authentication CR.", err.Error())
		return reconcile.Result{}, err
	}

	config := &imageassurance.Config{
		PullSecrets:                  pullSecrets,
		Installation:                 installation,
		OsType:                       rmeta.OSTypeLinux,
		ConfigurationConfigMap:       configurationConfigMap,
		TLSSecret:                    tlsSecret,
		KeyValidatorConfig:           kvc,
		TrustedCertBundle:            trustedBundle,
		ScannerAPIAccessToken:        scannerAPIToken,
		RuntimeCleanerAPIAccessToken: runtimeCleanerAPIToken,
		APIProxyURL:                  ia.Spec.APIProxyURL,
	}

	components := []render.Component{
		render.NewPassthrough([]client.Object{tlsSecret}...),
		imageassurance.ImageAssurance(config),
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       imageassurance.NameSpaceImageAssurance,
			ServiceAccounts: []string{imageassurance.ResourceNameImageAssuranceAPI},
			TrustedBundle:   trustedBundle,
		}),
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, components...); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			reqLogger.Error(err, "Error creating / updating resource")
			r.SetDegraded("Error creating / updating resource", err.Error())
			return reconcile.Result{}, err
		}
	}

	// Start the period sync of image assurance settings to the config map. Note that this function can be called multiple
	// times, once started the subsequent calls are no ops.
	r.configSyncer.StartPeriodicSync()

	if err := r.configSyncer.Error(); err != nil {
		reqLogger.Error(err, "An error occurred syncing while syncing the Image Assurance ConfigMap")
		r.status.SetDegraded(string(operatorv1.ResourceUpdateError), fmt.Sprintf("an error occurred syncing while syncing the Image Assurance ConfigMap: %v", err))

		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Clear the degraded bit since we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future, hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CRD status.
	ia.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, ia); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// Deprecated.
// This adapter was created to resolve merge conflicts.
// All calls in rs controller should be updated to use r.status.SetDegraded directly.
func (r *ReconcileImageAssurance) SetDegraded(message, errStr string) {
	var err error
	if errStr != "" {
		err = fmt.Errorf(errStr)
	}
	r.status.SetDegraded(operatorv1.Unknown, message, err, log.WithName(""))
}

// getAPICertSecret returns the image assurance api tls secret.
// It returns secret if available otherwise creates a new tls secret and returns it.
func getAPICertSecret(client client.Client, clusterDomain string) (*corev1.Secret, error) {
	// note that if secret is not found, ValidateCertPair returns nil, nil
	secret, err := utils.ValidateCertPair(client, common.OperatorNamespace(), imageassurance.APICertSecretName,
		corev1.TLSPrivateKeyKey, corev1.TLSCertKey)

	if err != nil {
		return nil, err
	}

	// If secret is found, ensure it has valid DNS names, note that if secret is nil EnsureCertificateSecret creates a new one.
	svcDNSNames := dns.GetServiceDNSNames(imageassurance.ResourceNameImageAssuranceAPI, imageassurance.NameSpaceImageAssurance, clusterDomain)
	secret, _, err = utils.EnsureCertificateSecret(
		imageassurance.APICertSecretName, secret, corev1.TLSPrivateKeyKey, corev1.TLSCertKey, rmeta.DefaultCertificateDuration, svcDNSNames...,
	)

	if err != nil {
		return nil, fmt.Errorf("error ensuring TLS certificate exists and has valid DNS names %q: %s", render.ManagerInternalTLSSecretName, err)
	}

	return secret, nil
}
