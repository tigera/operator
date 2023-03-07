// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package cloudrbac

import (
	"context"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	oprender "github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/cloudrbac"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// ReconcileCloudRBAC reconciles a CloudRBAC object
type ReconcileCloudRBAC struct {
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	clusterDomain string
}

var (
	log = logf.Log.WithName("controller_cloudrbac")
)

// Add creates a new CloudRBAC Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	reconciler := newReconciler(mgr, opts)

	c, err := controller.New("cloud-rbac-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	return add(mgr, c)
}

// newReconciler returns a new *reconcile.Reconciler.
func newReconciler(mgr manager.Manager, opts options.AddOptions) reconcile.Reconciler {
	r := &ReconcileCloudRBAC{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		status:        status.New(mgr.GetClient(), "cloud-rbac", opts.KubernetesVersion),
		clusterDomain: opts.ClusterDomain,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup.
func add(mgr manager.Manager, c controller.Controller) error {
	var err error

	// Watch for changes to primary resource CloudRBAC.
	err = c.Watch(&source.Kind{Type: &operatorv1.CloudRBAC{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("CloudRBAC-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("CloudRBAC-controller failed to watch Tigera network resource: %v", err)
	}

	for _, role := range []string{
		cloudrbac.RBACApiClusterRoleName,
	} {
		if err = utils.AddClusterRoleWatch(c, role); err != nil {
			return fmt.Errorf("CloudRBAC-controller failed to watch Cluster role %s: %v", role, err)
		}
	}

	for _, secretName := range []string{
		cloudrbac.RBACAPICertSecretName,
		certificatemanagement.CASecretName,
		oprender.ManagerInternalTLSSecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("CloudRBAC-controller failed to watch the Secret resource: %v", err)
		}
	}

	// Watch for changes to authentication
	err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("CloudRBAC-controller failed to watch resource: %w", err)
	}

	return nil
}

// Reconcile reads the state of the cluster for a CloudRBAC object and makes changes based on the state read
// and what is in the CloudRBAC.Spec
func (r *ReconcileCloudRBAC) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)
	reqLogger.Info("Reconciling CloudRBAC")

	// Fetch the CloudRBAC instance
	instance, err := utils.GetCloudRBAC(ctx, r.client)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("CloudRBAC CR not found", "err", err)
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			r.status.OnCRNotFound()
			return ctrl.Result{}, nil
		}
		r.SetDegraded(reqLogger, operatorv1.ResourceReadError, "Error querying CloudRBAC", err)
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	variant, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.SetDegraded(reqLogger, operatorv1.ResourceNotFound, "Installation not found", err)
			return ctrl.Result{}, nil
		}
		r.SetDegraded(reqLogger, operatorv1.ResourceReadError, "Error querying installation", err)
		return ctrl.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, installation, r.clusterDomain)
	if err != nil {
		r.SetDegraded(reqLogger, operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err)
		return ctrl.Result{}, err
	}
	certificateManager.AddToStatusManager(r.status, cloudrbac.RBACApiNamespace)

	dnsNames := dns.GetServiceDNSNames(cloudrbac.RBACApiName, cloudrbac.RBACApiNamespace, r.clusterDomain)
	keyPair, err := certificateManager.GetOrCreateKeyPair(r.client, cloudrbac.RBACAPICertSecretName, common.OperatorNamespace(), dnsNames)
	if err != nil {
		r.SetDegraded(reqLogger, operatorv1.ResourceCreateError, fmt.Sprintf("Failed to get %v secret from operator namespace", cloudrbac.RBACAPICertSecretName), err)
		return ctrl.Result{}, err
	}
	if keyPair == nil {
		r.SetDegraded(reqLogger, operatorv1.ResourceCreateError, fmt.Sprintf("%v secret not found in operator namespace", cloudrbac.RBACAPICertSecretName), nil)
		return ctrl.Result{}, nil
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		reqLogger.Error(err, "Error retrieving image pull secrets")
		r.SetDegraded(reqLogger, operatorv1.ResourceReadError, "Error retrieving image pull secrets", err)
		return reconcile.Result{}, err
	}

	managerInternalTLSCert, err := certificateManager.GetCertificate(r.client, oprender.ManagerInternalTLSSecretName, common.OperatorNamespace())
	if err != nil {
		r.SetDegraded(reqLogger, operatorv1.ResourceReadError, fmt.Sprintf("failed to retrieve / validate  %s", oprender.ManagerInternalTLSSecretName), err)
		return reconcile.Result{}, err
	}

	trustedBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates(managerInternalTLSCert)
	if err != nil {
		log.Error(err, "failed to create trusted bundle")
		r.SetDegraded(reqLogger, operatorv1.ResourceCreateError, "failed to create trusted bundle", err)
		return reconcile.Result{}, err
	}

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.SetDegraded(reqLogger, operatorv1.ResourceReadError, "Error querying Authentication", err)
		return reconcile.Result{}, err
	}
	if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
		r.SetDegraded(reqLogger, operatorv1.ResourceReadError, fmt.Sprintf("Authentication is not ready, status=%s", authenticationCR.Status.State), nil)
		return reconcile.Result{}, nil
	}

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain)
	if err != nil {
		r.SetDegraded(reqLogger, operatorv1.ResourceReadError, "failed to get key validator config", err)
		return reconcile.Result{}, err
	}

	cloudrbacConfig := &cloudrbac.Configuration{
		PullSecrets:        pullSecrets,
		Installation:       installation,
		TrustedBundle:      trustedBundle,
		KeyValidatorConfig: keyValidatorConfig,
		TLSKeyPair:         keyPair,
		PortalURL:          instance.Spec.PortalURL,
	}

	components := []oprender.Component{
		cloudrbac.RBACApi(cloudrbacConfig),
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace: cloudrbac.RBACApiNamespace,
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(keyPair, true, true),
			},
			TrustedBundle: cloudrbacConfig.TrustedBundle,
		}),
	}

	ch := utils.NewComponentHandler(log, r.client, r.scheme, instance)
	for _, component := range components {
		if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
			r.SetDegraded(reqLogger, operatorv1.InvalidConfigurationError, "Error with images from ImageSet", err)
			return ctrl.Result{}, err
		}

		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.SetDegraded(reqLogger, operatorv1.ResourceUpdateError, "Error creating / updating resource", err)
			return ctrl.Result{}, err
		}
	}

	r.status.ClearDegraded()
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ReconcileCloudRBAC) SetupWithManager(mgr ctrl.Manager) error {
	pred := builder.WithPredicates(predicate.ResourceVersionChangedPredicate{})
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Namespace{}).
		Owns(&corev1.Namespace{}).
		Owns(&corev1.Service{}, pred).
		Owns(&corev1.ServiceAccount{}, pred).
		Owns(&rbacv1.ClusterRole{}, pred).
		Owns(&rbacv1.ClusterRoleBinding{}, pred).
		Owns(&appsv1.Deployment{}, pred).
		Watches(&source.Kind{Type: &v3.ManagedCluster{}}, &handler.EnqueueRequestForObject{}).
		Complete(r)
}

// SetDegraded sets status as degraded the for the CloudRBAC resource
func (r *ReconcileCloudRBAC) SetDegraded(reqLogger logr.Logger, reason operatorv1.TigeraStatusReason, message string, err error) {
	r.status.SetDegraded(reason, message, err, reqLogger)
}
