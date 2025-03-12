// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package whisker

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	controllerName = "whisker-controller"
	ResourceName   = "whisker"
)

var log = logf.Log.WithName(controllerName)

// Add creates a new Reconciler Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.WhiskerCRDExists || opts.EnterpriseCRDExists {
		// Whisker is only supported in Calico deployments that have the CRD installed.
		return nil
	}

	statusManager := status.New(mgr.GetClient(), "whisker", opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, opts)

	// Create a new controller
	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	for _, secretName := range []string{
		monitor.PrometheusServerTLSSecretName,
		whisker.ManagedClusterConnectionSecretName,
		certificatemanagement.CASecretName,
		render.ProjectCalicoAPIServerTLSSecretName(operatorv1.TigeraSecureEnterprise),
		render.ProjectCalicoAPIServerTLSSecretName(operatorv1.Calico),
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("failed to add watch for secret %s/%s: %w", common.OperatorNamespace(), secretName, err)
		}
	}

	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("failed to add watch for config map %s/%s: %w", common.OperatorNamespace(), certificatemanagement.TrustedCertConfigMapName, err)
	}

	err = c.WatchObject(&operatorv1.Whisker{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch management cluster connection resource: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	if err := utils.AddDeploymentWatch(c, whisker.WhiskerDeploymentName, whisker.WhiskerNamespace); err != nil {
		return fmt.Errorf("%s failed to watch Whisker deployment: %w", controllerName, err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("whisker-controller failed to watch management-cluster-connection Tigerastatus: %w", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	p operatorv1.Provider,
	opts options.AddOptions,
) *Reconciler {
	c := &Reconciler{
		cli:           cli,
		scheme:        schema,
		provider:      p,
		status:        statusMgr,
		clusterDomain: opts.ClusterDomain,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &Reconciler{}

// Reconciler reconciles a ManagementClusterConnection object
type Reconciler struct {
	cli           client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
}

// Reconcile reads that state of the cluster for a Whisker object and makes changes based on the
// state read and what is in the Whisker.Spec. The Controller will requeue the Request to be
// processed again if the returned error is non-nil or Result.Requeue is true, otherwise upon completion it will
// remove the work from the queue.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Whisker")

	variant, installation, err := utils.GetInstallation(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	}

	whiskerCR, err := utils.GetIfExists[operatorv1.Whisker](ctx, utils.DefaultInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Whisker CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if whiskerCR == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}
	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&whiskerCR.ObjectMeta)

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	var tunnelSecret *corev1.Secret
	managementClusterConnection, err := utils.GetIfExists[operatorv1.ManagementClusterConnection](ctx, utils.DefaultTSEEInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	} else if managementClusterConnection != nil {
		tunnelSecret, err = utils.GetIfExists[corev1.Secret](ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()}, r.cli)
		if err != nil {
			return reconcile.Result{}, err
		}

		if err := utils.ApplyDefaults(ctx, r.cli, managementClusterConnection); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, err.Error(), err, reqLogger)
			return reconcile.Result{}, err
		}

		log.V(2).Info("Loaded ManagementClusterConnection config", managementClusterConnection)
	}

	certificateManager, err := certificatemanager.Create(r.cli, installation, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the certificate manager", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Goldmane needs a server certificate for it's gRPC API.
	// TODO: Add this to the trusted bundle. This isn't stritctly needed, since the bundle already includes the operator CA that
	// signed this certificate. But in order to support custom user-supplied certificates, we will need to do this.
	goldmaneCertificateNames := dns.GetServiceDNSNames(whisker.GoldmaneServiceName, whisker.WhiskerNamespace, r.clusterDomain)
	goldmaneCertificateNames = append(goldmaneCertificateNames, "localhost", "127.0.0.1")
	keyPair, err := certificateManager.GetOrCreateKeyPair(r.cli, whisker.GoldmaneKeyPairSecret, common.OperatorNamespace(), goldmaneCertificateNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating goldmane TLS certificate", err, log)
		return reconcile.Result{}, err
	}

	// Whisker-backend needs a certificate for mTLS with Goldmane.
	// TODO: Add this to the trusted bundle. This isn't stritctly needed, since the bundle already includes the operator CA that
	// signed this certificate. But in order to support custom user-supplied certificates, we will need to do this.
	whiskerBackendCertificateNames := dns.GetServiceDNSNames("whisker-backend", whisker.WhiskerNamespace, r.clusterDomain)
	whiskerBackendCertificateNames = append(whiskerBackendCertificateNames, "localhost", "127.0.0.1")
	backendKeyPair, err := certificateManager.GetOrCreateKeyPair(r.cli, whisker.WhiskerBackendKeyPairSecret, whisker.WhiskerNamespace, whiskerBackendCertificateNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating whisker-backend TLS certificate", err, log)
		return reconcile.Result{}, err
	}

	// Guardian needs a certificate for mTLS with Goldmane.
	// TODO: Add this to the trusted bundle. This isn't stritctly needed, since the bundle already includes the operator CA that
	// signed this certificate. But in order to support custom user-supplied certificates, we will need to do this.
	guardianCertificateNames := dns.GetServiceDNSNames("guardian", whisker.WhiskerNamespace, r.clusterDomain)
	guardianCertificateNames = append(guardianCertificateNames, "localhost", "127.0.0.1")
	guardianKeyPair, err := certificateManager.GetOrCreateKeyPair(r.cli, whisker.GuardianKeyPairSecret, whisker.WhiskerNamespace, guardianCertificateNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating guardian TLS certificate", err, log)
		return reconcile.Result{}, err
	}

	certComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       whisker.WhiskerNamespace,
		TruthNamespace:  common.OperatorNamespace(),
		ServiceAccounts: []string{whisker.WhiskerServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(keyPair, true, true),
			rcertificatemanagement.NewKeyPairOption(backendKeyPair, true, true),
			rcertificatemanagement.NewKeyPairOption(guardianKeyPair, true, true),
		},
		// TrustedBundle is managed by the core controller.
		TrustedBundle: nil,
	})

	trustedCertBundle, err := certificateManager.LoadTrustedBundle(ctx, r.cli, whisker.WhiskerNamespace)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error loading trusted cert bundle", err, reqLogger)
		return reconcile.Result{}, err
	}

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, whiskerCR)
	cfg := &whisker.Configuration{
		PullSecrets:                 pullSecrets,
		OpenShift:                   r.provider.IsOpenShift(),
		Installation:                installation,
		TunnelSecret:                tunnelSecret,
		TrustedCertBundle:           trustedCertBundle,
		ManagementClusterConnection: managementClusterConnection,
		GoldmaneServerKeyPair:       keyPair,
		WhiskerBackendKeyPair:       backendKeyPair,
		GuardianClientKeyPair:       guardianKeyPair,
	}

	components := []render.Component{certComponent, whisker.Whisker(cfg)}
	if err = imageset.ApplyImageSet(ctx, r.cli, variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	return reconcile.Result{}, nil
}
