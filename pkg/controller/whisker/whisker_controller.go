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

	"golang.org/x/net/http/httpproxy"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"github.com/tigera/operator/pkg/render"
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
	enabled, err := utils.WhiskerEnabled(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("failed to check if whisker was enabled: %w", err)
	}
	if !enabled {
		return nil
	}

	statusManager := status.New(mgr.GetClient(), "gold-rush", opts.KubernetesVersion)

	// Create the reconciler
	tierWatchReady := &utils.ReadyFlag{}
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, tierWatchReady, opts)

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

	err = c.WatchObject(&operatorv1.Whisker{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
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
		return fmt.Errorf("clusterconnection-controller failed to watch management-cluster-connection Tigerastatus: %w", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	p operatorv1.Provider,
	tierWatchReady *utils.ReadyFlag,
	opts options.AddOptions,
) *Reconciler {
	c := &Reconciler{
		cli:            cli,
		scheme:         schema,
		provider:       p,
		status:         statusMgr,
		clusterDomain:  opts.ClusterDomain,
		tierWatchReady: tierWatchReady,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &Reconciler{}

// Reconciler reconciles a ManagementClusterConnection object
type Reconciler struct {
	cli                        client.Client
	scheme                     *runtime.Scheme
	provider                   operatorv1.Provider
	status                     status.StatusManager
	clusterDomain              string
	tierWatchReady             *utils.ReadyFlag
	resolvedPodProxies         []*httpproxy.Config
	lastAvailabilityTransition metav1.Time
}

// Reconcile reads that state of the cluster for a Whisker object and makes changes based on the
// state read and what is in the Whisker.Spec. The Controller will requeue the Request to be
// processed again if the returned error is non-nil or Result.Requeue is true, otherwise upon completion it will
// remove the work from the queue.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Whisker")
	result := reconcile.Result{}

	variant, installation, err := utils.GetInstallation(ctx, r.cli)
	if err != nil {
		return result, err
	}

	whiskerCR, err := utils.GetIfExists[operatorv1.Whisker](ctx, utils.DefaultInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Whisker CR", err, reqLogger)
		return result, err
	} else if whiskerCR == nil {
		r.status.OnCRNotFound()
		return result, nil
	}
	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&whiskerCR.ObjectMeta)

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return result, err
	}

	certificateManager, err := certificatemanager.Create(r.cli, installation, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the certificate manager", err, reqLogger)
		return reconcile.Result{}, err
	}

	linseedCASecret, err := utils.GetIfExists[corev1.Secret](ctx,
		types.NamespacedName{Name: render.VoltronLinseedPublicCert, Namespace: common.OperatorNamespace()}, r.cli)
	if err != nil {
		return result, err
	}

	var trustedCertBundle certificatemanagement.TrustedBundle
	tunnelSecret := &corev1.Secret{}
	managementClusterConnection, err := utils.GetIfExists[operatorv1.ManagementClusterConnection](ctx, utils.DefaultTSEEInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying ManagementClusterConnection", err, reqLogger)
		return result, err
	} else if managementClusterConnection != nil {
		// Copy the secret from the operator namespace to the guardian namespace if it is present.

		err = r.cli.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()}, tunnelSecret)
		if err != nil {
			if !k8serrors.IsNotFound(err) {
				return result, err
			}
			tunnelSecret = nil
		}

		preDefaultPatchFrom := client.MergeFrom(managementClusterConnection.DeepCopy())
		managementClusterConnection.FillDefaults()

		// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
		// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
		if err := r.cli.Patch(ctx, managementClusterConnection, preDefaultPatchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, err.Error(), err, reqLogger)
			return reconcile.Result{}, err
		}

		log.V(2).Info("Loaded ManagementClusterConnection config", "config", managementClusterConnection)

		if managementClusterConnection.Spec.TLS.CA == operatorv1.CATypePublic {
			// If we need to trust a public CA, then we want Guardian to mount all the system certificates.
			trustedCertBundle, err = certificateManager.CreateTrustedBundleWithSystemRootCertificates()
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create tigera-ca-bundle configmap", err, reqLogger)
				return reconcile.Result{}, err
			}
		} else {
			trustedCertBundle = certificateManager.CreateTrustedBundle()
		}
	}

	if trustedCertBundle == nil {
		trustedCertBundle = certificateManager.CreateTrustedBundle()
	}

	trustedCertBundle.SetName("whisker-trusted-bundle")

	secretsToTrust := []string{render.ProjectCalicoAPIServerTLSSecretName(installation.Variant)}
	for _, secretName := range secretsToTrust {
		secret, err := certificateManager.GetCertificate(r.cli, secretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve %s", secretName), err, reqLogger)
			return reconcile.Result{}, err
		} else if secret == nil {
			reqLogger.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secretName))
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret '%s' to become available", secretName), nil, reqLogger)
			return reconcile.Result{}, nil
		}
		trustedCertBundle.AddCertificates(secret)
	}

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, whiskerCR)
	cfg := &whisker.Configuration{
		PullSecrets:                 pullSecrets,
		OpenShift:                   r.provider.IsOpenShift(),
		Installation:                installation,
		TunnelSecret:                tunnelSecret,
		TrustedCertBundle:           trustedCertBundle,
		LinseedPublicCASecret:       linseedCASecret,
		ManagementClusterConnection: managementClusterConnection,
	}

	components := []render.Component{whisker.Whisker(cfg)}
	if err = imageset.ApplyImageSet(ctx, r.cli, variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return result, err
		}
	}

	r.status.ClearDegraded()

	return result, nil
}

func newNSObjectKey(name, namespace string) client.ObjectKey {
	return types.NamespacedName{Name: name, Namespace: namespace}
}
