// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package nonclusterhost

import (
	"context"
	"fmt"
	"net"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/typhaautoscaler"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/nonclusterhost"
	"github.com/tigera/operator/pkg/render/serval"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

const controllerName = "nonclusterhost-controller"

var log = logf.Log.WithName("controller_nonclusterhost")

// typhaNonClusterHostDeployment is the legacy directly-exposed Typha deployment,
// used when spec.typhaEndpoint is set.
var typhaNonClusterHostDeployment = common.TyphaDeploymentName + render.TyphaNonClusterHostSuffix

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// create the reconciler
	reconciler, err := newReconciler(mgr, opts)
	if err != nil {
		return err
	}

	// create a new controller
	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create nonclusterhost-controller: %w", err)
	}

	return add(mgr, c)
}

func newReconciler(mgr manager.Manager, opts options.ControllerOptions) (reconcile.Reconciler, error) {
	statusManager := status.New(mgr.GetClient(), "non-cluster-hosts", opts.KubernetesVersion)

	// Both modes scale their Typha with the registered-host (HostEndpoint) count to the same
	// value: the serval gateway (typhaEndpoint unset) or the legacy
	// calico-typha-noncluster-host deployment (typhaEndpoint set). Exactly one exists at a
	// time, so a single autoscaler drives both — it applies the count to each and skips the
	// one that is absent.
	autoscaler, err := typhaautoscaler.NewHostEndpointScaler(
		mgr.GetConfig(), opts.K8sClientset, statusManager,
		[]string{serval.ServalDeploymentName, typhaNonClusterHostDeployment},
		opts.ShutdownContext.Done())
	if err != nil {
		return nil, fmt.Errorf("failed to create the non-cluster-host autoscaler: %w", err)
	}
	autoscaler.Start(opts.ShutdownContext)

	r := &ReconcileNonClusterHost{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		status:        statusManager,
		provider:      opts.DetectedProvider,
		clusterDomain: opts.ClusterDomain,
		autoscaler:    autoscaler,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

func add(mgr manager.Manager, c ctrlruntime.Controller) error {
	if err := c.WatchObject(&operatorv1.NonClusterHost{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch resource: %w", controllerName, err)
	}

	if err := utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	// The gateway's serving cert and the Typha keypair it reuses drive a re-render.
	for _, secretName := range []string{serval.ServalKeyPairSecret, render.TyphaTLSSecretName + render.TyphaNonClusterHostSuffix, certificatemanagement.CASecretName} {
		if err := utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("%s failed to watch secret %s: %w", controllerName, secretName, err)
		}
	}

	if err := imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	if err := utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to create periodic reconcile watch: %w", controllerName, err)
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileNonClusterHost{}

type ReconcileNonClusterHost struct {
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	provider      operatorv1.Provider
	clusterDomain string

	// autoscaler scales the serval gateway and the legacy calico-typha-noncluster-host
	// deployment by HostEndpoint count; only one exists at a time.
	autoscaler *typhaautoscaler.Autoscaler
}

func (r *ReconcileNonClusterHost) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	logc.Info("Reconciling NonClusterHost")

	instance, err := utils.GetNonClusterHost(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query NonClusterHost resource", err, logc)
		return reconcile.Result{}, err
	} else if instance == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	logc.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Re-trigger the autoscaler if degraded and requeue if it stays degraded.
	if r.autoscaler != nil && r.autoscaler.IsDegraded() {
		if err := r.autoscaler.TriggerRun(); err != nil {
			r.status.SetDegraded(operatorv1.ResourceScalingError, "Failed to scale Typha for non-cluster hosts", err, logc)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
	}

	// Validate the endpoint; it is the HTTPS front door in both modes.
	_, endpointHost, _, err := url.ParseEndpoint(instance.Spec.Endpoint)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid endpoint", err, logc)
		return reconcile.Result{}, err
	}

	// typhaEndpoint set selects the deprecated direct-to-typha (legacy) mode; unset selects
	// the serval gateway.
	gateway := instance.Spec.TyphaEndpoint == ""
	if !gateway {
		logc.Info("spec.typhaEndpoint is deprecated; clear it to use the serval gateway")
		if _, _, err = net.SplitHostPort(instance.Spec.TyphaEndpoint); err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid Typha endpoint", err, logc)
			return reconcile.Result{}, err
		}
	}

	// The host identity (ServiceAccount, token, ClusterRole) is shared by both modes.
	components := []render.Component{
		nonclusterhost.NonClusterHost(&nonclusterhost.Config{NonClusterHost: instance.Spec}),
	}

	if gateway {
		// Only the gateway needs an Installation (for images and certificates).
		variant, installationSpec, err := utils.GetInstallationSpec(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query Installation", err, logc)
			return reconcile.Result{}, err
		} else if installationSpec == nil {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", nil, logc)
			return reconcile.Result{}, nil
		}

		gatewayComponents, res, err := r.gatewayComponents(ctx, installationSpec, endpointHost, logc)
		if err != nil || res != nil {
			if res != nil {
				return *res, err
			}
			return reconcile.Result{}, err
		}
		components = append(components, gatewayComponents...)

		if err = imageset.ApplyImageSet(ctx, r.client, variant, components...); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
			return reconcile.Result{}, err
		}
	} else {
		// Legacy mode: tear down serval if it was previously rendered. No images to resolve.
		components = append(components, serval.Serval(&serval.Configuration{Deleted: true}))
	}

	ch := utils.NewComponentHandler(logc, r.client, r.scheme, instance)
	for _, component := range components {
		if err = ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
			return reconcile.Result{}, err
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	return reconcile.Result{}, nil
}

// gatewayComponents builds the serval gateway components (cert management + serval). It returns
// a non-nil *reconcile.Result when the caller should return early (e.g. waiting on a keypair).
func (r *ReconcileNonClusterHost) gatewayComponents(ctx context.Context, installationSpec *operatorv1.InstallationSpec, endpointHost string, logc logr.Logger) ([]render.Component, *reconcile.Result, error) {
	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, logc)
		return nil, &reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, installationSpec, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the certificate manager", err, logc)
		return nil, &reconcile.Result{}, err
	}

	// The serving certificate covers the in-cluster service names plus the external endpoint
	// host that non-cluster hosts connect to.
	dnsNames := dns.GetServiceDNSNames(serval.ServalServiceName, serval.ServalNamespace, r.clusterDomain)
	dnsNames = append(dnsNames, endpointHost)
	keyPair, err := certificateManager.GetOrCreateKeyPair(r.client, serval.ServalKeyPairSecret, common.OperatorNamespace(), dnsNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, logc)
		return nil, &reconcile.Result{}, err
	}

	// Serval's in-process Typha reuses the non-cluster-host Typha keypair (CN
	// typha-server-noncluster-host), so a BYO cert carries across the switch from the legacy
	// Typha deployment to the embedded one. The core controller also creates this keypair;
	// GetOrCreateKeyPair returns the existing one.
	typhaKeyPair, err := certificateManager.GetOrCreateKeyPair(
		r.client, render.TyphaTLSSecretName+render.TyphaNonClusterHostSuffix, common.OperatorNamespace(),
		[]string{serval.TyphaServerCommonName})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating the Typha server certificate", err, logc)
		return nil, &reconcile.Result{}, err
	}

	trustedBundle, err := certificateManager.CreateNamedTrustedBundleFromSecrets(serval.ServalDeploymentName, r.client, common.OperatorNamespace(), false)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the trusted bundle", err, logc)
		return nil, &reconcile.Result{}, err
	}

	certComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       serval.ServalNamespace,
		TruthNamespace:  common.OperatorNamespace(),
		ServiceAccounts: []string{serval.ServalServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(keyPair, true, true),
			rcertificatemanagement.NewKeyPairOption(typhaKeyPair, true, true),
		},
		TrustedBundle: trustedBundle,
	})

	servalComponent := serval.Serval(&serval.Configuration{
		PullSecrets:        pullSecrets,
		OpenShift:          r.provider.IsOpenShift(),
		Installation:       installationSpec,
		TrustedCertBundle:  trustedBundle,
		ServerKeyPair:      keyPair,
		TyphaServerKeyPair: typhaKeyPair,
		ClusterDomain:      r.clusterDomain,
		K8sServiceEp:       k8sapi.Endpoint,
	})

	return []render.Component{certComponent, servalComponent}, nil, nil
}
