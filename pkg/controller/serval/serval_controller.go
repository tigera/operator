// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package serval

import (
	"context"
	"fmt"

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
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/serval"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

const (
	controllerName = "serval-controller"
	ResourceName   = "serval"
)

var log = logf.Log.WithName(controllerName)

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	statusManager := status.New(mgr.GetClient(), ResourceName, opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts)

	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	if err = c.WatchObject(&operatorv1.Serval{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	for _, secretName := range []string{serval.ServalKeyPairSecret, certificatemanagement.CASecretName} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("failed to add watch for secret %s/%s: %w", common.OperatorNamespace(), secretName, err)
		}
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("%s failed to watch TigeraStatus: %w", controllerName, err)
	}

	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to create periodic reconcile watch: %w", controllerName, err)
	}

	return nil
}

func newReconciler(cli client.Client, scheme *runtime.Scheme, statusMgr status.StatusManager, opts options.ControllerOptions) *Reconciler {
	r := &Reconciler{
		cli:           cli,
		scheme:        scheme,
		provider:      opts.DetectedProvider,
		status:        statusMgr,
		clusterDomain: opts.ClusterDomain,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	cli           client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
}

func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	logc.Info("Reconciling Serval")

	instance, err := utils.GetIfExists[operatorv1.Serval](ctx, utils.DefaultEnterpriseInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query Serval resource", err, logc)
		return reconcile.Result{}, err
	} else if instance == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}
	r.status.OnCRFound()
	defer r.status.SetMetaData(&instance.ObjectMeta)

	endpointHost, _, _, err := url.ParseEndpoint(instance.Spec.Endpoint)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid endpoint", err, logc)
		return reconcile.Result{}, err
	}

	variant, installationSpec, err := utils.GetInstallationSpec(ctx, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query Installation", err, logc)
		return reconcile.Result{}, err
	} else if installationSpec == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", nil, logc)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, logc)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.cli, installationSpec, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the certificate manager", err, logc)
		return reconcile.Result{}, err
	}

	// The serving certificate covers the in-cluster service names plus the
	// external endpoint host that non-cluster hosts connect to.
	dnsNames := dns.GetServiceDNSNames(serval.ServalServiceName, serval.ServalNamespace, r.clusterDomain)
	dnsNames = append(dnsNames, endpointHost)
	keyPair, err := certificateManager.GetOrCreateKeyPair(r.cli, serval.ServalKeyPairSecret, common.OperatorNamespace(), dnsNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, logc)
		return reconcile.Result{}, err
	}

	trustedBundle, err := certificateManager.CreateNamedTrustedBundleFromSecrets(serval.ServalDeploymentName, r.cli, common.OperatorNamespace(), false)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the trusted bundle", err, logc)
		return reconcile.Result{}, err
	}

	certComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       serval.ServalNamespace,
		TruthNamespace:  common.OperatorNamespace(),
		ServiceAccounts: []string{serval.ServalServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(keyPair, true, true),
		},
		TrustedBundle: trustedBundle,
	})

	cfg := &serval.Configuration{
		PullSecrets:       pullSecrets,
		OpenShift:         r.provider.IsOpenShift(),
		Installation:      installationSpec,
		TrustedCertBundle: trustedBundle,
		ServerKeyPair:     keyPair,
		Serval:            instance,
		ClusterDomain:     r.clusterDomain,
	}

	components := []render.Component{certComponent, serval.Serval(cfg)}
	if err = imageset.ApplyImageSet(ctx, r.cli, variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
		return reconcile.Result{}, err
	}

	ch := utils.NewComponentHandler(logc, r.cli, r.scheme, instance)
	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
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
