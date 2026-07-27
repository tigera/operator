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

package otelcollector

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/common/validation"
	otelvalidation "github.com/tigera/operator/pkg/common/validation/otelcollector"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/otelcollector"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	controllerName = "log-collector-otel-controller"
	ResourceName   = "log-collector-otel"
)

var log = logf.Log.WithName(controllerName)

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	licenseAPIReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}

	statusManager := status.New(mgr.GetClient(), ResourceName, opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts, licenseAPIReady, tierWatchReady)

	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	go utils.WaitToAddLicenseKeyWatch(c, opts.K8sClientset, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: otelcollector.OTelCollectorPolicyName, Namespace: otelcollector.OTelCollectorNamespace},
	})

	if err = c.WatchObject(&operatorv1.LogCollector{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	if err = utils.AddAPIServerWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch APIServer resource: %w", controllerName, err)
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

	// Watch the workload and ConfigMap so out-of-band edits/deletes trigger reconcile.
	if err = utils.AddNamespacedWatch(c, &appsv1.StatefulSet{
		TypeMeta:   metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: otelcollector.OTelCollectorStatefulSetName, Namespace: otelcollector.OTelCollectorNamespace},
	}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch StatefulSet: %w", controllerName, err)
	}

	if err = utils.AddConfigMapWatch(c, otelcollector.OTelCollectorConfigMapName, otelcollector.OTelCollectorNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch ConfigMap: %w", controllerName, err)
	}

	if err = utils.AddSecretsWatch(c, otelcollector.OTelCollectorServerTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch the Secret resource(%s): %w", controllerName, otelcollector.OTelCollectorServerTLSSecretName, err)
	}

	return nil
}

func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	opts options.ControllerOptions,
	licenseAPIReady *utils.ReadyFlag,
	tierWatchReady *utils.ReadyFlag,
) *Reconciler {
	r := &Reconciler{
		cli:             cli,
		scheme:          schema,
		status:          statusMgr,
		opts:            opts,
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	cli             client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	opts            options.ControllerOptions
	licenseAPIReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
}

func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling OTelCollector")

	logCollector, err := utils.GetIfExists[operatorv1.LogCollector](ctx, utils.DefaultEnterpriseInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying LogCollector CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if logCollector == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	if logCollector.Spec.OTelCollector == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	r.status.OnCRFound()
	defer r.status.SetMetaData(&logCollector.ObjectMeta)

	variant, installationSpec, err := utils.GetInstallationSpec(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	} else if installationSpec == nil {
		return reconcile.Result{}, nil
	}

	if !utils.IsProjectCalicoV3Available(r.cli, r.opts, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	if err := r.cli.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Error querying calico-system tier", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.cli)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}
	if !utils.IsFeatureActive(license, common.OTelCollectorFeature) {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	gracePeriod := utils.ParseGracePeriod(license.Status.GracePeriod)
	licenseStatus := utils.GetLicenseStatus(license, gracePeriod)
	licenseExpired := licenseStatus == utils.LicenseStatusExpired

	var graceRequeueAfter time.Duration
	if licenseStatus == utils.LicenseStatusInGracePeriod {
		reqLogger.Info("License has expired and is within the grace period. Please renew your license to avoid service disruption.")
		graceRequeueAfter = time.Until(license.Status.Expiry.Add(gracePeriod))
	}

	if logCollector.Spec.OTelCollector.OTelCollectorStatefulSet != nil {
		if err := validation.ValidateReplicatedPodResourceOverrides(
			logCollector.Spec.OTelCollector.OTelCollectorStatefulSet,
			otelvalidation.ValidateOTelCollectorStatefulSetContainer,
			validation.NoContainersDefined,
		); err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid statefulSet overrides", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	var receiverTLSSecret certificatemanagement.KeyPairInterface
	var trustedBundle certificatemanagement.TrustedBundle

	hasLogs := logCollector.Spec.OTelCollector.Logs != nil && len(logCollector.Spec.OTelCollector.Logs.Types) > 0
	metricsEnabled := logCollector.Spec.OTelCollector.Metrics != nil &&
		logCollector.Spec.OTelCollector.Metrics.Enabled != nil &&
		*logCollector.Spec.OTelCollector.Metrics.Enabled == operatorv1.OTelMetricsEnable

	if hasLogs || metricsEnabled {
		certMgr, err := certificatemanager.Create(r.cli, installationSpec, r.opts.ClusterDomain, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
			return reconcile.Result{}, err
		}

		trustedBundle = certMgr.CreateTrustedBundle()

		if hasLogs {
			dnsNames := dns.GetServiceDNSNames(otelcollector.OTelCollectorServiceName, otelcollector.OTelCollectorNamespace, r.opts.ClusterDomain)
			receiverTLSSecret, err = certMgr.GetOrCreateKeyPair(r.cli, otelcollector.OTelCollectorServerTLSSecretName, common.OperatorNamespace(), dnsNames)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating OTel receiver TLS certificate", err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		certMgr.AddToStatusManager(r.status, otelcollector.OTelCollectorNamespace)
	}

	cfg := &otelcollector.Configuration{
		PullSecrets:       pullSecrets,
		OpenShift:         r.opts.DetectedProvider.IsOpenShift(),
		Installation:      installationSpec,
		OTelCollector:     logCollector.Spec.OTelCollector,
		ReceiverTLSSecret: receiverTLSSecret,
		TrustedCertBundle: trustedBundle,
	}

	var keyPairOptions []rcertificatemanagement.KeyPairOption
	if receiverTLSSecret != nil {
		keyPairOptions = append(keyPairOptions, rcertificatemanagement.NewKeyPairOption(receiverTLSSecret, true, true))
	}

	otelComponent, err := otelcollector.OTelCollector(cfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering OTel collector config", err, reqLogger)
		return reconcile.Result{}, err
	}

	components := []render.Component{
		otelComponent,
	}
	if len(keyPairOptions) > 0 || trustedBundle != nil {
		components = append(components, rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       otelcollector.OTelCollectorNamespace,
			ServiceAccounts: []string{otelcollector.OTelCollectorServiceAccountName},
			KeyPairOptions:  keyPairOptions,
			TrustedBundle:   trustedBundle,
		}))
	}

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, logCollector)
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

	if licenseExpired {
		r.status.SetDegraded(operatorv1.ResourceValidationError,
			"License is expired - OTel collector forwarding is stopped. Contact Tigera support or email licensing@tigera.io", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	return reconcile.Result{RequeueAfter: graceRequeueAfter}, nil
}
