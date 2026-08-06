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

	"github.com/go-logr/logr"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	if !opts.Variant.IsEnterprise() {
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
		{Name: otelcollector.OpenTelemetryCollectorPolicyName, Namespace: otelcollector.OpenTelemetryCollectorNamespace},
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
		ObjectMeta: metav1.ObjectMeta{Name: otelcollector.OpenTelemetryCollectorStatefulSetName, Namespace: otelcollector.OpenTelemetryCollectorNamespace},
	}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch StatefulSet: %w", controllerName, err)
	}

	if err = utils.AddConfigMapWatch(c, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch ConfigMap: %w", controllerName, err)
	}

	if err = utils.AddSecretsWatch(c, otelcollector.OpenTelemetryCollectorServerTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch the Secret resource(%s): %w", controllerName, otelcollector.OpenTelemetryCollectorServerTLSSecretName, err)
	}

	// The operator's CA rotates ahead of expiry; without this the collector would
	// keep verifying fluent-bit against a stale CA and silently reject every
	// connection until something else restarted it.
	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch the Secret resource(%s): %w", controllerName, certificatemanagement.CASecretName, err)
	}

	// User-supplied exporter TLS material: pick up creation, rotation and deletion.
	if err = utils.AddConfigMapWatch(c, otelcollector.OpenTelemetryCollectorCAConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch the ConfigMap resource(%s): %w", controllerName, otelcollector.OpenTelemetryCollectorCAConfigMapName, err)
	}

	if err = utils.AddSecretsWatch(c, otelcollector.OpenTelemetryCollectorClientTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch the Secret resource(%s): %w", controllerName, otelcollector.OpenTelemetryCollectorClientTLSSecretName, err)
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
	reqLogger.V(2).Info("Reconciling OpenTelemetry")

	logCollector, err := utils.GetIfExists[operatorv1.LogCollector](ctx, utils.DefaultEnterpriseInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying LogCollector CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if logCollector == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	if logCollector.Spec.OpenTelemetry == nil {
		// Nothing here is garbage-collected on its own — the resources are not
		// owned by a CR that gets deleted — so switching the feature off has to
		// remove them explicitly.
		if err := r.removeCollector(ctx, logCollector, reqLogger); err != nil {
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	r.status.OnCRFound()
	defer r.status.SetMetaData(&logCollector.ObjectMeta)

	installationSpec, err := utils.GetInstallationSpec(ctx, r.cli)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	} else if installationSpec == nil {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Installation to be available", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
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
	if !utils.IsFeatureActive(license, common.OpenTelemetryCollectorFeature) {
		// Definitive answer, so stop exporting. Losing the feature has to tear an
		// already-running collector down, otherwise a cluster that once had the
		// entitlement keeps forwarding after it lapses. Transient states above
		// (API not ready, license unreadable) deliberately do not tear down —
		// they requeue instead, so a blip cannot flap the collector.
		if err := r.removeCollector(ctx, logCollector, reqLogger); err != nil {
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	gracePeriod := utils.ParseGracePeriod(license.Status.GracePeriod)
	licenseStatus := utils.GetLicenseStatus(license, gracePeriod)
	var graceRequeueAfter time.Duration
	if licenseStatus == utils.LicenseStatusInGracePeriod {
		reqLogger.Info("License has expired and is within the grace period. Please renew your license to avoid service disruption.")
		graceRequeueAfter = time.Until(license.Status.Expiry.Add(gracePeriod))
	}

	// Reject specs the collector cannot start from, rather than rendering a config
	// it will reject at boot. Without this the pod crash-loops while TigeraStatus
	// sits on Progressing with nothing pointing at the cause.
	if err := validateOpenTelemetrySpec(logCollector.Spec.OpenTelemetry); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid OpenTelemetry configuration", err, reqLogger)
		return reconcile.Result{}, nil
	}

	if logCollector.Spec.OpenTelemetry.OpenTelemetryCollectorStatefulSet != nil {
		if err := validation.ValidateReplicatedPodResourceOverrides(
			logCollector.Spec.OpenTelemetry.OpenTelemetryCollectorStatefulSet,
			otelvalidation.ValidateOpenTelemetryCollectorStatefulSetContainer,
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

	if logCollector.Spec.OpenTelemetry.HasDataSources() {
		certMgr, err := certificatemanager.Create(r.cli, installationSpec, r.opts.ClusterDomain, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
			return reconcile.Result{}, err
		}

		trustedBundle = certMgr.CreateTrustedBundle()

		if logCollector.Spec.OpenTelemetry.HasLogs() {
			dnsNames := dns.GetServiceDNSNames(otelcollector.OpenTelemetryCollectorServiceName, otelcollector.OpenTelemetryCollectorNamespace, r.opts.ClusterDomain)
			receiverTLSSecret, err = certMgr.GetOrCreateKeyPair(r.cli, otelcollector.OpenTelemetryCollectorServerTLSSecretName, common.OperatorNamespace(), dnsNames)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating OpenTelemetry receiver TLS certificate", err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		certMgr.AddToStatusManager(r.status, otelcollector.OpenTelemetryCollectorNamespace)
	}

	// Optional user-supplied CA for exporter endpoints behind a private CA. It is
	// deliberately kept out of the trusted bundle: that bundle backs the receiver's
	// client_ca_file, so adding this CA there would make it a valid signer for
	// inbound client certificates. Absent means system roots alone, matching the
	// syslog-ca / splunk-ca convention.
	exporterCA := &corev1.ConfigMap{}
	if err := r.cli.Get(ctx, client.ObjectKey{
		Name:      otelcollector.OpenTelemetryCollectorCAConfigMapName,
		Namespace: common.OperatorNamespace(),
	}, exporterCA); err != nil {
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error reading ConfigMap %s", otelcollector.OpenTelemetryCollectorCAConfigMapName), err, reqLogger)
			return reconcile.Result{}, err
		}
		exporterCA = nil
	}
	// Its existence is the opt-in, so an empty one is a mistake rather than a
	// default. Catch it here: we would otherwise point ca_file at a path the
	// mount never materialises and the collector would fail to start.
	if exporterCA != nil && len(exporterCA.Data[corev1.TLSCertKey]) == 0 {
		r.status.SetDegraded(operatorv1.ResourceValidationError,
			fmt.Sprintf("ConfigMap %s must contain a %q key holding the exporter CA", otelcollector.OpenTelemetryCollectorCAConfigMapName, corev1.TLSCertKey), nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// The client keypair is required whenever an exporter opts into mutual TLS —
	// unlike the CA there is no sensible fallback, so a missing Secret degrades.
	var exporterClientTLS *corev1.Secret
	if exportersUseMutualTLS(logCollector.Spec.OpenTelemetry) {
		exporterClientTLS = &corev1.Secret{}
		if err := r.cli.Get(ctx, client.ObjectKey{
			Name:      otelcollector.OpenTelemetryCollectorClientTLSSecretName,
			Namespace: common.OperatorNamespace(),
		}, exporterClientTLS); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError,
				fmt.Sprintf("Waiting for Secret %s, required by exporters with mutualTLS enabled", otelcollector.OpenTelemetryCollectorClientTLSSecretName), err, reqLogger)
			return reconcile.Result{}, err
		}
		// Both halves must be present, for the same reason as the CA above.
		if len(exporterClientTLS.Data[corev1.TLSCertKey]) == 0 || len(exporterClientTLS.Data[corev1.TLSPrivateKeyKey]) == 0 {
			r.status.SetDegraded(operatorv1.ResourceValidationError,
				fmt.Sprintf("Secret %s must contain both %q and %q", otelcollector.OpenTelemetryCollectorClientTLSSecretName, corev1.TLSCertKey, corev1.TLSPrivateKeyKey), nil, reqLogger)
			return reconcile.Result{}, nil
		}
	}

	cfg := &otelcollector.Configuration{
		PullSecrets:       pullSecrets,
		OpenShift:         r.opts.DetectedProvider.IsOpenShift(),
		Installation:      installationSpec,
		OpenTelemetry:     logCollector.Spec.OpenTelemetry,
		ReceiverTLSSecret: receiverTLSSecret,
		TrustedCertBundle: trustedBundle,
		ExporterCA:        exporterCA,
		ExporterClientTLS: exporterClientTLS,
		// Naming an egress destination by domain requires this feature; without it
		// the exporter rules can only constrain the port.
		DomainEgressAllowed: utils.IsFeatureActive(license, common.EgressAccessControlFeature),
	}

	var keyPairOptions []rcertificatemanagement.KeyPairOption
	if receiverTLSSecret != nil {
		keyPairOptions = append(keyPairOptions, rcertificatemanagement.NewKeyPairOption(receiverTLSSecret, true, true))
	}

	otelComponent, err := otelcollector.OpenTelemetryCollector(cfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering OpenTelemetry collector config", err, reqLogger)
		return reconcile.Result{}, err
	}

	components := []render.Component{
		otelComponent,
	}
	if logCollector.Spec.OpenTelemetry.HasDataSources() {
		components = append(components, rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       otelcollector.OpenTelemetryCollectorNamespace,
			ServiceAccounts: []string{otelcollector.OpenTelemetryCollectorServiceAccountName},
			KeyPairOptions:  keyPairOptions,
			TrustedBundle:   trustedBundle,
		}))
	}

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, logCollector)
	if err = imageset.ApplyImageSet(ctx, r.cli, r.opts.Variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if licenseStatus == utils.LicenseStatusExpired {
		// Actually stop forwarding rather than only saying so: previously the
		// collector kept running and exporting after expiry, which contradicted
		// this message. Mirrors fluent-bit, whose DaemonSet is removed on expiry.
		if err := r.removeCollector(ctx, logCollector, reqLogger); err != nil {
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceValidationError,
			"License is expired - OpenTelemetry collector forwarding is stopped. Contact Tigera support or email licensing@tigera.io", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	return reconcile.Result{RequeueAfter: graceRequeueAfter}, nil
}

// removeCollector deletes every resource the collector component owns. It is used
// both when the feature is switched off and when the license expires.
func (r *Reconciler) removeCollector(ctx context.Context, logCollector *operatorv1.LogCollector, reqLogger logr.Logger) error {
	// Most clusters never enable this, and the disabled path runs on every
	// reconcile. Skip unless the workload is actually present, so we are not
	// issuing deletes for resources that have never existed.
	err := r.cli.Get(ctx, client.ObjectKey{
		Name:      otelcollector.OpenTelemetryCollectorStatefulSetName,
		Namespace: otelcollector.OpenTelemetryCollectorNamespace,
	}, &appsv1.StatefulSet{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error checking for an existing OpenTelemetry collector", err, reqLogger)
		return err
	}

	installationSpec, err := utils.GetInstallationSpec(ctx, r.cli)
	if err != nil || installationSpec == nil {
		// Without an Installation there is nothing to render from. Say so rather
		// than dropping the cleanup silently; the next reconcile retries.
		reqLogger.Info("Deferring OpenTelemetry collector cleanup until the Installation is available")
		return nil
	}
	comp, err := otelcollector.OpenTelemetryCollector(&otelcollector.Configuration{
		Installation:  installationSpec,
		OpenTelemetry: &operatorv1.OpenTelemetrySpec{},
		Disabled:      true,
	})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering OpenTelemetry collector for removal", err, reqLogger)
		return err
	}
	ch := utils.NewComponentHandler(log, r.cli, r.scheme, logCollector)
	if err := ch.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error removing OpenTelemetry collector resources", err, reqLogger)
		return err
	}
	return nil
}

// validateOpenTelemetrySpec rejects the two specs that render a config the
// collector refuses to start from. Both are validated by otelcol itself
// (service/pipelines/config.go: "service must have at least one pipeline" and
// "must have at least one exporter"), but it only finds out at boot, by which
// point the failure is an opaque crash-loop.
func validateOpenTelemetrySpec(spec *operatorv1.OpenTelemetrySpec) error {
	// Every pipeline we render fans out to all exporters, so with none configured
	// each pipeline would be exporter-less.
	if len(spec.Exporters) == 0 {
		return fmt.Errorf("at least one exporter must be configured in spec.openTelemetry.exporters")
	}
	// No log types and no metrics means no pipelines at all.
	if !spec.HasDataSources() {
		return fmt.Errorf("at least one data source must be enabled: set spec.openTelemetry.logs.types or spec.openTelemetry.metrics.enabled")
	}
	// Names key the exporters in the rendered config, so duplicates would emit the
	// same mapping key twice. +listMapKey=name normally stops this at the API
	// server; this guards the case where the CRD is out of date.
	seen := make(map[string]struct{}, len(spec.Exporters))
	for _, exp := range spec.Exporters {
		if _, dup := seen[exp.Name]; dup {
			return fmt.Errorf("exporter names must be unique in spec.openTelemetry.exporters: %q is duplicated", exp.Name)
		}
		seen[exp.Name] = struct{}{}
	}
	return nil
}

// exportersUseMutualTLS reports whether any exporter opts into presenting a
// client certificate, which makes the client keypair Secret mandatory.
func exportersUseMutualTLS(spec *operatorv1.OpenTelemetrySpec) bool {
	for _, exp := range spec.Exporters {
		if exp.MutualTLS != nil && *exp.MutualTLS {
			return true
		}
	}
	return false
}
