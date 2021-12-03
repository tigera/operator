// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package monitor

import (
	"context"
	_ "embed"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/monitor"
)

var log = logf.Log.WithName("controller_monitor")

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	var prometheusReady = &utils.ReadyFlag{}

	// Create the reconciler
	reconciler := newReconciler(mgr, opts, prometheusReady)

	// Create a new controller
	controller, err := controller.New("monitor-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create monitor-controller: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	go waitToAddPrometheusWatch(controller, k8sClient, log, prometheusReady)

	return add(mgr, controller)
}

func newReconciler(mgr manager.Manager, opts options.AddOptions, prometheusReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileMonitor{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "monitor", opts.KubernetesVersion),
		prometheusReady: prometheusReady,
		clusterDomain:   opts.ClusterDomain,
	}

	r.status.AddStatefulSets([]types.NamespacedName{
		{Namespace: common.TigeraPrometheusNamespace, Name: fmt.Sprintf("alertmanager-%s", monitor.CalicoNodeAlertmanager)},
		{Namespace: common.TigeraPrometheusNamespace, Name: fmt.Sprintf("prometheus-%s", monitor.CalicoNodePrometheus)},
	})

	r.status.Run(opts.ShutdownContext)
	return r
}

func add(mgr manager.Manager, c controller.Controller) error {
	var err error

	// watch for primary resource changes
	if err = c.Watch(&source.Kind{Type: &operatorv1.Monitor{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("monitor-controller failed to watch primary resource: %w", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("monitor-controller failed to watch Installation resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("monitor-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddSecretsWatch(c, monitor.PrometheusTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("monitor-controller failed to watch secret: %w", err)
	}

	err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("monitor-controller failed to watch resource: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileMonitor implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileMonitor{}

type ReconcileMonitor struct {
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	prometheusReady *utils.ReadyFlag
	clusterDomain   string
}

func (r *ReconcileMonitor) getMonitor(ctx context.Context) (*operatorv1.Monitor, error) {
	instance := &operatorv1.Monitor{}
	err := r.client.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (r *ReconcileMonitor) setDegraded(reqLogger logr.Logger, err error, msg string) {
	reqLogger.Error(err, msg)
	r.status.SetDegraded(msg, err.Error())
}

func (r *ReconcileMonitor) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Monitor")

	instance, err := r.getMonitor(ctx)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.setDegraded(reqLogger, err, "Failed to query Monitor")
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	variant, install, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.setDegraded(reqLogger, err, "Installation not found")
			return reconcile.Result{}, err
		}
		r.setDegraded(reqLogger, err, "Failed to query Installation")
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(install, r.client)
	if err != nil {
		r.setDegraded(reqLogger, err, "Error retrieving pull secrets")
		return reconcile.Result{}, err
	}

	if !r.prometheusReady.IsReady() {
		err = fmt.Errorf("waiting for Prometheus resources")
		r.setDegraded(reqLogger, err, "Waiting for Prometheus resources to be ready")
		return reconcile.Result{}, err
	}

	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("No ConfigMap found, a default one will be created.")
		} else {
			r.setDegraded(reqLogger, err, "Internal error attempting to retrieve ConfigMap")
			return reconcile.Result{}, err
		}
	}

	var tlsSecret *corev1.Secret
	if install.CertificateManagement == nil {
		// Check that if the apiserver cert pair secret exists that it is valid (has key and cert fields)
		// If it does not exist then this function still returns true
		tlsSecret, err = utils.ValidateCertPair(r.client,
			common.OperatorNamespace(),
			monitor.PrometheusTLSSecretName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
		)
		if err != nil {
			log.Error(err, "Invalid TLS Cert")
			r.status.SetDegraded("Error validating TLS certificate", err.Error())
			return reconcile.Result{}, err
		}

		if tlsSecret == nil {
			svcDNSNames := dns.GetServiceDNSNames(monitor.PrometheusHTTPAPIServiceName, common.TigeraPrometheusNamespace, r.clusterDomain)
			tlsSecret, err = rsecret.CreateTLSSecret(nil,
				monitor.PrometheusTLSSecretName,
				common.OperatorNamespace(),
				corev1.TLSPrivateKeyKey,
				corev1.TLSCertKey,
				rmeta.DefaultCertificateDuration,
				nil,
				svcDNSNames...,
			)
			if err != nil {
				log.Error(err, "Error creating TLS certificate")
				r.status.SetDegraded("Error creating TLS certificate", err.Error())
				return reconcile.Result{}, err
			}
		}

		r.status.RemoveCertificateSigningRequests(common.TigeraPrometheusNamespace)
	} else {
		// Monitor pending CSRs for the TigeraStatus
		r.status.AddCertificateSigningRequests(common.TigeraPrometheusNamespace, map[string]string{"k8s-app": common.TigeraPrometheusNamespace})
	}

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded("Error querying Authentication", err.Error())
		return reconcile.Result{}, err
	}
	if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded("Authentication is not ready", fmt.Sprintf("authenticationCR status: %s", authenticationCR.Status.State))
		return reconcile.Result{}, nil
	}

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain)
	if err != nil {
		log.Error(err, "Failed to process the authentication CR.")
		r.status.SetDegraded("Failed to process the authentication CR.", err.Error())
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	hdler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	alertmanagerConfigSecret, createInOperatorNamespace, err := r.readAlertmanagerConfigSecret(ctx)
	if err != nil {
		r.setDegraded(reqLogger, err, "Error retrieving Alertmanager configuration secret")
		return reconcile.Result{}, err
	}

	components := []render.Component{render.NewPassthrough([]client.Object{tlsSecret})}
	if createInOperatorNamespace {
		components = append(components, render.NewPassthrough([]client.Object{alertmanagerConfigSecret, tlsSecret}))
	}
	// Render prometheus component
	components = append(components, monitor.Monitor(
		install,
		pullSecrets,
		alertmanagerConfigSecret,
		tlsSecret,
		r.clusterDomain,
		keyValidatorConfig,
	))

	if err = imageset.ApplyImageSet(ctx, r.client, variant, components...); err != nil {
		r.setDegraded(reqLogger, err, "Error with images from ImageSet")
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.setDegraded(reqLogger, err, "Error creating / updating resource")
			return reconcile.Result{}, err
		}
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	instance.Status.State = operatorv1.TigeraStatusReady
	if err := r.client.Status().Update(ctx, instance); err != nil {
		r.setDegraded(reqLogger, err, fmt.Sprintf("Error updating the monitor status %s", operatorv1.TigeraStatusReady))
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

//go:embed alertmanager-config.yaml
var alertmanagerConfig string

// readAlertmanagerConfigSecret attempts to retrieve Alertmanager configuration secret from either the Tigera Operator
// namespace or the Tigera Prometheus namespace. If it doesn't exist in either of the namespace, a new default configuration
// secret will be created.
func (r *ReconcileMonitor) readAlertmanagerConfigSecret(ctx context.Context) (*corev1.Secret, bool, error) {
	// Previous to this change, a customer was expected to deploy the Alertmanager configuration secret
	// in the tigera-prometheus namespace directly. Now that this secret is managed by the Operator,
	// the customer must deploy this secret in the tigera-operator namespace. The Operator then copies
	// the secret from the tigera-operator namespace to the tigera-prometheus namespace.
	//
	// For new installation:
	//   A new secret will be created in the tigera-operator namespace and then copied to the tigera-prometheus namespace.
	//   Monitor controller holds the ownership of this secret.
	//
	// To handle upgrades:
	//   The tigera-prometheus secret will be copied back to the tigera-operator namespace.
	//   If this secret is modified by the user, Monitor controller won't set the ownership. Otherwise, it is owned by the Monitor.
	//
	// Tigera Operator will then watch for secret changes in the tigera-operator namespace and overwrite
	// any changes for this secret in the tigera-prometheus namespace. For future Alertmanager configuration changes,
	// Monitor controller can verify the owner reference of the configuration secret and decide if we want to
	// upgrade it automatically.

	defaultConfigSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.AlertmanagerConfigSecret,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string][]byte{
			"alertmanager.yaml": []byte(alertmanagerConfig),
		},
	}

	// Read Alertmanager configuration secret as-is if it is found in the tigera-operator namespace.
	secret, err := utils.GetSecret(ctx, r.client, monitor.AlertmanagerConfigSecret, common.OperatorNamespace())
	if err != nil {
		return nil, false, err
	} else if secret != nil {
		return secret, false, nil
	}

	// When Alertmanager configuration isn't found in the tigera-operator namespace, copy it from the tigera-prometheus namespace (upgrade).
	// If it is modified by the user, Monitor controller will not set the owner reference.
	secret, err = utils.GetSecret(ctx, r.client, monitor.AlertmanagerConfigSecret, common.TigeraPrometheusNamespace)
	if err != nil {
		return nil, false, err
	} else if secret != nil {
		// Monitor controller will own the secret if it is the same.
		if reflect.DeepEqual(defaultConfigSecret.Data, secret.Data) {
			return rsecret.CopyToNamespace(common.OperatorNamespace(), secret)[0], true, nil
		}

		// If the secret isn't the same, leave it unmanaged.
		s := rsecret.CopyToNamespace(common.OperatorNamespace(), secret)[0]
		if err := r.client.Create(ctx, s); err != nil {
			return nil, false, err
		}
		return s, false, nil
	}

	// Alertmanager configuration secret is not found in the tigera-operator or tigera-prometheus namespace (new install).
	// Operator should create a new default secret and set the owner reference.
	return defaultConfigSecret, true, nil
}
