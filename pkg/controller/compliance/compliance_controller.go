// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package compliance

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_compliance")

// Add creates a new Compliance Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	return add(mgr, newReconciler(mgr, opts.DetectedProvider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operatorv1.Provider) reconcile.Reconciler {
	r := &ReconcileCompliance{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: provider,
		status:   status.New(mgr.GetClient(), "compliance"),
	}
	r.status.Run()
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("compliance-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Compliance
	err = c.Watch(&source.Kind{Type: &operatorv1.Compliance{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("compliance-controller failed to watch Network resource: %w", err)
	}

	if err = utils.AddAPIServerWatch(c); err != nil {
		return fmt.Errorf("compliance-controller failed to watch APIServer resource: %w", err)
	}

	// Watch the given secrets in each both the compliance and operator namespaces
	for _, namespace := range []string{render.OperatorNamespace(), render.ComplianceNamespace} {
		for _, secretName := range []string{
			render.ElasticsearchPublicCertSecret, render.ElasticsearchComplianceBenchmarkerUserSecret,
			render.ElasticsearchComplianceControllerUserSecret, render.ElasticsearchComplianceReporterUserSecret,
			render.ElasticsearchComplianceSnapshotterUserSecret, render.ElasticsearchComplianceServerUserSecret,
			render.ComplianceServerCertSecret, render.ManagerInternalTLSSecretName, render.DexTLSSecretName} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("compliance-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	if err = utils.AddConfigMapWatch(c, render.ElasticsearchConfigMapName, render.OperatorNamespace()); err != nil {
		return fmt.Errorf("compliance-controller failed to watch the ConfigMap resource: %w", err)
	}

	// Watch for changes to primary resource ManagementCluster
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("compliance-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("compliance-controller failed to watch primary resource: %w", err)
	}

	err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("compliance-controller failed to watch resource: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileCompliance implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileCompliance{}

// ReconcileCompliance reconciles a Compliance object
type ReconcileCompliance struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	provider operatorv1.Provider
	status   status.StatusManager
}

func GetCompliance(ctx context.Context, cli client.Client) (*operatorv1.Compliance, error) {
	instance := &operatorv1.Compliance{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// Reconcile reads that state of the cluster for a Compliance object and makes changes based on the state read
// and what is in the Compliance.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileCompliance) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Compliance")

	ctx := context.Background()

	// Fetch the Compliance instance
	instance, err := GetCompliance(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("Compliance config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying compliance", err.Error())
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded("Waiting for Tigera API server to be ready", "")
		return reconcile.Result{}, err
	}

	if err = utils.CheckLicenseKey(ctx, r.client); err != nil {
		r.status.SetDegraded("License not found", err.Error())
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Query for the installation object.
	network, err := installation.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		log.Error(err, "Failed to retrieve pull secrets")
		r.status.SetDegraded("Failed to retrieve pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	esClusterConfig, err := utils.GetElasticsearchClusterConfig(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch cluster configuration is not available, waiting for it to become available")
			r.status.SetDegraded("Elasticsearch cluster configuration is not available, waiting for it to become available", err.Error())
			return reconcile.Result{}, nil
		}
		log.Error(err, "Failed to get the elasticsearch cluster configuration")
		r.status.SetDegraded("Failed to get the elasticsearch cluster configuration", err.Error())
		return reconcile.Result{}, err
	}

	secretsToWatch := []string{
		render.ElasticsearchComplianceBenchmarkerUserSecret, render.ElasticsearchComplianceControllerUserSecret,
		render.ElasticsearchComplianceReporterUserSecret, render.ElasticsearchComplianceSnapshotterUserSecret,
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		log.Error(err, "Error reading ManagementCluster")
		r.status.SetDegraded("Error reading ManagementCluster", err.Error())
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		log.Error(err, "Error reading ManagementClusterConnection")
		r.status.SetDegraded("Error reading ManagementClusterConnection", err.Error())
		return reconcile.Result{}, err
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		log.Error(err, "")
		r.status.SetDegraded(err.Error(), "")
		return reconcile.Result{}, err
	}

	// Compliance server is only for Standalone or Management clusters
	if managementClusterConnection == nil {
		secretsToWatch = append(secretsToWatch, render.ElasticsearchComplianceServerUserSecret)
	}

	esSecrets, err := utils.ElasticsearchSecrets(ctx, secretsToWatch, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	var managerInternalTLSSecret *corev1.Secret
	if managementCluster != nil {
		managerInternalTLSSecret, err = utils.ValidateCertPair(r.client,
			render.ManagerInternalTLSSecretName,
			render.ManagerInternalSecretCertName,
			render.ManagerInternalSecretKeyName,
		)
		if err != nil {
			log.Error(err, fmt.Sprintf("failed to retrieve / validate %s", render.ManagerInternalSecretCertName))
			r.status.SetDegraded(fmt.Sprintf("failed to retrieve / validate  %s", render.ManagerInternalSecretKeyName), err.Error())
			return reconcile.Result{}, err
		}
	}

	complianceServerCertSecret, err := utils.ValidateCertPair(r.client,
		render.ComplianceServerCertSecret,
		render.ComplianceServerCertName,
		render.ComplianceServerKeyName,
	)
	if err != nil {
		log.Error(err, fmt.Sprintf("failed to retrieve / validate %s", render.ComplianceServerCertSecret))
		r.status.SetDegraded(fmt.Sprintf("failed to retrieve / validate  %s", render.ComplianceServerCertSecret), err.Error())
		return reconcile.Result{}, err
	}

	// Fetch the Authentication spec. If present, we use it to configure dex as an authentication proxy.
	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded("Error querying Authentication", err.Error())
		return reconcile.Result{}, err
	}
	if authentication != nil && authentication.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded("Authentication is not ready", fmt.Sprintf("authentication status: %s", authentication.Status.State))
		return reconcile.Result{}, nil
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	var dexCfg render.DexKeyValidatorConfig
	if authentication != nil {
		dexTLSSecret := &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexTLSSecretName, Namespace: render.OperatorNamespace()}, dexTLSSecret); err != nil {
			r.status.SetDegraded("Failed to read dex tls secret", err.Error())
			return reconcile.Result{}, err
		}
		dexCfg = render.NewDexKeyValidatorConfig(authentication, dexTLSSecret)
	}

	reqLogger.V(3).Info("rendering components")
	openshift := r.provider == operatorv1.ProviderOpenShift
	// Render the desired objects from the CRD and create or update them.
	component, err := render.Compliance(esSecrets, managerInternalTLSSecret, &network.Spec, complianceServerCertSecret, esClusterConfig, pullSecrets, openshift, managementCluster, managementClusterConnection, dexCfg)
	if err != nil {
		log.Error(err, "error rendering Compliance")
		r.status.SetDegraded("Error rendering Compliance", err.Error())
		return reconcile.Result{}, err
	}

	if err := handler.CreateOrUpdate(ctx, component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CRD status.
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
