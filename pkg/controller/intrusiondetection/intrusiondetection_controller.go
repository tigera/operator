// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package intrusiondetection

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/tigera/operator/api/v1"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/logcollector"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_intrusiondetection")

// Add creates a new IntrusionDetection Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}

	var licenseAPIReady = &utils.ReadyFlag{}

	// create the reconciler
	reconciler := newReconciler(mgr, opts, licenseAPIReady)

	// Create a new controller
	controller, err := controller.New("intrusiondetection-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return fmt.Errorf("Failed to create intrusiondetection-controller: %v", err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(controller, k8sClient, log, licenseAPIReady)

	return add(mgr, controller)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions, licenseAPIReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileIntrusionDetection{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "intrusion-detection", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
	}
	r.status.Run()
	return r
}

// add adds watches for resources that are available at startup
func add(mgr manager.Manager, c controller.Controller) error {
	var err error

	// Watch for changes to primary resource IntrusionDetection
	err = c.Watch(&source.Kind{Type: &operatorv1.IntrusionDetection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch primary resource: %v", err)
	}

	err = c.Watch(&source.Kind{Type: &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Namespace: render.IntrusionDetectionNamespace,
		Name:      render.IntrusionDetectionInstallerJobName,
	}}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch installer job: %v", err)
	}

	// Watch for changes to to primary resource LogCollector, to determine if syslog forwarding is
	// turned on or off.
	err = c.Watch(&source.Kind{Type: &operatorv1.LogCollector{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch LogCollector resource: %v", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch Network resource: %v", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddAPIServerWatch(c); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch APIServer resource: %v", err)
	}

	for _, secretName := range []string{
		esgateway.EsGatewayElasticPublicCertSecret, render.ElasticsearchIntrusionDetectionUserSecret,
		render.ElasticsearchIntrusionDetectionJobUserSecret, render.ElasticsearchADJobUserSecret,
		esgateway.EsGatewayKibanaPublicCertSecret, render.ManagerInternalTLSSecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, rmeta.OperatorNamespace()); err != nil {
			return fmt.Errorf("intrusiondetection-controller failed to watch the Secret resource: %v", err)
		}
	}

	if err = utils.AddSecretsWatch(c, render.ManagerInternalTLSSecretName, render.IntrusionDetectionNamespace); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the Secret resource: %v", err)
	}

	if err = utils.AddSecretsWatch(c, esgateway.EsGatewayElasticPublicCertSecret, render.IntrusionDetectionNamespace); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the Secret resource: %v", err)
	}

	if err = utils.AddSecretsWatch(c, esgateway.EsGatewayKibanaPublicCertSecret, render.IntrusionDetectionNamespace); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the Secret resource: %v", err)
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, rmeta.OperatorNamespace()); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the ConfigMap resource: %v", err)
	}

	if err = utils.AddConfigMapWatch(c, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the ConfigMap resource: %v", err)
	}

	return nil
}

// blank assignment to verify that ReconcileIntrusionDetection implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileIntrusionDetection{}

// ReconcileIntrusionDetection reconciles a IntrusionDetection object
type ReconcileIntrusionDetection struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	licenseAPIReady *utils.ReadyFlag
}

// Reconcile reads that state of the cluster for a IntrusionDetection object and makes changes based on the state read
// and what is in the IntrusionDetection.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileIntrusionDetection) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling IntrusionDetection")

	// Fetch the IntrusionDetection instance
	instance := &operatorv1.IntrusionDetection{}
	err := r.client.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(3).Info("IntrusionDetection CR not found", "err", err)
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.V(3).Info("failed to get IntrusionDetection CR", "err", err)
		r.status.SetDegraded("Error querying IntrusionDetection", err.Error())
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded("Waiting for Tigera API server to be ready", "")
		return reconcile.Result{}, err
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded("Waiting for LicenseKeyAPI to be ready", "")
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("License not found", err.Error())
			return reconcile.Result{RequeueAfter: 10 * time.Second}, err
		}
		r.status.SetDegraded("Error querying license", err.Error())
		return reconcile.Result{RequeueAfter: 10 * time.Second}, err
	}

	// Query for the installation object.
	variant, network, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	// Query for pull secrets in operator namespace
	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		log.Error(err, "Error retrieving Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	// Query for the LogCollector instance. We need this to determine whether or not
	// to forward IDS event logs. Since this is optional, we don't need to degrade or
	// change status if LogCollector is not found.
	lc, err := logcollector.GetLogCollector(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("(optional) LogCollector object not found, proceed without it")
		}
	}

	esClusterConfig, err := utils.GetElasticsearchClusterConfig(context.Background(), r.client)
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

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		log.Error(err, "Failed to read ManagementClusterConnection")
		r.status.SetDegraded("Failed to read ManagementClusterConnection", err.Error())
		return reconcile.Result{}, err
	}

	secrets := []string{
		render.ElasticsearchIntrusionDetectionUserSecret,
		render.ElasticsearchADJobUserSecret,
	}

	if managementClusterConnection == nil {
		secrets = append(secrets, render.ElasticsearchIntrusionDetectionJobUserSecret)
	}

	esSecrets, err := utils.ElasticsearchSecrets(
		context.Background(),
		secrets,
		r.client,
	)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	kibanaPublicCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: esgateway.EsGatewayKibanaPublicCertSecret, Namespace: rmeta.OperatorNamespace()}, kibanaPublicCertSecret); err != nil {
		reqLogger.Error(err, "Failed to read Kibana public cert secret")
		r.status.SetDegraded("Failed to read Kibana public cert secret", err.Error())
		return reconcile.Result{}, err
	}

	var esLicenseType render.ElasticsearchLicenseType
	var managerInternalTLSSecret *corev1.Secret
	if managementClusterConnection == nil {
		if esLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, reqLogger); err != nil {
			r.status.SetDegraded("Failed to get Elasticsearch license", err.Error())
			return reconcile.Result{}, err
		}

		managerInternalTLSSecret, err = utils.ValidateCertPair(r.client,
			rmeta.OperatorNamespace(),
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

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	reqLogger.V(3).Info("rendering components")
	// Render the desired objects from the CRD and create or update them.
	var hasNoLicense = !utils.IsFeatureActive(license, common.ThreatDefenseFeature)
	component := render.IntrusionDetection(
		lc,
		esSecrets,
		kibanaPublicCertSecret,
		network,
		esClusterConfig,
		pullSecrets,
		r.provider == operatorv1.ProviderOpenShift,
		r.clusterDomain,
		esLicenseType,
		managementClusterConnection != nil,
		hasNoLicense,
		managerInternalTLSSecret,
	)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err := handler.CreateOrUpdateOrDelete(context.Background(), component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	if hasNoLicense {
		log.V(4).Info("IntrusionDetection is not activated as part of this license")
		r.status.SetDegraded("Feature is not active", "License does not support this feature")
		return reconcile.Result{}, nil
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
