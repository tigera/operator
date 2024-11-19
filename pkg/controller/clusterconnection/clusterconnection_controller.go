// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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

package clusterconnection

import (
	"context"
	"fmt"

	"golang.org/x/net/http/httpproxy"
	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	controllerName = "clusterconnection-controller"
	ResourceName   = "management-cluster-connection"
)

var log = logf.Log.WithName(controllerName)

// Add creates a new ManagementClusterConnection Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started. This controller is meant only for enterprise users.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	statusManager := status.New(mgr.GetClient(), "management-cluster-connection", opts.KubernetesVersion)

	// Create the reconciler
	tierWatchReady := &utils.ReadyFlag{}
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, tierWatchReady, opts)

	// Create a new controller
	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	// Watch for changes to License and Tier, as their status is used as input to determine whether network policy should be reconciled by this controller.
	go utils.WaitToAddLicenseKeyWatch(c, k8sClient, log, nil)
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, tierWatchReady)

	go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, []types.NamespacedName{
		{Name: render.GuardianPolicyName, Namespace: render.GuardianNamespace},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.GuardianNamespace},
	})

	for _, secretName := range []string{
		render.PacketCaptureServerCert,
		monitor.PrometheusServerTLSSecretName,
		render.ProjectCalicoAPIServerTLSSecretName(operatorv1.TigeraSecureEnterprise),
		render.ProjectCalicoAPIServerTLSSecretName(operatorv1.Calico),
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("failed to add watch for secret %s/%s: %w", common.OperatorNamespace(), secretName, err)
		}
	}

	return add(mgr, c)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	p operatorv1.Provider,
	tierWatchReady *utils.ReadyFlag,
	opts options.AddOptions,
) *ReconcileConnection {
	c := &ReconcileConnection{
		Client:         cli,
		Scheme:         schema,
		Provider:       p,
		status:         statusMgr,
		clusterDomain:  opts.ClusterDomain,
		tierWatchReady: tierWatchReady,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// add adds a new controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, c ctrlruntime.Controller) error {
	// Watch for changes to primary resource ManagementCluster
	err := c.WatchObject(&operatorv1.ManagementCluster{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	// Watch for changes to the secrets associated with the ManagementClusterConnection.
	if err = utils.AddSecretsWatch(c, render.GuardianSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.GuardianSecretName, err)
	}

	// Watch for changes to the secrets associated with the PacketCapture APIs.
	if err = utils.AddSecretsWatch(c, render.PacketCaptureServerCert, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.PacketCaptureServerCert, err)
	}
	// Watch for changes to the secrets associated with Prometheus.
	if err = utils.AddSecretsWatch(c, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, monitor.PrometheusServerTLSSecretName, err)
	}

	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, certificatemanagement.CASecretName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	if err := utils.AddDeploymentWatch(c, render.GuardianDeploymentName, render.GuardianNamespace); err != nil {
		return fmt.Errorf("%s failed to watch Guardian deployment: %w", controllerName, err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("clusterconnection-controller failed to watch management-cluster-connection Tigerastatus: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileConnection{}

// ReconcileConnection reconciles a ManagementClusterConnection object
type ReconcileConnection struct {
	Client                     client.Client
	Scheme                     *runtime.Scheme
	Provider                   operatorv1.Provider
	status                     status.StatusManager
	clusterDomain              string
	tierWatchReady             *utils.ReadyFlag
	resolvedPodProxies         []*httpproxy.Config
	lastAvailabilityTransition metav1.Time
}

// Reconcile reads that state of the cluster for a ManagementClusterConnection object and makes changes based on the
// state read and what is in the ManagementClusterConnection.Spec. The Controller will requeue the Request to be
// processed again if the returned error is non-nil or Result.Requeue is true, otherwise upon completion it will
// remove the work from the queue.
func (r *ReconcileConnection) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling the management cluster connection")
	result := reconcile.Result{}

	variant, instl, err := utils.GetInstallation(ctx, r.Client)
	if err != nil {
		return result, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.Client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch the managementClusterConnection.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.Client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying ManagementClusterConnection", err, reqLogger)
		return result, err
	} else if managementClusterConnection == nil {
		r.status.OnCRNotFound()
		return result, nil
	}
	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&managementClusterConnection.ObjectMeta)

	// Changes for updating ManagementClusterConnection status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.Client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		managementClusterConnection.Status.Conditions = status.UpdateStatusCondition(managementClusterConnection.Status.Conditions, ts.Status.Conditions)
		if err := r.Client.Status().Update(ctx, managementClusterConnection); err != nil {
			log.WithValues("reason", err).Info("Failed to create ManagementClusterConnection status conditions.")
			return reconcile.Result{}, err
		}
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, err
	}

	preDefaultPatchFrom := client.MergeFrom(managementClusterConnection.DeepCopy())
	fillDefaults(managementClusterConnection)

	// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
	// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
	if err := r.Client.Patch(ctx, managementClusterConnection, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, err.Error(), err, reqLogger)
		return reconcile.Result{}, err
	}

	log.V(2).Info("Loaded ManagementClusterConnection config", "config", managementClusterConnection)

	pullSecrets, err := utils.GetNetworkingPullSecrets(instl, r.Client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return result, err
	}

	certificateManager, err := certificatemanager.Create(r.Client, instl, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Copy the secret from the operator namespace to the guardian namespace if it is present.
	tunnelSecret := &corev1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()}, tunnelSecret)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving secrets from guardian namespace", err, reqLogger)
		if !k8serrors.IsNotFound(err) {
			return result, nil
		}
		return result, err
	}

	var trustedCertBundle certificatemanagement.TrustedBundle
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

	secretsToTrust := []string{render.ProjectCalicoAPIServerTLSSecretName(instl.Variant)}

	// Add the packet capture certificate if it exists; otherwise, skip for now. The operator will reconcile the certificate once available.
	s, err := utils.GetSecret(ctx, r.Client, render.PacketCaptureServerCert, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying secret for PacketCapture certificate", err, reqLogger)
		return reconcile.Result{}, err
	}
	if s != nil {
		secretsToTrust = append(secretsToTrust, render.PacketCaptureServerCert)
	}

	// If external prometheus is enabled, the secret will be signed by the Calico CA and won't get rendered. We can skip
	// adding it to the bundle, as trusting the CA will suffice.
	monitorCR := &operatorv1.Monitor{}
	if err := r.Client.Get(ctx, utils.DefaultTSEEInstanceKey, monitorCR); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying required Monitor resource: ", err, reqLogger)
		return reconcile.Result{}, err
	}
	if monitorCR.Spec.ExternalPrometheus == nil {
		secretsToTrust = append(secretsToTrust, monitor.PrometheusServerTLSSecretName)
	}

	for _, secretName := range secretsToTrust {
		secret, err := certificateManager.GetCertificate(r.Client, secretName, common.OperatorNamespace())
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

	// Determine the current deployment availability.
	var currentAvailabilityTransition metav1.Time
	var currentlyAvailable bool
	guardianDeployment := v1.Deployment{}
	err = r.Client.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, &guardianDeployment)
	if err != nil && !k8serrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read the deployment status of Guardian", err, reqLogger)
		return reconcile.Result{}, nil
	} else if err == nil {
		for _, condition := range guardianDeployment.Status.Conditions {
			if condition.Type == v1.DeploymentAvailable {
				currentAvailabilityTransition = condition.LastTransitionTime
				if condition.Status == corev1.ConditionTrue {
					currentlyAvailable = true
				}
				break
			}
		}
	}

	// Resolve the proxies used by each Guardian pod. We only update the resolved proxies if the availability of the
	// Guardian deployment has changed since our last reconcile and the deployment is currently available. We restrict
	// the resolution of pod proxies in this way to limit the number of pod queries we make.
	if !currentAvailabilityTransition.Equal(&r.lastAvailabilityTransition) && currentlyAvailable {
		// Query guardian pods.
		labelSelector := labels.SelectorFromSet(map[string]string{
			"app.kubernetes.io/name": render.GuardianDeploymentName,
		})
		pods := corev1.PodList{}
		err := r.Client.List(ctx, &pods, &client.ListOptions{
			LabelSelector: labelSelector,
			Namespace:     render.GuardianNamespace,
		})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to list the pods of the Guardian deployment", err, reqLogger)
			return reconcile.Result{}, nil
		}

		// Resolve the proxy config for each pod. Pods without a proxy will have a nil proxy config value.
		var podProxies []*httpproxy.Config
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.Name == render.GuardianDeploymentName {
					var podProxyConfig *httpproxy.Config
					var httpsProxy, noProxy string
					for _, env := range container.Env {
						switch env.Name {
						case "https_proxy", "HTTPS_PROXY":
							httpsProxy = env.Value
						case "no_proxy", "NO_PROXY":
							noProxy = env.Value
						}
					}
					if httpsProxy != "" || noProxy != "" {
						podProxyConfig = &httpproxy.Config{
							HTTPSProxy: httpsProxy,
							NoProxy:    noProxy,
						}
					}

					podProxies = append(podProxies, podProxyConfig)
				}
			}
		}

		r.resolvedPodProxies = podProxies
	}
	r.lastAvailabilityTransition = currentAvailabilityTransition

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	tierAvailable := false
	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.Client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err == nil {
		tierAvailable = true
	} else if !k8serrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, reqLogger)
		return reconcile.Result{}, err
	}

	licenseActive := false
	// Ensure the license can support enterprise policy, before rendering any network policies within it.
	if license, err := utils.FetchLicenseKey(ctx, r.Client); err == nil {
		if utils.IsFeatureActive(license, common.EgressAccessControlFeature) {
			licenseActive = true
		}
	} else if !k8serrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, reqLogger)
		return reconcile.Result{}, err
	}

	// The creation of the Tier depends on this controller to reconcile it's non-NetworkPolicy resources so that the
	// License becomes available. Therefore, if we fail to query the Tier, we exclude NetworkPolicy from reconciliation
	// and tolerate errors arising from the Tier not being created.
	includeEgressNetworkPolicy := tierAvailable && licenseActive

	ch := utils.NewComponentHandler(log, r.Client, r.Scheme, managementClusterConnection)
	guardianCfg := &render.GuardianConfiguration{
		URL:                         managementClusterConnection.Spec.ManagementClusterAddr,
		PodProxies:                  r.resolvedPodProxies,
		TunnelCAType:                managementClusterConnection.Spec.TLS.CA,
		PullSecrets:                 pullSecrets,
		OpenShift:                   r.Provider.IsOpenShift(),
		Installation:                instl,
		TunnelSecret:                tunnelSecret,
		TrustedCertBundle:           trustedCertBundle,
		ManagementClusterConnection: managementClusterConnection,
	}

	components := []render.Component{render.Guardian(guardianCfg)}

	// v3 NetworkPolicy will fail to reconcile if the Tier is not created, which can only occur once a License is created.
	// In managed clusters, the clusterconnection controller is a dependency for the License to be created. In case the
	// License is unavailable and reconciliation of non-NetworkPolicy resources in the clusterconnection controller
	// would resolve it, we render network policies last to prevent a chicken-and-egg scenario.
	if includeEgressNetworkPolicy {
		policyComponent, err := render.GuardianPolicy(guardianCfg)
		if err != nil {
			log.Error(err, "Failed to create NetworkPolicy component for Guardian, policy will be omitted")
		} else {
			components = append(components, policyComponent)
		}
	}

	if err = imageset.ApplyImageSet(ctx, r.Client, variant, components...); err != nil {
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

	// We should create the Guardian deployment.
	return result, nil
}

func fillDefaults(mcc *operatorv1.ManagementClusterConnection) {
	if mcc.Spec.TLS == nil {
		mcc.Spec.TLS = &operatorv1.ManagementClusterTLS{}
	}
	if mcc.Spec.TLS.CA == "" {
		mcc.Spec.TLS.CA = operatorv1.CATypeTigera
	}
}
