// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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
	"net"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const controllerName = "clusterconnection-controller"

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
	licenseWatchReady := &utils.ReadyFlag{}
	policyWatchesReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, licenseWatchReady, tierWatchReady, policyWatchesReady, opts)

	// Create a new controller
	controller, err := controller.New(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	// Watch for changes to License and Tier, as their status is used as input to determine whether network policy should be reconciled by this controller.
	go utils.WaitToAddLicenseKeyWatch(controller, k8sClient, log, licenseWatchReady)
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, controller, k8sClient, log, tierWatchReady)

	go utils.WaitToAddNetworkPolicyWatches(controller, k8sClient, log, policyWatchesReady, []types.NamespacedName{
		{Name: render.GuardianPolicyName, Namespace: render.GuardianNamespace},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.GuardianNamespace},
	})

	return add(mgr, controller)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	p operatorv1.Provider,
	licenseWatchReady *utils.ReadyFlag,
	tierWatchReady *utils.ReadyFlag,
	policyWatchesReady *utils.ReadyFlag,
	opts options.AddOptions,
) *ReconcileConnection {
	c := &ReconcileConnection{
		Client:             cli,
		Scheme:             schema,
		Provider:           p,
		status:             statusMgr,
		clusterDomain:      opts.ClusterDomain,
		licenseWatchReady:  licenseWatchReady,
		tierWatchReady:     tierWatchReady,
		policyWatchesReady: policyWatchesReady,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// add adds a new controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, c controller.Controller) error {
	// Watch for changes to primary resource ManagementCluster
	err := c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	// Watch for changes to the secrets associated with the ManagementClusterConnection.
	if err = utils.AddSecretsWatch(c, render.GuardianSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.GuardianSecretName, err)
	}

	// Watch for optional voltron server secret
	if err = utils.AddSecretsWatch(c, render.VoltronServerSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.VoltronServerSecretName, err)
	}

	// Watch for changes to the secrets associated with the PacketCapture APIs.
	if err = utils.AddSecretsWatch(c, render.PacketCaptureCertSecret, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.PacketCaptureCertSecret, err)
	}
	// Watch for changes to the secrets associated with Prometheus.
	if err = utils.AddSecretsWatch(c, render.PrometheusTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.PrometheusTLSSecretName, err)
	}

	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, certificatemanagement.CASecretName, err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Network resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	return nil
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileConnection{}

// ReconcileConnection reconciles a ManagementClusterConnection object
type ReconcileConnection struct {
	Client             client.Client
	Scheme             *runtime.Scheme
	Provider           operatorv1.Provider
	status             status.StatusManager
	clusterDomain      string
	licenseWatchReady  *utils.ReadyFlag
	tierWatchReady     *utils.ReadyFlag
	policyWatchesReady *utils.ReadyFlag
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
		log.Error(err, "Error reading ManagementCluster")
		r.status.SetDegraded("Error reading ManagementCluster", err.Error())
		return reconcile.Result{}, err
	}

	// Fetch the managementClusterConnection.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.Client)
	if err != nil {
		r.status.SetDegraded("Error querying ManagementClusterConnection", err.Error())
		return result, err
	} else if managementClusterConnection == nil {
		r.status.OnCRNotFound()
		return result, nil
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		log.Error(err, "")
		r.status.SetDegraded(err.Error(), "")
		return reconcile.Result{}, err
	}

	log.V(2).Info("Loaded ManagementClusterConnection config", "config", managementClusterConnection)
	r.status.OnCRFound()

	pullSecrets, err := utils.GetNetworkingPullSecrets(instl, r.Client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return result, err
	}

	certificateManager, err := certificatemanager.Create(r.Client, instl, r.clusterDomain)
	if err != nil {
		log.Error(err, "unable to create the Tigera CA")
		r.status.SetDegraded("Unable to create the Tigera CA", err.Error())
		return reconcile.Result{}, err
	}

	// Copy the secret from the operator namespace to the guardian namespace if it is present.
	tunnelSecret := &corev1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()}, tunnelSecret)
	if err != nil {
		r.status.SetDegraded("Error retrieving secrets from guardian namespace", err.Error())
		if !k8serrors.IsNotFound(err) {
			return result, nil
		}
		return result, err
	}

	// check if public CA is used for voltron
	var usePublicCA bool
	if err := r.Client.Get(ctx, types.NamespacedName{Name: render.VoltronServerSecretName, Namespace: common.OperatorNamespace()}, tunnelSecret); err != nil {
		usePublicCA = true
	}

	trustedCertBundle := certificateManager.CreateTrustedBundle()
	for _, secretName := range []string{render.PacketCaptureCertSecret, render.PrometheusTLSSecretName} {
		secret, err := certificateManager.GetCertificate(r.Client, secretName, common.OperatorNamespace())
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("failed to retrieve %s", secretName))
			r.status.SetDegraded(fmt.Sprintf("Failed to retrieve %s", secretName), err.Error())
			return reconcile.Result{}, err
		} else if secret == nil {
			reqLogger.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secretName))
			r.status.SetDegraded(fmt.Sprintf("Waiting for secret '%s' to become available", secretName), "")
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		}
		trustedCertBundle.AddCertificates(secret)
	}

	// In managed clusters, successful reconciliation of non-NetworkPolicy resources in the clusterconnection controller
	// ensures that NetworkPolicy is reconcilable (by enabling* the creation of containing Tier and License). Therefore,
	// to prevent a chicken-and-egg scenario, we only reconcile NetworkPolicy resources once we can confirm that all
	// requirements to reconcile NetworkPolicy have been met.
	//
	// * In managed clusters, the License can only be pushed once Guardian has been deployed, and (as always) the Tier
	//   can only be created once the License is available.
	includeNetworkPolicy := true
	var egressAccessControlFeatureRequired bool
	var networkPolicyIsReconcilable bool
	if clusterAddrHasDomain, err := managementClusterAddrHasDomain(managementClusterConnection); err == nil && clusterAddrHasDomain {
		egressAccessControlFeatureRequired = true
		networkPolicyIsReconcilable = utils.IsV3NetworkPolicyReconcilable(ctx, r.Client, networkpolicy.TigeraComponentTierName, common.EgressAccessControlFeature)
	} else {
		if err != nil {
			log.Error(err, fmt.Sprintf(
				"Failed to parse ManagementClusterAddr. Assuming %s does not require license feature %s",
				render.GuardianPolicyName,
				common.EgressAccessControlFeature,
			))
		}
		egressAccessControlFeatureRequired = false
		networkPolicyIsReconcilable = utils.IsV3NetworkPolicyReconcilable(ctx, r.Client, networkpolicy.TigeraComponentTierName)
	}

	if networkPolicyIsReconcilable {
		if egressAccessControlFeatureRequired {
			license, err := utils.FetchLicenseKey(ctx, r.Client)
			if err != nil {
				if k8serrors.IsNotFound(err) {
					r.status.SetDegraded("License not found", err.Error())
					return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
				}
				r.status.SetDegraded("Error querying license", err.Error())
				return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
			}

			if !utils.IsFeatureActive(license, common.EgressAccessControlFeature) {
				r.status.SetDegraded("Feature is not active", "License does not support feature: egress-access-control")
				return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
			}
		}

		if !r.licenseWatchReady.IsReady() {
			r.status.SetDegraded("Waiting for LicenseKeyAPI to be ready", "")
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}

		if !r.tierWatchReady.IsReady() {
			r.status.SetDegraded("Waiting for Tier watch to be established", "")
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}

		if !r.policyWatchesReady.IsReady() {
			r.status.SetDegraded("Waiting for NetworkPolicy watches to be established", "")
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}
	} else {
		includeNetworkPolicy = false
	}

	ch := utils.NewComponentHandler(log, r.Client, r.Scheme, managementClusterConnection)
	guardianCfg := &render.GuardianConfiguration{
		URL:                  managementClusterConnection.Spec.ManagementClusterAddr,
		PullSecrets:          pullSecrets,
		Openshift:            r.Provider == operatorv1.ProviderOpenShift,
		Installation:         instl,
		TunnelSecret:         tunnelSecret,
		TrustedCertBundle:    trustedCertBundle,
		UsePublicCA:          usePublicCA,
		IncludeNetworkPolicy: includeNetworkPolicy,
	}
	component := render.Guardian(guardianCfg)

	if err = imageset.ApplyImageSet(ctx, r.Client, variant, component); err != nil {
		log.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return result, err
	}

	r.status.ClearDegraded()

	// We should create the Guardian deployment.
	return result, nil
}

func managementClusterAddrHasDomain(connection *operatorv1.ManagementClusterConnection) (bool, error) {
	host, _, err := net.SplitHostPort(connection.Spec.ManagementClusterAddr)
	if err != nil {
		return false, err
	}

	return net.ParseIP(host) == nil, nil
}
