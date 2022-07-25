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

package apiserver

import (
	"context"
	"fmt"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/common/validation"
	apiserver "github.com/tigera/operator/pkg/common/validation/apiserver"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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

var log = logf.Log.WithName("controller_apiserver")

// Add creates a new APIServer Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	r := newReconciler(mgr, opts)

	c, err := controller.New("apiserver-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create apiserver-controller: %v", err)
	}

	// Established deferred watches against the v3 API that should succeed after the Enterprise API Server becomes available.
	if opts.EnterpriseCRDExists {
		k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
		if err != nil {
			log.Error(err, "Failed to establish a connection to k8s")
			return err
		}

		// Watch for changes to Tier, as its status is used as input to determine whether network policy should be reconciled by this controller.
		go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, r.tierWatchReady)

		go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, []types.NamespacedName{
			{Name: render.APIServerPolicyName, Namespace: rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise)},
			{Name: render.PacketCapturePolicyName, Namespace: render.PacketCaptureNamespace},
		})
	}

	return add(c, r)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) *ReconcileAPIServer {
	r := &ReconcileAPIServer{
		client:              mgr.GetClient(),
		scheme:              mgr.GetScheme(),
		provider:            opts.DetectedProvider,
		amazonCRDExists:     opts.AmazonCRDExists,
		enterpriseCRDsExist: opts.EnterpriseCRDExists,
		status:              status.New(mgr.GetClient(), "apiserver", opts.KubernetesVersion),
		clusterDomain:       opts.ClusterDomain,
		usePSP:              opts.UsePSP,
		tierWatchReady:      &utils.ReadyFlag{},
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup
func add(c controller.Controller, r *ReconcileAPIServer) error {
	// Watch for changes to primary resource APIServer
	err := c.Watch(&source.Kind{Type: &operatorv1.APIServer{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create APIServer watch", "err", err)
		return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		log.V(5).Info("Failed to create network watch", "err", err)
		return fmt.Errorf("apiserver-controller failed to watch Tigera network resource: %v", err)
	}

	if err = utils.AddConfigMapWatch(c, render.K8sSvcEndpointConfigMapName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("apiserver-controller failed to watch ConfigMap %s: %w", render.K8sSvcEndpointConfigMapName, err)
	}

	if r.amazonCRDExists {
		err = c.Watch(&source.Kind{Type: &operatorv1.AmazonCloudIntegration{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			log.V(5).Info("Failed to create AmazonCloudIntegration watch", "err", err)
			return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
		}
	}

	if r.enterpriseCRDsExist {
		// Watch for changes to primary resource ManagementCluster
		err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
		}

		// Watch for changes to primary resource ManagementClusterConnection
		err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
		}

		for _, namespace := range []string{common.OperatorNamespace(), rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise)} {
			if err = utils.AddSecretsWatch(c, render.VoltronTunnelSecretName, namespace); err != nil {
				return fmt.Errorf("apiserver-controller failed to watch the Secret resource: %v", err)
			}
		}

		// Watch for changes to authentication
		err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("apiserver-controller failed to watch resource: %w", err)
		}
	}

	for _, secretName := range []string{
		"calico-apiserver-certs", "tigera-apiserver-certs", render.PacketCaptureCertSecret,
		certificatemanagement.CASecretName, render.DexTLSSecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("apiserver-controller failed to watch the Secret resource: %v", err)
		}
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("apiserver-controller failed to watch ImageSet: %w", err)
	}

	log.V(5).Info("Controller created and Watches setup")
	return nil
}

// blank assignment to verify that ReconcileAPIServer implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAPIServer{}

// ReconcileAPIServer reconciles a APIServer object
type ReconcileAPIServer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client              client.Client
	scheme              *runtime.Scheme
	provider            operatorv1.Provider
	amazonCRDExists     bool
	enterpriseCRDsExist bool
	status              status.StatusManager
	clusterDomain       string
	usePSP              bool
	tierWatchReady      *utils.ReadyFlag
}

// Reconcile reads that state of the cluster for a APIServer object and makes changes based on the state read
// and what is in the APIServer.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAPIServer) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling APIServer")

	instance, msg, err := utils.GetAPIServer(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("APIServer config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(msg, err.Error())
		reqLogger.Error(err, fmt.Sprintf("An error occurred when querying the APIServer resource: %s", msg))
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// Validate APIServer resource.
	if err := validateAPIServerResource(instance); err != nil {
		r.status.SetDegraded("APIServer is invalid", err.Error())
		return reconcile.Result{}, err
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
	if variant == "" {
		r.status.SetDegraded("Waiting for Installation to be ready", "")
		return reconcile.Result{}, nil
	}
	ns := rmeta.APIServerNamespace(variant)

	certificateManager, err := certificatemanager.Create(r.client, network, r.clusterDomain)
	if err != nil {
		log.Error(err, "unable to create the Tigera CA")
		r.status.SetDegraded("Unable to create the Tigera CA", err.Error())
		return reconcile.Result{}, err
	}

	// We need separate certificates for OSS vs Enterprise.
	secretName := render.ProjectCalicoApiServerTLSSecretName(network.Variant)
	tlsSecret, err := certificateManager.GetOrCreateKeyPair(r.client, secretName, common.OperatorNamespace(), dns.GetServiceDNSNames(render.ProjectCalicoApiServerServiceName(network.Variant), rmeta.APIServerNamespace(network.Variant), r.clusterDomain))
	if err != nil {
		log.Error(err, "Unable to get or create tls key pair")
		r.status.SetDegraded("Unable to get or create tls key pair", err.Error())
		return reconcile.Result{}, err
	}

	certificateManager.AddToStatusManager(r.status, ns)

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		log.Error(err, "Error retrieving Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	// Query enterprise-only data.
	var tunnelCASecret certificatemanagement.KeyPairInterface
	var amazon *operatorv1.AmazonCloudIntegration
	var managementCluster *operatorv1.ManagementCluster
	var managementClusterConnection *operatorv1.ManagementClusterConnection
	var tunnelSecretPassthrough render.Component
	includeV3NetworkPolicy := false
	if variant == operatorv1.TigeraSecureEnterprise {
		managementCluster, err = utils.GetManagementCluster(ctx, r.client)
		if err != nil {
			log.Error(err, "Error reading ManagementCluster")
			r.status.SetDegraded("Error reading ManagementCluster", err.Error())
			return reconcile.Result{}, err
		}

		managementClusterConnection, err = utils.GetManagementClusterConnection(ctx, r.client)
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

		if managementCluster != nil {
			tunnelCASecret, err = certificateManager.GetKeyPair(r.client, render.VoltronTunnelSecretName, common.OperatorNamespace())
			if tunnelCASecret == nil {
				tunnelSecret, err := certificatemanagement.CreateSelfSignedSecret(render.VoltronTunnelSecretName, common.OperatorNamespace(), "tigera-voltron", []string{"voltron"})
				if err == nil {
					tunnelCASecret = certificatemanagement.NewKeyPair(tunnelSecret, nil, "")
					// Creating the voltron tunnel secret is not (yet) supported by certificate mananger.
					tunnelSecretPassthrough = render.NewPassthrough(tunnelCASecret.Secret(common.OperatorNamespace()))
				}
			}
			if err != nil {
				log.Error(err, "Unable to get or create the tunnel secret")
				r.status.SetDegraded("Unable to get or create the tunnel secret", err.Error())
				return reconcile.Result{}, err
			}
		}

		if r.amazonCRDExists {
			amazon, err = utils.GetAmazonCloudIntegration(ctx, r.client)
			if errors.IsNotFound(err) {
				amazon = nil
			} else if err != nil {
				log.Error(err, "Error reading AmazonCloudIntegration")
				r.status.SetDegraded("Error reading AmazonCloudIntegration", err.Error())
				return reconcile.Result{}, err
			}
		}

		// Ensure the allow-tigera tier exists, before rendering any network policies within it.
		//
		// The creation of the Tier depends on this controller to reconcile it's non-NetworkPolicy resources so that
		// the API Server becomes available. Therefore, if we fail to query the Tier, we exclude NetworkPolicy from
		// reconciliation and tolerate errors arising from the Tier not being created or the API server not being available.
		// We also exclude NetworkPolicy and do not degrade when the Tier watch is not ready, as this means the API server is not available.
		if r.tierWatchReady.IsReady() {
			if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
				if !errors.IsNotFound(err) && !meta.IsNoMatchError(err) {
					log.Error(err, "Error querying allow-tigera tier")
					r.status.SetDegraded("Error querying allow-tigera tier", err.Error())
					return reconcile.Result{}, err
				}
			} else {
				includeV3NetworkPolicy = true
			}
		}
	}

	err = utils.GetK8sServiceEndPoint(r.client)
	if err != nil {
		log.Error(err, "Error reading services endpoint configmap")
		r.status.SetDegraded("Error reading services endpoint configmap", err.Error())
		return reconcile.Result{}, err
	}
	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	reqLogger.V(3).Info("rendering components")

	apiServerCfg := render.APIServerConfiguration{
		K8SServiceEndpoint:          k8sapi.Endpoint,
		Installation:                network,
		APIServer:                   &instance.Spec,
		ForceHostNetwork:            false,
		ManagementCluster:           managementCluster,
		ManagementClusterConnection: managementClusterConnection,
		AmazonCloudIntegration:      amazon,
		TLSKeyPair:                  tlsSecret,
		PullSecrets:                 pullSecrets,
		Openshift:                   r.provider == operatorv1.ProviderOpenShift,
		TunnelCASecret:              tunnelCASecret,
		UsePSP:                      r.usePSP,
	}

	component, err := render.APIServer(&apiServerCfg)
	if err != nil {
		log.Error(err, "Error rendering APIServer")
		r.status.SetDegraded("Error rendering APIServer", err.Error())
		return reconcile.Result{}, err
	}
	components := []render.Component{
		component,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       rmeta.APIServerNamespace(variant),
			ServiceAccounts: []string{render.ApiServerServiceAccountName(variant)},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(tlsSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(tunnelCASecret, true, true),
			},
		}),
	}
	if tunnelSecretPassthrough != nil {
		components = append(components, tunnelSecretPassthrough)
	}

	var pcPolicy render.Component
	if variant == operatorv1.TigeraSecureEnterprise {
		packetCaptureCertSecret, err := certificateManager.GetOrCreateKeyPair(
			r.client,
			render.PacketCaptureCertSecret,
			common.OperatorNamespace(),
			dns.GetServiceDNSNames(render.PacketCaptureServiceName, render.PacketCaptureNamespace, r.clusterDomain))
		if err != nil {
			r.status.SetDegraded("Error retrieve or creating packet capture TLS certificate", err.Error())
			return reconcile.Result{}, err
		}

		// Fetch the Authentication spec. If present, we use to configure user authentication.
		authenticationCR, err := utils.GetAuthentication(ctx, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded("Error querying Authentication", err.Error())
			return reconcile.Result{}, err
		}

		keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain)
		if err != nil {
			log.Error(err, "Failed to process the authentication CR.")
			r.status.SetDegraded("Failed to process the authentication CR.", err.Error())
			return reconcile.Result{}, err
		}

		packetCaptureApiCfg := &render.PacketCaptureApiConfiguration{
			PullSecrets:                 pullSecrets,
			Openshift:                   r.provider == operatorv1.ProviderOpenShift,
			Installation:                network,
			KeyValidatorConfig:          keyValidatorConfig,
			ServerCertSecret:            packetCaptureCertSecret,
			ClusterDomain:               r.clusterDomain,
			ManagementClusterConnection: managementClusterConnection,
		}
		pc := render.PacketCaptureAPI(packetCaptureApiCfg)
		pcPolicy = render.PacketCaptureAPIPolicy(packetCaptureApiCfg)
		components = append(components, pc,
			rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
				Namespace:       render.PacketCaptureNamespace,
				ServiceAccounts: []string{render.PacketCaptureServiceAccountName},
				KeyPairOptions: []rcertificatemanagement.KeyPairOption{
					rcertificatemanagement.NewKeyPairOption(packetCaptureCertSecret, true, true),
				},
			}),
		)
		certificateManager.AddToStatusManager(r.status, render.PacketCaptureNamespace)
	}

	// v3 NetworkPolicy will fail to reconcile if the API server deployment is unhealthy. In case the API Server
	// deployment becomes unhealthy and reconciliation of non-NetworkPolicy resources in the apiserver controller
	// would resolve it, we render the network policies of components last to prevent a chicken-and-egg scenario.
	if includeV3NetworkPolicy {
		components = append(components, render.APIServerPolicy(&apiServerCfg))
		if pcPolicy != nil {
			components = append(components, pcPolicy)
		}
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, components...); err != nil {
		log.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded("Error with images from ImageSet", err.Error())
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := handler.CreateOrUpdateOrDelete(context.Background(), component, r.status); err != nil {
			r.status.SetDegraded("Error creating / updating resource", err.Error())
			return reconcile.Result{}, err
		}
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

func validateAPIServerResource(instance *operatorv1.APIServer) error {
	// Verify the APIServerDeployment overrides, if specified, is valid.
	if d := instance.Spec.APIServerDeployment; d != nil {
		err := validation.ValidateReplicatedPodResourceOverrides(d, apiserver.ValidateAPIServerDeploymentContainer, apiserver.ValidateAPIServerDeploymentInitContainer)
		if err != nil {
			return fmt.Errorf("APIServer spec.APIServerDeployment is not valid: %w", err)
		}
	}
	return nil

}
