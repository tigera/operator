package whisker

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"k8s.io/apimachinery/pkg/types"

	"github.com/go-logr/logr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/render"
	"golang.org/x/net/http/httpproxy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type reconciler struct {
	cli                        client.Client
	status                     status.StatusManager
	scheme                     *runtime.Scheme
	log                        logr.Logger
	Provider                   operatorv1.Provider
	resolvedPodProxies         []*httpproxy.Config
	lastAvailabilityTransition metav1.Time
	clusterDomain              string
}

func (r *reconciler) Reconcile(ctx context.Context, params params[operatorv1.ManagementClusterConnection], request reconcile.Request) (reconcile.Result, error) {
	cr := params.cr
	if t, msg, err := r.resolveProxies(ctx); err != nil {
		r.status.SetDegraded(t, msg, err, r.log)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.cli, params.installations, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, r.log)
		return reconcile.Result{}, err
	}

	tunnelSecret := &corev1.Secret{}
	err = r.cli.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()}, tunnelSecret)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving secrets from guardian namespace", err, r.log)
		if !k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, nil
	}

	var trustedCertBundle certificatemanagement.TrustedBundle
	if cr.Spec.TLS.CA == operatorv1.CATypePublic {
		// If we need to trust a public CA, then we want Guardian to mount all the system certificates.
		trustedCertBundle, err = certificateManager.CreateTrustedBundleWithSystemRootCertificates()
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create tigera-ca-bundle configmap", err, r.log)
			return reconcile.Result{}, err
		}
	} else {
		trustedCertBundle = certificateManager.CreateTrustedBundle()
	}
	secretsToTrust := []string{render.ProjectCalicoAPIServerTLSSecretName(params.installations.Variant)}
	for _, secretName := range secretsToTrust {
		secret, err := certificateManager.GetCertificate(r.cli, secretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve %s", secretName), err, r.log)
			return reconcile.Result{}, err
		} else if secret == nil {
			r.log.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secretName))
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret '%s' to become available", secretName), nil, r.log)
			return reconcile.Result{}, nil
		}
		trustedCertBundle.AddCertificates(secret)
	}

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, params.cr)
	guardianCfg := &render.GuardianConfiguration{
		URL:               params.cr.Spec.ManagementClusterAddr,
		TunnelCAType:      params.cr.Spec.TLS.CA,
		Installation:      params.installations,
		PodProxies:        r.resolvedPodProxies,
		PullSecrets:       params.pullSecrets,
		OpenShift:         r.Provider.IsOpenShift(),
		TunnelSecret:      tunnelSecret,
		TrustedCertBundle: trustedCertBundle,
	}

	components := []render.Component{render.Guardian(guardianCfg)}

	// The creation of the Tier depends on this controller to reconcile it's non-NetworkPolicy resources so that the
	// License becomes available. Therefore, if we fail to query the Tier, we exclude NetworkPolicy from reconciliation
	// and tolerate errors arising from the Tier not being created.
	includeEgressNetworkPolicy := params.tigeraTierAvailable && utils.IsFeatureActive(params.license, common.EgressAccessControlFeature)

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

	if err := imageset.ApplyImageSet(ctx, r.cli, params.variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, r.log)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, r.log)
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

func (r *reconciler) resolveProxies(ctx context.Context) (operatorv1.TigeraStatusReason, string, error) {
	var currentAvailabilityTransition metav1.Time
	var currentlyAvailable bool

	guardianDeployment := appsv1.Deployment{}
	err := r.cli.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, &guardianDeployment)
	if err != nil && !k8serrors.IsNotFound(err) {
		return operatorv1.ResourceReadError, "Failed to read the deployment status of Guardian", err
	} else if err == nil {
		for _, condition := range guardianDeployment.Status.Conditions {
			if condition.Type == appsv1.DeploymentAvailable {
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
		err := r.cli.List(ctx, &pods, &client.ListOptions{
			LabelSelector: labelSelector,
			Namespace:     render.GuardianNamespace,
		})
		if err != nil {
			return operatorv1.ResourceReadError, "Failed to list the pods of the Guardian deployment.", err
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

	return "", "", nil
}
