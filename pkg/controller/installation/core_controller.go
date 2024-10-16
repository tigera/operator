// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

package installation

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"
	"github.com/tigera/operator/pkg/envoygateway"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/active"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/migration"
	"github.com/tigera/operator/pkg/controller/migration/convert"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/crds"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/resourcequota"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	techPreviewFeatureSeccompApparmor = "tech-preview.operator.tigera.io/node-apparmor-profile"

	// The default port used by calico/node to report Calico Enterprise internal metrics.
	// This is separate from the calico/node prometheus metrics port, which is user configurable.
	defaultNodeReporterPort = 9081
)

const InstallationName string = "calico"

//// Use of Finalizers for graceful termination
//
// There is a problem with tearing down the Calico resources where removing the calico-cni RBAC resources
// prevents pod-networked pods (e.g., kube-controllers) from teminating because the CNI plugin no longer has the necessary permissions.
//
// To ensure this problem does not happen we make liberal use of finalizers to ensure a staged teardown of resources created by this operator.
//
// - Each controller (including this one) that requires the CNI plugin for teardown can add its own finalizer to the Installation CR, and is responsible
//   for removing this finalizer when its finalization logic is complete.
// - This controller adds a finalizer to the Calico CNI resources to ensure they remain even when the Installation
//   is deleted. This finalizer is only removed once all per-controller finalizers on the Installation are removed.
// - This controller adds a finalizer to the Installation that is only removed after the CNI resources have had their finalizers removed.
//   This allows the Installation resource to remain while the operator as a whole cleans up.
//
// When the Installation resource is being deleted (has a DeletionTimestamp) the following sequence occurs:
//
//   1. Kubernetes will begin cleaning up any resources owned by the Installation.
//   2. This controller will pass Terminating=true to the kube-controllers render code, ensuring
//      the kube-controllers resources are explicitly deleted.
//   3. Once kube-controllers is terminated we will remove this controller's Finalizer from the Installation.
//   4. Once there are no more per-controller finalizers on the Installation, this controller will re-render the calico-cni ClusterRoleBinding,
//      ClusterRole, and ServiceAccount resources to remove the finalizers on them.
//   4. Once the calico-cni finalizers are emoved, this controller will remove the tigera.io/operator-cleanup finalizer
//      from the Installation, allowing it to be deleted.
//   5. Deletion of the Installation will trigger cleanup of the remaining calico-system resources left in the cluster.

var (
	log                    = logf.Log.WithName("controller_installation")
	openshiftNetworkConfig = "cluster"
)

// Add creates a new Installation Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	ri, err := newReconciler(mgr, opts)
	if err != nil {
		return fmt.Errorf("failed to create Core Reconciler: %w", err)
	}

	c, err := ctrlruntime.NewController("tigera-installation-controller", mgr, controller.Options{Reconciler: ri})
	if err != nil {
		return fmt.Errorf("failed to create tigera-installation-controller: %w", err)
	}

	// Established deferred watches against the v3 API that should succeed after the Enterprise API Server becomes available.
	if opts.EnterpriseCRDExists {
		k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
		if err != nil {
			log.Error(err, "Failed to establish a connection to k8s")
			return err
		}

		// Watch for changes to Tier, as its status is used as input to determine whether network policy should be reconciled by this controller.
		go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, ri.tierWatchReady)

		go utils.WaitToAddNetworkPolicyWatches(c, k8sClient, log, []types.NamespacedName{
			{Name: kubecontrollers.KubeControllerNetworkPolicyName, Namespace: common.CalicoNamespace},
		},
		)
	}

	return add(c, ri)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) (*ReconcileInstallation, error) {
	nm, err := migration.NewCoreNamespaceMigration(mgr.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Namespace migration: %w", err)
	}

	statusManager := status.New(mgr.GetClient(), "calico", opts.KubernetesVersion)

	// The typhaAutoscaler needs a clientset.
	cs, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return nil, err
	}

	// Create the SharedIndexInformer used by the typhaAutoscaler
	nodeListWatch := cache.NewListWatchFromClient(cs.CoreV1().RESTClient(), "nodes", "", fields.Everything())
	nodeIndexInformer := cache.NewSharedIndexInformer(nodeListWatch, &corev1.Node{}, 0, cache.Indexers{})
	go nodeIndexInformer.Run(opts.ShutdownContext.Done())

	// Create a Typha autoscaler.
	typhaListWatch := cache.NewListWatchFromClient(cs.AppsV1().RESTClient(), "deployments", "calico-system", fields.OneTermEqualSelector("metadata.name", "calico-typha"))
	typhaScaler := newTyphaAutoscaler(cs, nodeIndexInformer, typhaListWatch, statusManager)

	r := &ReconcileInstallation{
		config:               mgr.GetConfig(),
		client:               mgr.GetClient(),
		scheme:               mgr.GetScheme(),
		watches:              make(map[runtime.Object]struct{}),
		autoDetectedProvider: opts.DetectedProvider,
		status:               statusManager,
		typhaAutoscaler:      typhaScaler,
		namespaceMigration:   nm,
		enterpriseCRDsExist:  opts.EnterpriseCRDExists,
		clusterDomain:        opts.ClusterDomain,
		manageCRDs:           opts.ManageCRDs,
		tierWatchReady:       &utils.ReadyFlag{},
		newComponentHandler:  utils.NewComponentHandler,
	}
	r.status.Run(opts.ShutdownContext)
	r.typhaAutoscaler.start(opts.ShutdownContext)
	return r, nil
}

// add adds watches for resources that are available at startup
func add(c ctrlruntime.Controller, r *ReconcileInstallation) error {
	// Watch for changes to primary resource Installation
	err := c.WatchObject(&operator.Installation{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, InstallationName); err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch calico Tigerastatus: %w", err)
	}

	if r.autoDetectedProvider.IsOpenShift() {
		// Watch for OpenShift network configuration as well. If we're running in OpenShift, we need to
		// merge this configuration with our own and the write back the status object.
		err = c.WatchObject(&configv1.Network{}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("tigera-installation-controller failed to watch openshift network config: %w", err)
			}
		}
		// Watch for OpenShift infrastructure configuration, we'll need to check this for special setup when
		// running OpenShift on AWS and/or OpenShift Hosted Control Plane (HCP).
		err = c.WatchObject(&configv1.Infrastructure{}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("tigera-installation-controller failed to watch openshift infrastructure config: %w", err)
			}
		}
	}

	// Watch for secrets in the operator namespace. We watch for all secrets, since we care
	// about specifically named ones - e.g., manager-tls, as well as image pull secrets that
	// may have been provided by the user with arbitrary names.
	err = utils.AddSecretsWatch(c, "", common.OperatorNamespace())
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch secrets: %w", err)
	}

	for _, cm := range []string{render.BirdTemplatesConfigMapName, render.BGPLayoutConfigMapName, render.K8sSvcEndpointConfigMapName, render.TyphaCAConfigMapName} {
		if err = utils.AddConfigMapWatch(c, cm, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch ConfigMap %s: %w", cm, err)
		}
	}

	if err = utils.AddConfigMapWatch(c, active.ActiveConfigMapName, common.CalicoNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch ConfigMap %s: %w", active.ActiveConfigMapName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch ImageSet: %w", err)
	}

	for _, obj := range secondaryResources() {
		if err = utils.AddNamespacedWatch(c, obj, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch %s: %w", obj, err)
		}
	}

	// Watch for changes to KubeControllersConfiguration.
	err = c.WatchObject(&crdv1.KubeControllersConfiguration{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch KubeControllersConfiguration resource: %w", err)
	}

	// Watch for changes to FelixConfiguration.
	err = c.WatchObject(&crdv1.FelixConfiguration{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch FelixConfiguration resource: %w", err)
	}

	// Watch for changes to BGPConfiguration.
	err = c.WatchObject(&crdv1.BGPConfiguration{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch BGPConfiguration resource: %w", err)
	}

	if r.enterpriseCRDsExist {
		// Watch for changes to primary resource ManagementCluster
		err = c.WatchObject(&operator.ManagementCluster{}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %v", err)
		}

		// Watch for changes to primary resource ManagementClusterConnection
		err = c.WatchObject(&operator.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %v", err)
		}

		// watch for change to primary resource LogCollector
		err = c.WatchObject(&operator.LogCollector{}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %v", err)
		}

		// Watch the internal manager TLS secret in the operator namespace, which included in the bundle for es-kube-controllers.
		if err = utils.AddSecretsWatch(c, render.ManagerInternalTLSSecretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch secret: %v", err)
		}

		if r.manageCRDs {
			if err = addCRDWatches(c, operator.TigeraSecureEnterprise); err != nil {
				return fmt.Errorf("tigera-installation-controller failed to watch CRD resource: %v", err)
			}
		}
	} else {
		if r.manageCRDs {
			if err = addCRDWatches(c, operator.Calico); err != nil {
				return fmt.Errorf("tigera-installation-controller failed to watch CRD resource: %v", err)
			}
		}
	}

	// Watch for changes to IPPool.
	err = c.WatchObject(&crdv1.IPPool{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch IPPool resource: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// secondaryResources returns a list of the secondary resources that this controller
// monitors for changes. Add resources here which correspond to the resources created by
// this controller.
func secondaryResources() []client.Object {
	return []client.Object{
		// We care about all of these resource types, so long as they are in the calico-system namespace.
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: common.CalicoNamespace}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: common.CalicoNamespace}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: common.CalicoNamespace}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: common.CalicoNamespace}},

		// We care about specific named resources of these types.
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoNodeObjectName}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoCNIPluginObjectName}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.KubeControllerRole}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoNodeObjectName}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.CalicoCNIPluginObjectName}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.KubeControllerRole}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: common.CalicoNamespace}},
	}
}

var _ reconcile.Reconciler = &ReconcileInstallation{}

// ReconcileInstallation reconciles a Installation object
type ReconcileInstallation struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	config               *rest.Config
	client               client.Client
	scheme               *runtime.Scheme
	watches              map[runtime.Object]struct{}
	autoDetectedProvider operator.Provider
	status               status.StatusManager
	typhaAutoscaler      *typhaAutoscaler
	namespaceMigration   migration.NamespaceMigration
	enterpriseCRDsExist  bool
	amazonCRDExists      bool
	migrationChecked     bool
	clusterDomain        string
	manageCRDs           bool
	tierWatchReady       *utils.ReadyFlag

	// newComponentHandler returns a new component handler. Useful stub for unit testing.
	newComponentHandler func(log logr.Logger, client client.Client, scheme *runtime.Scheme, cr metav1.Object) utils.ComponentHandler
}

// getActivePools returns the full set of enabled IP pools in the cluster.
func getActivePools(ctx context.Context, client client.Client) (*crdv1.IPPoolList, error) {
	allPools := crdv1.IPPoolList{}
	if err := client.List(ctx, &allPools); err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("unable to list IPPools: %s", err.Error())
	}
	filtered := crdv1.IPPoolList{}
	for _, pool := range allPools.Items {
		if pool.Spec.Disabled {
			continue
		}
		filtered.Items = append(filtered.Items, pool)
	}
	return &filtered, nil
}

// updateInstallationWithDefaults returns the default installation instance with defaults populated.
func updateInstallationWithDefaults(ctx context.Context, client client.Client, instance *operator.Installation, provider operator.Provider) error {
	// Determine the provider in use by combining any auto-detected value with any value
	// specified in the Installation CR. mergeProvider updates the CR with the correct value.
	err := mergeProvider(instance, provider)
	if err != nil {
		return err
	}

	awsNode := &appsv1.DaemonSet{}
	key := types.NamespacedName{Name: "aws-node", Namespace: metav1.NamespaceSystem}
	err = client.Get(ctx, key, awsNode)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("unable to read aws-node daemonset: %s", err.Error())
		}
		awsNode = nil
	}

	currentPools, err := getActivePools(ctx, client)
	if err != nil {
		return fmt.Errorf("unable to list IPPools: %s", err.Error())
	}

	err = MergeAndFillDefaults(instance, awsNode, currentPools)
	if err != nil {
		return err
	}
	return nil
}

// MergeAndFillDefaults merges in configuration from the Kubernetes provider, if applicable, and then
// populates defaults in the Installation instance.
func MergeAndFillDefaults(i *operator.Installation, awsNode *appsv1.DaemonSet, currentPools *crdv1.IPPoolList) error {
	if awsNode != nil {
		if err := updateInstallationForAWSNode(i, awsNode); err != nil {
			return fmt.Errorf("could not resolve AWS node configuration: %s", err.Error())
		}
	}

	return fillDefaults(i, currentPools)
}

// fillDefaults populates the default values onto an Installation object.
func fillDefaults(instance *operator.Installation, currentPools *crdv1.IPPoolList) error {
	// Populate the instance with defaults for any fields not provided by the user.
	if len(instance.Spec.Registry) != 0 && instance.Spec.Registry != components.UseDefault && !strings.HasSuffix(instance.Spec.Registry, "/") {
		// Make sure registry, except for the special case "UseDefault", always ends with a slash.
		instance.Spec.Registry = fmt.Sprintf("%s/", instance.Spec.Registry)
	}

	if len(instance.Spec.Variant) == 0 {
		// Default to installing Calico.
		instance.Spec.Variant = operator.Calico
	}

	// Default to running Calico as privileged.
	if instance.Spec.NonPrivileged == nil {
		npd := operator.NonPrivilegedDisabled
		instance.Spec.NonPrivileged = &npd
	}

	if instance.Spec.TyphaAffinity == nil {
		switch instance.Spec.KubernetesProvider {
		// in AKS, there is a feature called 'virtual-nodes' which represent azure's container service as a node in the kubernetes cluster.
		// virtual-nodes have many limitations, namely it's unable to run hostNetworked pods. virtual-kubelets are tainted to prevent pods from running on them,
		// but typha tolerates all taints and will run there.
		// as such, we add a required anti-affinity for virtual-nodes if running on azure
		case operator.ProviderAKS:
			instance.Spec.TyphaAffinity = &operator.TyphaAffinity{
				NodeAffinity: &operator.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "type",
									Operator: corev1.NodeSelectorOpNotIn,
									Values:   []string{"virtual-node"},
								},
								{
									Key:      "kubernetes.azure.com/cluster",
									Operator: corev1.NodeSelectorOpExists,
								},
							},
						}},
					},
				},
			}
		default:
			instance.Spec.TyphaAffinity = nil
		}
	}

	// Default the CNI plugin based on the Kubernetes provider.
	if instance.Spec.CNI == nil {
		instance.Spec.CNI = &operator.CNISpec{}
	}
	if instance.Spec.CNI.Type == "" {
		switch instance.Spec.KubernetesProvider {
		case operator.ProviderAKS:
			instance.Spec.CNI.Type = operator.PluginAzureVNET
		case operator.ProviderEKS:
			instance.Spec.CNI.Type = operator.PluginAmazonVPC
		case operator.ProviderGKE:
			instance.Spec.CNI.Type = operator.PluginGKE
		default:
			instance.Spec.CNI.Type = operator.PluginCalico
		}
	}

	// Default IPAM based on CNI.
	if instance.Spec.CNI.IPAM == nil {
		instance.Spec.CNI.IPAM = &operator.IPAMSpec{}
	}
	if instance.Spec.CNI.IPAM.Type == "" {
		switch instance.Spec.CNI.Type {
		case operator.PluginAzureVNET:
			instance.Spec.CNI.IPAM.Type = operator.IPAMPluginAzureVNET
		case operator.PluginAmazonVPC:
			instance.Spec.CNI.IPAM.Type = operator.IPAMPluginAmazonVPC
		case operator.PluginGKE:
			instance.Spec.CNI.IPAM.Type = operator.IPAMPluginHostLocal
		default:
			instance.Spec.CNI.IPAM.Type = operator.IPAMPluginCalico
		}
	}

	// Default any unspecified fields within the CalicoNetworkSpec.
	if instance.Spec.CalicoNetwork == nil {
		instance.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}

	// Default dataplane is iptables.
	if instance.Spec.CalicoNetwork.LinuxDataplane == nil {
		dpIptables := operator.LinuxDataplaneIptables
		instance.Spec.CalicoNetwork.LinuxDataplane = &dpIptables
	}

	// Default Windows dataplane is disabled
	winDataplaneDisabled := operator.WindowsDataplaneDisabled
	if instance.Spec.CalicoNetwork.WindowsDataplane == nil {
		instance.Spec.CalicoNetwork.WindowsDataplane = &winDataplaneDisabled
	}

	// If Windows is enabled, populate CNI bin, config and log dirs with defaults
	// per provider if not explicitly configured
	if *instance.Spec.CalicoNetwork.WindowsDataplane != winDataplaneDisabled {
		if instance.Spec.WindowsNodes == nil {
			instance.Spec.WindowsNodes = &operator.WindowsNodeSpec{}
		}

		defaultCNIBinDir, defaultCNIConfigDir, defaultCNILogDir := render.DefaultWindowsCNIDirectories(instance.Spec)

		if instance.Spec.WindowsNodes.CNIBinDir == "" {
			instance.Spec.WindowsNodes.CNIBinDir = defaultCNIBinDir
		}
		if instance.Spec.WindowsNodes.CNIConfigDir == "" {
			instance.Spec.WindowsNodes.CNIConfigDir = defaultCNIConfigDir
		}
		if instance.Spec.WindowsNodes.CNILogDir == "" {
			instance.Spec.WindowsNodes.CNILogDir = defaultCNILogDir
		}
	}

	// Default BGP enablement based on CNI plugin and provider.
	if instance.Spec.CalicoNetwork.BGP == nil {
		enabled := operator.BGPEnabled
		disabled := operator.BGPDisabled
		switch instance.Spec.CNI.Type {
		case operator.PluginCalico:
			switch instance.Spec.KubernetesProvider {
			case operator.ProviderEKS:
				// On EKS, we use VXLAN mode with Calico CNI so default BGP off.
				instance.Spec.CalicoNetwork.BGP = &disabled
			default:
				// Other platforms assume BGP is needed.
				instance.Spec.CalicoNetwork.BGP = &enabled
			}
		default:
			// For non-Calico CNIs, assume BGP should be off.
			instance.Spec.CalicoNetwork.BGP = &disabled
		}
	}

	needIPv4Autodetection := false
	if *instance.Spec.CalicoNetwork.LinuxDataplane == operator.LinuxDataplaneBPF {
		// BPF dataplane requires IP autodetection even if we're not using Calico IPAM.
		needIPv4Autodetection = true
	}
	if currentPools != nil {
		for _, pool := range currentPools.Items {
			ip, _, err := net.ParseCIDR(pool.Spec.CIDR)
			if err != nil {
				return fmt.Errorf("failed to parse CIDR %s: %s", pool.Spec.CIDR, err)
			}
			if ip.To4() != nil {
				// This is an IPv4 pool - we should default IPv4 autodetection if not specified.
				needIPv4Autodetection = true
			} else if ip.To16() != nil {
				// This is an IPv6 pool - we should default IPv6 autodetection if not specified.
				if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 == nil {
					t := true
					instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 = &operator.NodeAddressAutodetection{
						FirstFound: &t,
					}
				}
			}
		}
	}

	if needIPv4Autodetection && instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 == nil {
		switch instance.Spec.KubernetesProvider {
		case operator.ProviderDockerEE:
			// firstFound finds the Docker Enterprise interface prefixed with br-, which is unusable for the
			// node address, so instead skip the interface br-.
			instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
				SkipInterface: "^br-.*",
			}
		case operator.ProviderEKS:
			// EKS uses multiple interfaces to spread load; we want to pick the main interface with the
			// default route.
			instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
				CanReach: "8.8.8.8",
			}
		default:
			// Default IPv4 address detection to "first found" if not specified.
			t := true
			instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
				FirstFound: &t,
			}
		}
	}

	if instance.Spec.CNI.Type == operator.PluginCalico &&
		*instance.Spec.CalicoNetwork.LinuxDataplane == operator.LinuxDataplaneIptables &&
		instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds == nil {
		var delay int32 = 0
		instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &delay
	}

	// While a number of the fields in this section are relevant to all CNI plugins,
	// there are some settings which are currently only applicable if using Calico CNI.
	// Handle those here.
	if instance.Spec.CNI.Type == operator.PluginCalico {
		if instance.Spec.CalicoNetwork.HostPorts == nil {
			hp := operator.HostPortsEnabled
			instance.Spec.CalicoNetwork.HostPorts = &hp
		}

		if instance.Spec.CalicoNetwork.MultiInterfaceMode == nil {
			mm := operator.MultiInterfaceModeNone
			instance.Spec.CalicoNetwork.MultiInterfaceMode = &mm
		}

		// setting default values for calico-cni logging configuration when not provided by the user
		if instance.Spec.Logging == nil {
			instance.Spec.Logging = new(operator.Logging)
		}
		if instance.Spec.Logging.CNI == nil {
			instance.Spec.Logging.CNI = new(operator.CNILogging)
		}

		// set LofSeverity default to Info
		if instance.Spec.Logging.CNI.LogSeverity == nil {
			instance.Spec.Logging.CNI.LogSeverity = new(operator.LogLevel)
			*instance.Spec.Logging.CNI.LogSeverity = operator.LogLevelInfo
		}

		// set LogFileMaxCount default to 10
		if instance.Spec.Logging.CNI.LogFileMaxCount == nil {
			instance.Spec.Logging.CNI.LogFileMaxCount = new(uint32)
			*instance.Spec.Logging.CNI.LogFileMaxCount = 10
		}

		// set LogFileMaxAge default to 30 days
		if instance.Spec.Logging.CNI.LogFileMaxAgeDays == nil {
			instance.Spec.Logging.CNI.LogFileMaxAgeDays = new(uint32)
			*instance.Spec.Logging.CNI.LogFileMaxAgeDays = 30
		}

		// set LogFileMaxSize default to 100 Mi
		if instance.Spec.Logging.CNI.LogFileMaxSize == nil {
			instance.Spec.Logging.CNI.LogFileMaxSize = new(resource.Quantity)
			*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("100Mi")
		}
	}

	// If not specified by the user, set the default control plane replicas to 2.
	if instance.Spec.ControlPlaneReplicas == nil {
		var replicas int32 = 2
		instance.Spec.ControlPlaneReplicas = &replicas
	}

	// If not specified by the user, set the flex volume plugin location based on platform.
	if len(instance.Spec.FlexVolumePath) == 0 {
		if instance.Spec.KubernetesProvider.IsOpenShift() {
			// In OpenShift 4.x, the location for flexvolume plugins has changed.
			// See: https://bugzilla.redhat.com/show_bug.cgi?id=1667606#c5
			instance.Spec.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
		} else if instance.Spec.KubernetesProvider.IsGKE() {
			instance.Spec.FlexVolumePath = "/home/kubernetes/flexvolume/"
		} else if instance.Spec.KubernetesProvider.IsAKS() {
			instance.Spec.FlexVolumePath = "/etc/kubernetes/volumeplugins/"
		} else if instance.Spec.KubernetesProvider.IsRKE2() {
			instance.Spec.FlexVolumePath = "/var/lib/kubelet/volumeplugins/"
		} else {
			instance.Spec.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		}
	}

	if len(instance.Spec.KubeletVolumePluginPath) == 0 {
		instance.Spec.KubeletVolumePluginPath = filepath.Clean("/var/lib/kubelet")
	}

	// Default rolling update parameters.
	one := intstr.FromInt(1)
	if instance.Spec.NodeUpdateStrategy.RollingUpdate == nil {
		instance.Spec.NodeUpdateStrategy.RollingUpdate = &appsv1.RollingUpdateDaemonSet{}
	}
	if instance.Spec.NodeUpdateStrategy.RollingUpdate.MaxUnavailable == nil {
		instance.Spec.NodeUpdateStrategy.RollingUpdate.MaxUnavailable = &one
	}
	if instance.Spec.NodeUpdateStrategy.Type == "" {
		instance.Spec.NodeUpdateStrategy.Type = appsv1.RollingUpdateDaemonSetStrategyType
	}

	return nil
}

// mergeProvider determines the correct provider based on the auto-detected value, and the user-provided one,
// and updates the Installation CR accordingly. It returns an error if incompatible values are provided.
func mergeProvider(cr *operator.Installation, provider operator.Provider) error {
	// If we detected one provider but user set provider to something else, throw an error
	if !provider.IsNone() && !cr.Spec.KubernetesProvider.IsNone() && cr.Spec.KubernetesProvider != provider {
		msg := "installation spec.kubernetesProvider '%s' does not match auto-detected value '%s'"
		return fmt.Errorf(msg, cr.Spec.KubernetesProvider, provider)
	}

	// If we've reached this point, it means only one source of provider is being used - auto-detection or
	// user-provided, but not both. Or, it means that both have been specified but are the same.
	// If it's the CR provided one, then just use that. Otherwise, use the auto-detected one.
	if cr.Spec.KubernetesProvider.IsNone() {
		cr.Spec.KubernetesProvider = provider
	}
	log.WithValues("provider", cr.Spec.KubernetesProvider).V(1).Info("Determined provider")
	return nil
}

func (r *ReconcileInstallation) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Installation.operator.tigera.io")

	newActiveCM, err := r.checkActive(reqLogger)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Get the installation object if it exists so that we can save the original
	// status before we merge/fill that object with other values.
	instance := &operator.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}

	installationMarkedForDeletion := (instance.DeletionTimestamp != nil)
	if installationMarkedForDeletion {
		reqLogger.Info("Installation object is terminating")
	}
	preDefaultPatchFrom := client.MergeFrom(instance.DeepCopy())

	// Mark CR found so we can report converter problems via tigerastatus
	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating Installation status conditions.
	if request.Name == InstallationName && request.Namespace == "" {
		ts := &operator.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: InstallationName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create Installation status conditions.")
			return reconcile.Result{}, err
		}
	}

	instanceStatus := instance.Status
	if !r.migrationChecked {
		// update Installation resource with existing install if it exists.
		nc, err := convert.NeedsConversion(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operator.ResourceValidationError, "Error checking for existing installation", err, reqLogger)
			return reconcile.Result{}, err
		}
		if nc {
			install, err := convert.Convert(ctx, r.client)
			if err != nil {
				if errors.As(err, &convert.ErrIncompatibleCluster{}) {
					r.status.SetDegraded(operator.MigrationError, "Existing Calico installation can not be managed by Tigera Operator as it is configured in a way that Operator does not currently support. Please update your existing Calico install config", err, reqLogger)
					// We should always requeue a convert problem. Don't return error
					// to make sure we never back off retrying.
					return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
				}
				r.status.SetDegraded(operator.MigrationError, "Error converting existing installation", err, reqLogger)
				return reconcile.Result{}, err
			}
			instance.Spec = utils.OverrideInstallationSpec(install.Spec, instance.Spec)
		}
	}

	// update Installation with defaults
	if err := updateInstallationWithDefaults(ctx, r.client, instance, r.autoDetectedProvider); err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "installation", instance)

	// Validate the configuration.
	if err := validateCustomResource(instance); err != nil {
		r.status.SetDegraded(operator.InvalidConfigurationError, "Invalid Installation provided", err, reqLogger)
		return reconcile.Result{}, err
	}

	// See the section 'Use of Finalizers for graceful termination' at the top of this file for details.
	if installationMarkedForDeletion {
		// This controller manages a finalizer to track whether its own pods have been properly torn down. Only remove it
		// when all pod-networked Pods managed by this controller have been torn down. For now, this is just calico-kube-controllers.
		l := &appsv1.Deployment{}
		err = r.client.Get(ctx, types.NamespacedName{Name: "calico-kube-controllers", Namespace: common.CalicoNamespace}, l)
		if err != nil && !apierrors.IsNotFound(err) {
			r.status.SetDegraded(operator.ResourceReadError, "Unable to read calico-kube-controllers deployment", err, reqLogger)
			return reconcile.Result{}, err
		} else if apierrors.IsNotFound(err) {
			reqLogger.Info("calico-kube-controllers has been deleted, removing finalizer", "finalizer", render.InstallationControllerFinalizer)
			utils.RemoveInstallationFinalizer(instance, render.InstallationControllerFinalizer)
		} else {
			reqLogger.Info("calico-kube-controller is still present, waiting for termination")
		}

		// Keep an overarching finalizer on the Installation object until ALL necessary dependencies have been cleaned up.
		// This ensures we don't delete the CNI plugin and calico-node too early, as they are a pre-requisite for tearing
		// down networking for other pods deployed by this operator.
		doneTerminating := true
		reqLogger.V(1).Info("Checking if we can remove Installation finalizer", "finalizer", render.OperatorCompleteFinalizer)

		// Wait until the calico-node cluster role binding has been cleaned up. This ClusterRole will only be removed after all other
		// controllers have completed their finalization logic and removed their finalizer from the Installation.
		crb := rbacv1.ClusterRoleBinding{}
		key := types.NamespacedName{Name: "calico-node"}
		err := r.client.Get(ctx, key, &crb)
		if err != nil && !apierrors.IsNotFound(err) {
			r.status.SetDegraded(operator.ResourceNotFound, "Unable to get ClusterRoleBinding", err, reqLogger)
			return reconcile.Result{}, err
		}
		for _, x := range crb.Finalizers {
			if x == render.CNIFinalizer {
				reqLogger.V(1).Info("Installation still finalizing: ClusterRoleBinding calico-node still active")
				doneTerminating = false
			}
		}

		// If all of the above checks passed, we can clear the finalizer responsible for tracking
		// whether all operator cleanup has completed.
		if doneTerminating {
			reqLogger.Info("Removing Installation finalizer", "finalizer", render.OperatorCompleteFinalizer)
			utils.RemoveInstallationFinalizer(instance, render.OperatorCompleteFinalizer)
		}
	} else {
		// Add a finalizer to track whether or not this controller's specific finalization logic has completed.
		utils.SetInstallationFinalizer(instance, render.InstallationControllerFinalizer)

		// Add a finalizer to ensure the Installation is not deleted until all Operator finalization
		// logic has completed.
		utils.SetInstallationFinalizer(instance, render.OperatorCompleteFinalizer)
	}

	// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
	// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
	// Note that we only write the 'base' installation back. We don't want to write the changes from 'overlay', as those should only
	// be stored in the 'overlay' resource.
	if err := r.client.Patch(ctx, instance, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Update Installation with 'overlay'
	overlay := operator.Installation{}
	if err := r.client.Get(ctx, utils.OverlayInstanceKey, &overlay); err != nil {
		if !apierrors.IsNotFound(err) {
			reqLogger.Error(err, "An error occurred when querying the 'overlay' Installation resource")
			return reconcile.Result{}, err
		}
		reqLogger.V(5).Info("no 'overlay' installation found")
	} else {
		instance.Spec = utils.OverrideInstallationSpec(instance.Spec, overlay.Spec)
		reqLogger.V(2).Info("loaded final computed config", "config", instance)

		// Validate the configuration.
		if err := validateCustomResource(instance); err != nil {
			r.status.SetDegraded(operator.InvalidConfigurationError, "Invalid computed config", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if err = r.updateCRDs(ctx, instance.Spec.Variant, reqLogger); err != nil {
		return reconcile.Result{}, err
	}

	// Now that migrated config is stored in the installation resource, we no longer need
	// to check if a migration is needed for the lifetime of the operator.
	r.migrationChecked = true

	// A status is needed at this point for operator scorecard tests.
	// status.variant is written later but for some tests the reconciliation
	// does not get to that point.
	if reflect.DeepEqual(instanceStatus, operator.InstallationStatus{}) {
		instance.Status = operator.InstallationStatus{}
		if err := r.client.Status().Update(ctx, instance); err != nil {
			r.status.SetDegraded(operator.ResourceUpdateError, "Failed to write default status", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Wait for IP pools to be programmed. This may be done out-of-band by the user, or by the operator's IP pool controller.
	currentPools, err := getActivePools(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "error querying IP pools", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Make sure CNI is configured before continuing.
	if instance.Spec.CNI == nil || instance.Spec.CNI.IPAM == nil {
		r.status.SetDegraded(operator.InvalidConfigurationError, "waiting for spec.cni to be filled in", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Determine if this cluster needs IP pools in order to operate.
	// - If the installation has IP pools specified, then the cluster wants IP pools.
	// - If the installation has no IP pools specified, it may still need them if it's using Calico IPAM or networking.
	needsIPPools := instance.Spec.CalicoNetwork != nil && len(instance.Spec.CalicoNetwork.IPPools) != 0
	if instance.Spec.CNI.Type == operator.PluginCalico || instance.Spec.CNI.IPAM.Type == operator.IPAMPluginCalico {
		needsIPPools = true
	}
	if needsIPPools && len(currentPools.Items) == 0 {
		r.status.SetDegraded(operator.ResourceNotFound, "waiting for enabled IP pools to be created", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// If the autoscalar is degraded then trigger a run and recheck the degraded status. If it is still degraded after the
	// the run the reset the degraded status and requeue the request.
	if r.typhaAutoscaler.isDegraded() {
		if err := r.typhaAutoscaler.triggerRun(); err != nil {
			r.status.SetDegraded(operator.ResourceScalingError, "Failed to scale typha", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
	}

	// The operator supports running in a "Calico only" mode so that it doesn't need to run TSEE specific controllers.
	// If we are switching from this mode to one that enables TSEE, we need to restart the operator to enable the other controllers.
	if !r.enterpriseCRDsExist && instance.Spec.Variant == operator.TigeraSecureEnterprise {
		// Perform an API discovery to determine if the necessary APIs exist. If they do, we can reboot into TSEE mode.
		// if they do not, we need to notify the user that the requested configuration is invalid.
		b, err := utils.RequiresTigeraSecure(r.config)
		if b {
			log.Info("Rebooting to enable TigeraSecure controllers")
			os.Exit(0)
		} else if err != nil {
			r.status.SetDegraded(operator.InternalServerError, "Error discovering Tigera Secure availability", err, reqLogger)
		} else {
			r.status.SetDegraded(operator.InternalServerError, "Cannot deploy Tigera Secure", fmt.Errorf("missing Tigera Secure custom resource definitions"), reqLogger)
		}

		// Queue a retry. We don't want to watch the APIServer API since it might not exist and would cause
		// this controller to fail.
		reqLogger.Info("Scheduling a retry", "when", utils.StandardRetry)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Query for pull secrets in operator namespace
	pullSecrets, err := utils.GetNetworkingPullSecrets(&instance.Spec, r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	var managementCluster *operator.ManagementCluster
	var managementClusterConnection *operator.ManagementClusterConnection
	var logCollector *operator.LogCollector
	includeV3NetworkPolicy := false
	if r.enterpriseCRDsExist {
		logCollector, err = utils.GetLogCollector(ctx, r.client)
		if logCollector != nil {
			if err != nil {
				r.status.SetDegraded(operator.ResourceReadError, "Error reading LogCollector", err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		managementCluster, err = utils.GetManagementCluster(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
			return reconcile.Result{}, err
		}

		managementClusterConnection, err = utils.GetManagementClusterConnection(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
			return reconcile.Result{}, err
		}

		if managementClusterConnection != nil && managementCluster != nil {
			err = fmt.Errorf("having both a managementCluster and a managementClusterConnection is not supported")
			r.status.SetDegraded(operator.ResourceValidationError, "", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Ensure the allow-tigera tier exists, before rendering any network policies within it.
		//
		// The creation of the Tier depends on this controller to reconcile it's non-NetworkPolicy resources so that
		// the API Server becomes available. Therefore, if we fail to query the Tier, we exclude NetworkPolicy from
		// reconciliation and tolerate errors arising from the Tier not being created or the API server not being available.
		// We also exclude NetworkPolicy and do not degrade when the Tier watch is not ready, as this means the API server is not available.
		if r.tierWatchReady.IsReady() {
			if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
				if !apierrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
					r.status.SetDegraded(operator.ResourceReadError, "Error querying allow-tigera tier", err, reqLogger)
					return reconcile.Result{}, err
				}
			} else {
				includeV3NetworkPolicy = true
			}
		}
	}

	certificateManager, err := certificatemanager.Create(r.client, &instance.Spec, r.clusterDomain, common.OperatorNamespace(), certificatemanager.WithLogger(reqLogger))
	if err != nil {
		r.status.SetDegraded(operator.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	typhaNodeTLS, err := GetOrCreateTyphaNodeTLSConfig(r.client, certificateManager)
	if err != nil {
		log.Error(err, "Error with Typha/Felix secrets")
		r.status.SetDegraded(operator.CertificateError, "Error with Typha/Felix secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	if instance.Spec.Variant == operator.TigeraSecureEnterprise {
		managerInternalTLSSecret, err := certificateManager.GetCertificate(r.client, render.ManagerInternalTLSSecretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, fmt.Sprintf("Error fetching TLS secret %s in namespace %s", render.ManagerInternalTLSSecretName, common.OperatorNamespace()), err, reqLogger)
			return reconcile.Result{}, nil
		} else if managerInternalTLSSecret != nil {
			// It may seem odd to add the manager internal TLS secret to the trusted bundle for Typha / calico-node, but this bundle is also used
			// for other components in this namespace such as es-kube-controllers, who communicates with Voltron and thus needs to trust this certificate.
			typhaNodeTLS.TrustedBundle.AddCertificates(managerInternalTLSSecret)
		}
	}

	birdTemplates, err := getBirdTemplates(r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error retrieving confd templates", err, reqLogger)
		return reconcile.Result{}, err
	}

	bgpLayout, err := getConfigMap(r.client, render.BGPLayoutConfigMapName)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error retrieving BGP layout ConfigMap", err, reqLogger)
		return reconcile.Result{}, err
	}

	if bgpLayout != nil {
		// Validate that BGP layout ConfigMap has the expected key.
		if _, ok := bgpLayout.Data[render.BGPLayoutConfigMapKey]; !ok {
			err = fmt.Errorf("BGP layout ConfigMap does not have %v key", render.BGPLayoutConfigMapKey)
			r.status.SetDegraded(operator.ResourceValidationError, "Error in BGP layout ConfigMap", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	err = utils.PopulateK8sServiceEndPoint(r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error reading services endpoint configmap", err, reqLogger)
		return reconcile.Result{}, err
	}

	openShiftOnAws := false
	if instance.Spec.KubernetesProvider.IsOpenShift() {
		openShiftOnAws, err = isOpenshiftOnAws(instance, ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error checking if OpenShift is on AWS", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Determine if we need to migrate resources from the kube-system namespace. If
	// we do then we'll render the Calico components with additional node selectors to
	// prevent scheduling, later we will run a migration that migrates nodes one by one
	// to mimic a 'normal' rolling update.
	needNsMigration, err := r.namespaceMigration.NeedsCoreNamespaceMigration(ctx)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error checking if namespace migration is needed", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Set any non-default FelixConfiguration values that we need.
	felixConfiguration, err := utils.PatchFelixConfiguration(ctx, r.client, func(fc *crdv1.FelixConfiguration) (bool, error) {
		// Configure defaults.
		u, err := r.setDefaultsOnFelixConfiguration(ctx, instance, fc, reqLogger)
		if err != nil {
			return false, err
		}

		// Configure nftables mode.
		u2, err := r.setNftablesMode(ctx, instance, fc, reqLogger)
		if err != nil {
			return false, err
		}
		return u || u2, nil
	})
	if err != nil {
		return reconcile.Result{}, err
	}

	// nodeReporterMetricsPort is a port used in Enterprise to host internal metrics.
	// Operator is responsible for creating a service which maps to that port.
	// Here, we'll check the default felixconfiguration to see if the user is specifying
	// a non-default port, and use that value if they are.
	nodeReporterMetricsPort := defaultNodeReporterPort
	var nodePrometheusTLS certificatemanagement.KeyPairInterface
	calicoVersion := components.CalicoRelease
	if instance.Spec.Variant == operator.TigeraSecureEnterprise {

		// Determine the port to use for nodeReporter metrics.
		if felixConfiguration.Spec.PrometheusReporterPort != nil {
			nodeReporterMetricsPort = *felixConfiguration.Spec.PrometheusReporterPort
		}

		if nodeReporterMetricsPort == 0 {
			err := errors.New("felixConfiguration prometheusReporterPort=0 not supported")
			r.status.SetDegraded(operator.InvalidConfigurationError, "invalid metrics port", err, reqLogger)
			return reconcile.Result{}, err
		}

		nodePrometheusTLS, err = certificateManager.GetOrCreateKeyPair(r.client, render.NodePrometheusTLSServerSecret, common.OperatorNamespace(), dns.GetServiceDNSNames(render.CalicoNodeMetricsService, common.CalicoNamespace, r.clusterDomain))
		if err != nil {
			r.status.SetDegraded(operator.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
		if nodePrometheusTLS != nil {
			typhaNodeTLS.TrustedBundle.AddCertificates(nodePrometheusTLS)
		}
		prometheusClientCert, err := certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operator.CertificateError, "Unable to fetch prometheus certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
		if prometheusClientCert != nil {
			typhaNodeTLS.TrustedBundle.AddCertificates(prometheusClientCert)
		}

		// es-kube-controllers needs to trust the ESGW certificate. We'll fetch it here and add it to the trusted bundle.
		// Note that although we're adding this to the typhaNodeTLS trusted bundle, it will be used by es-kube-controllers. This is because
		// all components within this namespace share a trusted CA bundle. This is necessary because prior to v3.13 secrets were not signed by
		// a single CA so we need to include each individually.
		esgwCertificate, err := certificateManager.GetCertificate(r.client, relasticsearch.PublicCertSecret, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operator.CertificateError, fmt.Sprintf("Failed to retrieve / validate  %s", relasticsearch.PublicCertSecret), err, reqLogger)
			return reconcile.Result{}, err
		}
		if esgwCertificate != nil {
			typhaNodeTLS.TrustedBundle.AddCertificates(esgwCertificate)
		}

		calicoVersion = components.EnterpriseRelease
	}

	kubeControllersMetricsPort, err := utils.GetKubeControllerMetricsPort(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Unable to read KubeControllersConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Secure calico kube controller metrics.
	var kubeControllerTLS certificatemanagement.KeyPairInterface
	if instance.Spec.Variant == operator.TigeraSecureEnterprise {
		// Create or Get TLS certificates for kube controller.
		kubeControllerTLS, err = certificateManager.GetOrCreateKeyPair(
			r.client,
			kubecontrollers.KubeControllerPrometheusTLSSecret,
			common.OperatorNamespace(),
			dns.GetServiceDNSNames(kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, r.clusterDomain))
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error finding or creating TLS certificate kube controllers metric", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Add prometheus client certificate to Trusted bundle.
		kubecontrollerprometheusTLS, err := certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Failed to get certificate for kube controllers", err, reqLogger)
			return reconcile.Result{}, err
		} else if kubecontrollerprometheusTLS != nil {
			typhaNodeTLS.TrustedBundle.AddCertificates(kubeControllerTLS, kubecontrollerprometheusTLS)
		}
	}

	nodeAppArmorProfile := ""
	a := instance.GetObjectMeta().GetAnnotations()
	if val, ok := a[techPreviewFeatureSeccompApparmor]; ok {
		nodeAppArmorProfile = val
	}

	components := []render.Component{}

	namespaceCfg := &render.NamespaceConfiguration{
		Installation: &instance.Spec,
		PullSecrets:  pullSecrets,
	}
	// Render namespaces for Calico.
	components = append(components, render.Namespaces(namespaceCfg))

	if newActiveCM != nil && !installationMarkedForDeletion {
		log.Info("adding active configmap")
		components = append(components, render.NewPassthrough(newActiveCM))
	}

	// If we're on OpenShift on AWS render a Job (and needed resources) to
	// setup the security groups we need for IPIP, BGP, and Typha communication.
	if openShiftOnAws {
		// Detect if this cluster is an OpenShift HPC hosted cluster, as AWS
		// security group setup is different in this case.
		hostedOpenShift, err := isHostedOpenShift(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error checking if in a hosted OpenShift HCP cluster on AWS", err, reqLogger)
			return reconcile.Result{}, err
		}
		awsSGSetupCfg := &render.AWSSGSetupConfiguration{
			PullSecrets:     instance.Spec.ImagePullSecrets,
			Installation:    &instance.Spec,
			HostedOpenShift: hostedOpenShift,
		}
		awsSetup, err := render.AWSSecurityGroupSetup(awsSGSetupCfg)
		if err != nil {
			// If there is a problem rendering this do not degrade or stop rendering
			// anything else.
			log.Info(err.Error())
		} else {
			components = append(components, awsSetup)
		}
	}

	if instance.Spec.KubernetesProvider.IsGKE() {
		// We do this only for GKE as other providers don't (yet?)
		// automatically add resource quota that constrains whether
		// Calico components that are marked cluster or node critical
		// can be scheduled.
		criticalPriorityClasses := []string{render.NodePriorityClassName, render.ClusterPriorityClassName}
		resourceQuotaObj := resourcequota.ResourceQuotaForPriorityClassScope(resourcequota.CalicoCriticalResourceQuotaName,
			common.CalicoNamespace, criticalPriorityClasses)
		resourceQuotaComponent := render.NewPassthrough(resourceQuotaObj)
		components = append(components, resourceQuotaComponent)

	}

	components = append(components,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       common.CalicoNamespace,
			ServiceAccounts: []string{render.CalicoNodeObjectName, render.TyphaServiceAccountName, kubecontrollers.KubeControllerServiceAccount},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.NodeSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(nodePrometheusTLS, true, true),
				rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.TyphaSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(kubeControllerTLS, true, true),
			},
			TrustedBundle: typhaNodeTLS.TrustedBundle,
		}))

	// Build a configuration for rendering calico/typha.
	typhaCfg := render.TyphaConfiguration{
		K8sServiceEp:      k8sapi.Endpoint,
		Installation:      &instance.Spec,
		TLS:               typhaNodeTLS,
		MigrateNamespaces: needNsMigration,
		ClusterDomain:     r.clusterDomain,
		FelixHealthPort:   *felixConfiguration.Spec.HealthPort,
	}
	components = append(components, render.Typha(&typhaCfg))

	// See the section 'Use of Finalizers for graceful termination' at the top of this file for terminating details.
	canRemoveCNI := false
	if installationMarkedForDeletion {
		// Wait for other controllers to complete their finalizer teardown before removing the CNI plugin.
		canRemoveCNI = true
		for _, f := range instance.Finalizers {
			if f != render.OperatorCompleteFinalizer {
				reqLogger.Info("Waiting for finalization to complete before removing CNI resources", "finalizer", f)
				canRemoveCNI = false
			}
		}
	} else {
		// In some rare scenarios, we can hit a deadlock where resources have been marked with a deletion timestamp but the operator
		// does not recognize that it must remove their finalizers. This can happen if, for example, someone manually
		// deletes a ServiceAccount instead of deleting the Installation object. In this case, we need
		// to allow the deletion to complete so the operator can re-create the resources. Otherwise the objects will be stuck terminating forever.
		toCheck := render.CNIPluginFinalizedObjects()
		needsCleanup := []client.Object{}
		for _, obj := range toCheck {
			if err := r.client.Get(ctx, types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}, obj); err != nil {
				if !apierrors.IsNotFound(err) {
					r.status.SetDegraded(operator.ResourceReadError, "Error querying object", err, reqLogger)
					return reconcile.Result{}, err
				}
				// Not found - nothing to do.
				continue
			}
			if obj.GetDeletionTimestamp() != nil {
				// The object is marked for deletion, but the installation is not terminating. We need to remove the finalizers from this object
				// so that it can be deleted and recreated.
				reqLogger.Info("Object is marked for deletion but installation is not terminating",
					"kind", obj.GetObjectKind(),
					"name", obj.GetName(),
					"namespace", obj.GetNamespace(),
				)
				obj.SetFinalizers(stringsutil.RemoveStringInSlice(render.CNIFinalizer, obj.GetFinalizers()))
				needsCleanup = append(needsCleanup, obj)
			}
		}
		if len(needsCleanup) > 0 {
			// Add a component to remove the finalizers from the objects that need it.
			reqLogger.Info("Removing finalizers from objects that are wronly marked for deletion")
			components = append(components, render.NewPassthrough(needsCleanup...))
		}
	}

	// Fetch any existing default BGPConfiguration object.
	bgpConfiguration := &crdv1.BGPConfiguration{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfiguration)
	if err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operator.ResourceReadError, "Unable to read BGPConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Build a configuration for rendering calico/node.
	nodeCfg := render.NodeConfiguration{
		K8sServiceEp:            k8sapi.Endpoint,
		Installation:            &instance.Spec,
		IPPools:                 crdPoolsToOperator(currentPools.Items),
		LogCollector:            logCollector,
		BirdTemplates:           birdTemplates,
		TLS:                     typhaNodeTLS,
		ClusterDomain:           r.clusterDomain,
		NodeReporterMetricsPort: nodeReporterMetricsPort,
		BGPLayouts:              bgpLayout,
		NodeAppArmorProfile:     nodeAppArmorProfile,
		MigrateNamespaces:       needNsMigration,
		CanRemoveCNIFinalizer:   canRemoveCNI,
		PrometheusServerTLS:     nodePrometheusTLS,
		FelixHealthPort:         *felixConfiguration.Spec.HealthPort,
		BindMode:                bgpConfiguration.Spec.BindMode,
	}
	components = append(components, render.Node(&nodeCfg))

	csiCfg := render.CSIConfiguration{
		Installation: &instance.Spec,
		Terminating:  installationMarkedForDeletion,
		OpenShift:    instance.Spec.KubernetesProvider.IsOpenShift(),
	}
	components = append(components, render.CSI(&csiCfg))

	// Build a configuration for rendering calico/kube-controllers.
	kubeControllersCfg := kubecontrollers.KubeControllersConfiguration{
		K8sServiceEp:                k8sapi.Endpoint,
		Installation:                &instance.Spec,
		ManagementCluster:           managementCluster,
		ManagementClusterConnection: managementClusterConnection,
		ClusterDomain:               r.clusterDomain,
		MetricsPort:                 kubeControllersMetricsPort,
		Terminating:                 installationMarkedForDeletion,
		MetricsServerTLS:            kubeControllerTLS,
		TrustedBundle:               typhaNodeTLS.TrustedBundle,
		Namespace:                   common.CalicoNamespace,
		BindingNamespaces:           []string{common.CalicoNamespace},
	}
	components = append(components, kubecontrollers.NewCalicoKubeControllers(&kubeControllersCfg))

	// v3 NetworkPolicy will fail to reconcile if the API server deployment is unhealthy. In case the API Server
	// deployment becomes unhealthy and reconciliation of non-NetworkPolicy resources in the core controller
	// would resolve it, we render the network policies of components last to prevent a chicken-and-egg scenario.
	if includeV3NetworkPolicy {
		components = append(components,
			kubecontrollers.NewCalicoKubeControllersPolicy(&kubeControllersCfg),
			render.NewPassthrough(networkpolicy.AllowTigeraDefaultDeny(common.CalicoNamespace)),
		)
	}

	installEnvoyGateway := (instance.Spec.Variant == v1.TigeraSecureEnterprise)
	if installEnvoyGateway {
		if err = r.installEnvoyGateway(ctx, reqLogger); err != nil {
			return reconcile.Result{}, err
		}
	}

	imageSet, err := imageset.GetImageSet(ctx, r.client, instance.Spec.Variant)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error getting ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if imageSet == nil {
		// There is no imageSet for the configured variant, but check to see if there are any
		// ImageSets with a different variant so we can give the user some kind of indication
		// to why an existing ImageSet is being ignored.
		nvis, err := imageset.DoesNonVariantImageSetExist(ctx, r.client, instance.Spec.Variant)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error checking for non-variant ImageSet", err, reqLogger)
			return reconcile.Result{}, err
		} else {
			if nvis {
				reqLogger.Info("An ImageSet exists for a different variant")
			}
		}
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		r.status.SetDegraded(operator.ResourceValidationError, "Error validating ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ResolveImages(imageSet, components...); err != nil {
		r.status.SetDegraded(operator.ResourceValidationError, "Error resolving ImageSet for components", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a component handler to create or update the rendered components.
	handler := r.newComponentHandler(log, r.client, r.scheme, instance)
	for _, component := range components {
		if err := handler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
			r.status.SetDegraded(operator.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// TODO: We handle too many components in this controller at the moment. Once we are done consolidating,
	// we can have the CreateOrUpdate logic handle this for us.
	r.status.AddDaemonsets([]types.NamespacedName{{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}})
	r.status.AddDeployments([]types.NamespacedName{{Name: common.KubeControllersDeploymentName, Namespace: common.CalicoNamespace}})
	certificateManager.AddToStatusManager(r.status, common.CalicoNamespace)

	// Run this after we have rendered our components so the new (operator created)
	// Deployments and Daemonset exist with our special migration nodeSelectors.
	if needNsMigration {
		if err := r.namespaceMigration.Run(ctx, reqLogger); err != nil {
			r.status.SetDegraded(operator.ResourceMigrationError, "error migrating resources to calico-system", err, reqLogger)
			// We should always requeue a migration problem. Don't return error
			// to make sure we never start backing off retrying.
			return reconcile.Result{Requeue: true}, nil
		}
		// Requeue so we can update our resources (without the migration changes)
		return reconcile.Result{Requeue: true}, nil
	} else if r.namespaceMigration.NeedCleanup() {
		if err := r.namespaceMigration.CleanupMigration(ctx, reqLogger); err != nil {
			r.status.SetDegraded(operator.ResourceMigrationError, "error migrating resources to calico-system", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Determine which MTU to use in the status fields.
	statusMTU := 0
	if instance.Spec.CalicoNetwork != nil && instance.Spec.CalicoNetwork.MTU != nil {
		// If set explicitly in the spec, then use that.
		statusMTU = int(*instance.Spec.CalicoNetwork.MTU)
	} else if calicoDirectoryExists() {
		// Otherwise, if the /var/lib/calico directory is present, see if we can read
		// a value from there.
		statusMTU, err = readMTUFile()
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "error reading network MTU", err, reqLogger)
			return reconcile.Result{}, err
		}
	} else {
		// If neither is present, then we don't have MTU information available.
		// Auto-detection will still be used for Calico, but the operator won't know
		// what the value is.
		reqLogger.V(1).Info("Unable to determine MTU - no explicit config, and /var/lib/calico is not mounted")
	}

	// We have successfully reconciled the Calico installation.
	if instance.Spec.KubernetesProvider.IsOpenShift() {
		openshiftConfig := &configv1.Network{}
		err = r.client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Unable to update OpenShift Network config: failed to read OpenShift network configuration", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Get resource before updating to use in the Patch call.
		patchFrom := client.MergeFrom(openshiftConfig.DeepCopy())

		// Update the config status with the current state.
		reqLogger.WithValues("openshiftConfig", openshiftConfig).V(1).Info("Updating OpenShift cluster network status")
		openshiftConfig.Status.ClusterNetwork = openshiftConfig.Spec.ClusterNetwork
		openshiftConfig.Status.ServiceNetwork = openshiftConfig.Spec.ServiceNetwork
		openshiftConfig.Status.NetworkType = "Calico"
		openshiftConfig.Status.ClusterNetworkMTU = statusMTU

		if err = r.client.Patch(ctx, openshiftConfig, patchFrom); err != nil {
			r.status.SetDegraded(operator.ResourcePatchError, "Error patching openshift network status", err, reqLogger.WithValues("openshiftConfig", openshiftConfig))
			return reconcile.Result{}, err
		}
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	// If eBPF is enabled in the operator API, patch FelixConfiguration to enable it within Felix.
	_, err = utils.PatchFelixConfiguration(ctx, r.client, func(fc *crdv1.FelixConfiguration) (bool, error) {
		return r.setBPFUpdatesOnFelixConfiguration(ctx, instance, fc, reqLogger)
	})
	if err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Error updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Write updated status.
	if statusMTU > math.MaxInt32 || statusMTU < 0 {
		return reconcile.Result{}, errors.New("the MTU size should be between Max int32 (2147483647) and 0")
	}
	instance.Status.MTU = int32(statusMTU)
	// Variant and CalicoVersion must be updated at the same time.
	instance.Status.Variant = instance.Spec.Variant
	instance.Status.CalicoVersion = calicoVersion
	if imageSet == nil {
		instance.Status.ImageSet = ""
	} else {
		instance.Status.ImageSet = imageSet.Name
	}
	instance.Status.Computed = &instance.Spec
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}

	reqLogger.V(1).Info("Finished reconciling Installation")
	return reconcile.Result{}, nil
}

func readMTUFile() (int, error) {
	filename := "/var/lib/calico/mtu"
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return zero.
			return 0, nil
		}
		return 0, err
	}
	res, err := strconv.Atoi(strings.TrimSpace(string(data)))
	return res, err
}

func calicoDirectoryExists() bool {
	_, err := os.Stat("/var/lib/calico")
	return err == nil
}

func GetOrCreateTyphaNodeTLSConfig(cli client.Client, certificateManager certificatemanager.CertificateManager) (*render.TyphaNodeTLS, error) {
	return getOrCreateTyphaNodeTLSConfig(cli, certificateManager, certificateManager.GetOrCreateKeyPair)
}

func GetTyphaNodeTLSConfig(cli client.Client, certificateManager certificatemanager.CertificateManager) (*render.TyphaNodeTLS, error) {
	return getOrCreateTyphaNodeTLSConfig(cli, certificateManager, certificateManager.GetKeyPair)
}

// getOrCreateTyphaNodeTLSConfig reads and validates the CA ConfigMap and Secrets for
// Typha and Felix configuration. It returns the validated resources or error
// if there was one.
func getOrCreateTyphaNodeTLSConfig(cli client.Client, certificateManager certificatemanager.CertificateManager, createKeyPairFunc func(cli client.Client, secretName, secretNamespace string, dnsNames []string) (certificatemanagement.KeyPairInterface, error)) (*render.TyphaNodeTLS, error) {
	// accumulate all the error messages so all problems with the certs
	// and CA are reported.
	var errMsgs []string
	getOrCreateKeyPair := func(secretName, commonName string) (keyPair certificatemanagement.KeyPairInterface, cn string, uriSAN string) {
		keyPair, err := createKeyPairFunc(cli, secretName, common.OperatorNamespace(), []string{commonName})
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		} else {

			if !keyPair.BYO() {
				cn = commonName
			} else {
				// todo: Integrate this with the new certificate manager or find another alternative for uriSAN and cn.
				secret, err := utils.GetSecret(context.Background(), cli, secretName, common.OperatorNamespace())
				if err != nil {
					errMsgs = append(errMsgs, err.Error())
				} else if secret != nil {
					data := secret.Data
					if data != nil {
						cn, uriSAN = string(data[render.CommonName]), string(data[render.URISAN])
					}
				}
			}
			if cn == "" && uriSAN == "" {
				errMsgs = append(errMsgs, "CertPair for Felix does not contain common-name or uri-san")
			}
		}
		return
	}
	node, nodeCommonName, nodeURISAN := getOrCreateKeyPair(render.NodeTLSSecretName, render.FelixCommonName)
	typha, typhaCommonName, typhaURISAN := getOrCreateKeyPair(render.TyphaTLSSecretName, render.TyphaCommonName)
	var trustedBundle certificatemanagement.TrustedBundle
	configMap, err := getConfigMap(cli, render.TyphaCAConfigMapName)
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CA for Typha is invalid: %s", err))
	} else if configMap != nil {
		if len(configMap.Data[render.TyphaCABundleName]) == 0 {
			errMsgs = append(errMsgs, fmt.Sprintf("ConfigMap %q does not have a field named %q", render.TyphaCAConfigMapName, render.TyphaCABundleName))
		} else {
			trustedBundle, err = certificateManager.CreateTrustedBundleWithSystemRootCertificates(node, typha,
				certificatemanagement.NewCertificate(render.TyphaCAConfigMapName, common.CalicoNamespace, []byte(configMap.Data[render.TyphaCABundleName]), nil))
			if err != nil {
				errMsgs = append(errMsgs, fmt.Sprintf("Error creating trusted bundle %s", err))
			}
		}
	} else {
		trustedBundle, err = certificateManager.CreateTrustedBundleWithSystemRootCertificates(node, typha)
		if err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("Error creating trusted bundle %s", err))
		}
	}
	if len(errMsgs) != 0 {
		return nil, fmt.Errorf("%s", strings.Join(errMsgs, ";"))
	}
	return &render.TyphaNodeTLS{
		TrustedBundle:   trustedBundle,
		TyphaSecret:     typha,
		TyphaCommonName: typhaCommonName,
		TyphaURISAN:     typhaURISAN,
		NodeSecret:      node,
		NodeCommonName:  nodeCommonName,
		NodeURISAN:      nodeURISAN,
	}, nil
}

func (r *ReconcileInstallation) setNftablesMode(_ context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, reqLogger logr.Logger) (bool, error) {
	updated := false

	// Set the FelixConfiguration nftables dataplane mode based on the operator configuration. We do this unconditonally because
	// we don't need to handle upgrades from versions that were previously FelixConfiguration only - nftables mode has always
	// been controlled by the operator.
	if install.Spec.CalicoNetwork.LinuxDataplane != nil {
		if *install.Spec.CalicoNetwork.LinuxDataplane == operatorv1.LinuxDataplaneNftables {
			// The operator is configured to use the nftables dataplane. Configure Felix to use nftables.
			nftablesMode := crdv1.NFTablesModeEnabled
			fc.Spec.NFTablesMode = &nftablesMode
			updated = true
		} else {
			// The operator is configured to use another dataplane. Disable nftables.
			nftablesMode := crdv1.NFTablesModeDisabled
			fc.Spec.NFTablesMode = &nftablesMode
			updated = true
		}
	}
	if updated {
		reqLogger.Info("Patching nftables mode", "nftablesMode", *fc.Spec.NFTablesMode)
	}
	return updated, nil
}

// setDefaultOnFelixConfiguration will take the passed in fc and add any defaulting needed
// based on the install config.
func (r *ReconcileInstallation) setDefaultsOnFelixConfiguration(ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, reqLogger logr.Logger) (bool, error) {
	updated := false

	switch install.Spec.CNI.Type {
	// If we're using the AWS CNI plugin we need to ensure the route tables that calico-node
	// uses do not conflict with the ones the AWS CNI plugin uses so default them
	// in the FelixConfiguration if they are not already set.
	case operator.PluginAmazonVPC:
		if fc.Spec.RouteTableRange == nil {
			updated = true
			// Defaulting based on that AWS might be using the following:
			// - The ENI device number + 1
			//   Currently the max number of ENIs for any host is 15.
			//   p4d.24xlarge is reported to support 4x15 ENI but it uses 4 cards
			//   and AWS CNI only uses ENIs on card 0.
			// - The VLAN table ID + 100 (there is doubt if this is true)
			fc.Spec.RouteTableRange = &crdv1.RouteTableRange{
				Min: 65,
				Max: 99,
			}
		}
	case operator.PluginGKE:
		if fc.Spec.RouteTableRange == nil {
			updated = true
			// Don't conflict with the GKE CNI plugin's routes.
			fc.Spec.RouteTableRange = &crdv1.RouteTableRange{
				Min: 10,
				Max: 250,
			}
		}
	}

	// Determine the felix health port to use. Prefer the configuration from FelixConfiguration,
	// but default to 9099 (or 9199 on OpenShift). We will also write back whatever we select to FelixConfiguration.
	felixHealthPort := 9099
	if install.Spec.KubernetesProvider.IsOpenShift() {
		felixHealthPort = 9199
	}
	if fc.Spec.HealthPort == nil {
		fc.Spec.HealthPort = &felixHealthPort
		updated = true
	}
	vxlanVNI := 4096
	// MKE uses a vxlanVNI:4096 and vxlanPort:4789 for its docker swarm vxlan.
	// This results in a conflict with calico's VXLAN and the vxlan.calico interface
	// gets deleted. To fix this we change the vxlanVNI to 10000 as recommended by
	// MKE docs (https://docs.mirantis.com/mke/3.7/cli-ref/mke-cli-install.html).
	if install.Spec.KubernetesProvider == operator.ProviderDockerEE {
		vxlanVNI = 10000
	}

	if fc.Spec.VXLANVNI == nil {
		fc.Spec.VXLANVNI = &vxlanVNI
		updated = true
	}

	if install.Spec.KubernetesProvider == operator.ProviderDockerEE {
		// Set bpfHostConntrackBypass to false for eBPF dataplane to work with MKE
		if install.Spec.BPFEnabled() && fc.Spec.BPFHostConntrackBypass == nil {
			disableBPFHostConntrackBypass(fc)
			updated = true
		}
	}

	if install.Spec.Variant == operator.TigeraSecureEnterprise {
		// Some platforms need a different default setting for dnsTrustedServers, because their DNS service is not named "kube-dns".
		dnsService := ""
		switch install.Spec.KubernetesProvider {
		case operator.ProviderOpenShift:
			dnsService = "k8s-service:openshift-dns/dns-default"
		case operator.ProviderRKE2:
			dnsService = "k8s-service:kube-system/rke2-coredns-rke2-coredns"
		}
		if dnsService != "" {
			felixDefault := "k8s-service:kube-dns"
			trustedServers := []string{dnsService}
			// Keep any other values that are already configured, excepting the value
			// that we are setting and the kube-dns default.
			existingSetting := ""
			if fc.Spec.DNSTrustedServers != nil {
				existingSetting = strings.Join(*(fc.Spec.DNSTrustedServers), ",")
				for _, server := range *(fc.Spec.DNSTrustedServers) {
					if server != felixDefault && server != dnsService {
						trustedServers = append(trustedServers, server)
					}
				}
			}
			newSetting := strings.Join(trustedServers, ",")
			if newSetting != existingSetting {
				fc.Spec.DNSTrustedServers = &trustedServers
				updated = true
			}
		}
	}

	// If BPF is enabled, but not set on FelixConfiguration, do so here. This could happen when an older
	// version of operator is replaced by the new one. Older versions of the operator used an
	// environment variable to enable BPF, but we no longer do so. In order to prevent disruption
	// when the environment variable is removed by the render code of the new operator, make sure
	// FelixConfiguration has the correct value set.

	// If calico-node daemonset exists, we need to check the ENV VAR and set FelixConfiguration accordingly.
	// Otherwise, just move on.
	ds := &appsv1.DaemonSet{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: common.CalicoNamespace, Name: common.NodeDaemonSetName}, ds)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			reqLogger.Error(err, "An error occurred when getting the Daemonset resource")
			return false, err
		}
	} else {
		bpfEnabledOnDaemonsetWithEnvVar, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
		if err != nil {
			reqLogger.Error(err, "An error occurred when querying the Daemonset resource")
			return false, err
		} else if bpfEnabledOnDaemonsetWithEnvVar && !bpfEnabledOnFelixConfig(fc) {
			err = setBPFEnabledOnFelixConfiguration(fc, true)
			if err != nil {
				reqLogger.Error(err, "Unable to enable eBPF data plane")
				return false, err
			} else {
				updated = true
			}
		}
	}

	return updated, nil
}

// setBPFUpdatesOnFelixConfiguration will take the passed in fc and update any BPF properties needed
// based on the install config and the daemonset.
func (r *ReconcileInstallation) setBPFUpdatesOnFelixConfiguration(ctx context.Context, install *operator.Installation, fc *crdv1.FelixConfiguration, reqLogger logr.Logger) (bool, error) {
	updated := false

	bpfEnabledOnInstall := install.Spec.BPFEnabled()
	if bpfEnabledOnInstall {
		ds := &appsv1.DaemonSet{}
		err := r.client.Get(ctx, types.NamespacedName{Namespace: common.CalicoNamespace, Name: common.NodeDaemonSetName}, ds)
		if err != nil {
			return false, err
		}
		if !bpfEnabledOnFelixConfig(fc) && isRolloutCompleteWithBPFVolumes(ds) {
			err := setBPFEnabledOnFelixConfiguration(fc, bpfEnabledOnInstall)
			if err != nil {
				reqLogger.Error(err, "Unable to enable eBPF data plane")
				return false, err
			} else {
				updated = true
			}
		}
	} else {
		if fc.Spec.BPFEnabled == nil || *fc.Spec.BPFEnabled {
			err := setBPFEnabledOnFelixConfiguration(fc, bpfEnabledOnInstall)
			if err != nil {
				reqLogger.Error(err, "Unable to enable eBPF data plane")
				return false, err
			} else {
				updated = true
			}
		}
	}

	return updated, nil
}

var osExitOverride = os.Exit

// checkActive verifies the operator that calls this function is designated as the active operator.
// If this operator is not designated as active then this function does an os.Exit(0) so the operator
// gets restarted.
// If this operator is the designated operator (or assumed because there is no designation) then
// this function returns with no error.
// If the active operator designation needs to be set then the first return field is a ConfigMap that
// should be created to set the designation, other wise the field is nil.
// The second returned field reports if there was an error when trying to determine active operator.
func (r *ReconcileInstallation) checkActive(log logr.Logger) (*corev1.ConfigMap, error) {
	cm, err := active.GetActiveConfigMap(r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceValidationError,
			fmt.Sprintf("Error determining if operator in %s namespace is active", common.OperatorNamespace()),
			err,
			log)
		return nil, err
	}
	imActive, activeNs := active.IsThisOperatorActive(cm)
	if !imActive {
		log.Info("Exiting because this operator is not designated active",
			"my-namespace", common.OperatorNamespace(),
			"active-namespace", activeNs)
		osExitOverride(0)
		return nil, fmt.Errorf("returning error for test purposes")
	}

	if cm == nil {
		return active.GenerateMyActiveConfigMap(), nil
	} else {
		return nil, nil
	}
}

func (r *ReconcileInstallation) updateCRDs(ctx context.Context, variant operator.ProductVariant, log logr.Logger) error {
	if !r.manageCRDs {
		return nil
	}
	crdComponent := render.NewPassthrough(crds.ToRuntimeObjects(crds.GetCRDs(variant)...)...)
	// Specify nil for the CR so no ownership is put on the CRDs. We do this so removing the
	// Installation CR will not remove the CRDs.
	handler := r.newComponentHandler(log, r.client, r.scheme, nil)
	if err := handler.CreateOrUpdateOrDelete(ctx, crdComponent, nil); err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Error creating / updating CRD resource", err, log)
		return err
	}
	return nil
}

func (r *ReconcileInstallation) installEnvoyGateway(ctx context.Context, log logr.Logger) error {
	egComponent := render.NewPassthrough(envoygateway.GetResources(log)...)
	// Specify nil for the CR so no ownership is put on the gateway resources.  We do this so
	// removing the Installation CR will not remove them.
	handler := r.newComponentHandler(log, r.client, r.scheme, nil)
	if err := handler.CreateOrUpdateOrDelete(ctx, egComponent, nil); err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Error creating / updating gateway resource", err, log)
		return err
	}
	return nil
}

func getConfigMap(client client.Client, cmName string) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read ConfigMap %q: %s", cmName, err)
	}
	return cm, nil
}

func getBirdTemplates(client client.Client) (map[string]string, error) {
	cm, err := getConfigMap(client, render.BirdTemplatesConfigMapName)
	if err != nil || cm == nil {
		return nil, err
	}
	bt := make(map[string]string)
	for k, v := range cm.Data {
		bt[k] = v
	}
	return bt, nil
}

// isOpenshiftOnAws returns true if running on OpenShift on AWS, this is determined
// by the KubernetesProvider on the installation and the infrastructure OpenShift
// status.
func isOpenshiftOnAws(install *operator.Installation, ctx context.Context, client client.Client) (bool, error) {
	if !install.Spec.KubernetesProvider.IsOpenShift() {
		return false, nil
	}
	infra := configv1.Infrastructure{}
	// If configured to run in openshift, then also fetch the openshift configuration API.
	if err := client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, &infra); err != nil {
		return false, fmt.Errorf("unable to read OpenShift infrastructure configuration: %w", err)
	}
	return (infra.Status.PlatformStatus.Type == "AWS"), nil
}

// isHostedOpenShift returns true if this cluster is an OpenShift HCP hosted cluster.
func isHostedOpenShift(ctx context.Context, client client.Client) (bool, error) {
	infra := configv1.Infrastructure{}
	if err := client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, &infra); err != nil {
		return false, fmt.Errorf("unable to read OpenShift infrastructure configuration: %w", err)
	}
	return (infra.Status.ControlPlaneTopology == "External"), nil
}

func updateInstallationForAWSNode(i *operator.Installation, ds *appsv1.DaemonSet) error {
	if ds == nil {
		return nil
	}

	if i.Spec.CNI == nil {
		i.Spec.CNI = &operator.CNISpec{}
	}

	if i.Spec.CNI.Type == "" {
		i.Spec.CNI.Type = operator.PluginAmazonVPC
	}
	return nil
}

func addCRDWatches(c ctrlruntime.Controller, v operator.ProductVariant) error {
	pred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			// Create occurs because we've created it, so we can safely ignore it.
			return false
		},
	}
	for _, x := range crds.GetCRDs(v) {
		if err := c.WatchObject(x, &handler.EnqueueRequestForObject{}, pred); err != nil {
			return err
		}
	}
	return nil
}

func crdPoolsToOperator(crds []crdv1.IPPool) []operator.IPPool {
	pools := []v1.IPPool{}
	for _, p := range crds {
		op := v1.IPPool{}
		op.FromProjectCalicoV1(p)
		pools = append(pools, op)
	}
	return pools
}
