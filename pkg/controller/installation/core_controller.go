// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

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
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	operator "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/migration"
	"github.com/tigera/operator/pkg/controller/migration/convert"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/go-logr/logr"
	apps "k8s.io/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	techPreviewFeatureSeccompApparmor = "tech-preview.operator.tigera.io/node-apparmor-profile"

	// The default port used by calico/node to report Calico Enterprise internal metrics.
	// This is separate from the calico/node prometheus metrics port, which is user configurable.
	defaultNodeReporterPort = 9081
)

var log = logf.Log.WithName("controller_installation")
var openshiftNetworkConfig = "cluster"

// Add creates a new Installation Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	ri, err := newReconciler(mgr, opts)
	if err != nil {
		return fmt.Errorf("failed to create Core Reconciler: %w", err)
	}
	return add(mgr, ri)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) (*ReconcileInstallation, error) {
	nm, err := migration.NewCoreNamespaceMigration(mgr.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize Namespace migration: %w", err)
	}

	statusManager := status.New(mgr.GetClient(), "calico", opts.KubernetesVersion)

	// The typhaAutoscaler needs a clientset.
	cs, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return nil, err
	}

	// Create a Typha autoscaler.
	nodeListWatch := cache.NewListWatchFromClient(cs.CoreV1().RESTClient(), "nodes", "", fields.Everything())
	typhaListWatch := cache.NewListWatchFromClient(cs.AppsV1().RESTClient(), "deployments", "calico-system", fields.OneTermEqualSelector("metadata.name", "calico-typha"))
	typhaScaler := newTyphaAutoscaler(cs, nodeListWatch, typhaListWatch, statusManager)

	r := &ReconcileInstallation{
		config:               mgr.GetConfig(),
		client:               mgr.GetClient(),
		scheme:               mgr.GetScheme(),
		watches:              make(map[runtime.Object]struct{}),
		autoDetectedProvider: opts.DetectedProvider,
		status:               statusManager,
		typhaAutoscaler:      typhaScaler,
		namespaceMigration:   nm,
		amazonCRDExists:      opts.AmazonCRDExists,
		enterpriseCRDsExist:  opts.EnterpriseCRDExists,
		clusterDomain:        opts.ClusterDomain,
	}
	r.status.Run()
	r.typhaAutoscaler.start()
	return r, nil
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r *ReconcileInstallation) error {
	// Create a new controller
	c, err := controller.New("tigera-installation-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create tigera-installation-controller: %w", err)
	}

	r.controller = c

	// Watch for changes to primary resource Installation
	err = c.Watch(&source.Kind{Type: &operator.Installation{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %w", err)
	}

	if r.autoDetectedProvider == operator.ProviderOpenShift {
		// Watch for openshift network configuration as well. If we're running in OpenShift, we need to
		// merge this configuration with our own and the write back the status object.
		err = c.Watch(&source.Kind{Type: &configv1.Network{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("tigera-installation-controller failed to watch openshift network config: %w", err)
			}
		}
	}

	// Watch for secrets in the operator namespace. We watch for all secrets, since we care
	// about specifically named ones - e.g., manager-tls, as well as image pull secrets that
	// may have been provided by the user with arbitrary names.
	err = utils.AddSecretsWatch(c, "", rmeta.OperatorNamespace())
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch secrets: %w", err)
	}

	for _, cm := range []string{render.BirdTemplatesConfigMapName, render.BGPLayoutConfigMapName, render.K8sSvcEndpointConfigMapName} {
		if err = utils.AddConfigMapWatch(c, cm, rmeta.OperatorNamespace()); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch ConfigMap %s: %w", cm, err)
		}
	}

	// Only watch the AmazonCloudIntegration if the CRD is available
	if r.amazonCRDExists {
		err = c.Watch(&source.Kind{Type: &operator.AmazonCloudIntegration{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			log.V(5).Info("Failed to create AmazonCloudIntegration watch", "err", err)
			return fmt.Errorf("amazoncloudintegration-controller failed to watch primary resource: %w", err)
		}
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch ImageSet: %w", err)
	}

	for _, t := range secondaryResources() {
		pred := predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				// Create occurs because we've created it, so we can safely ignore it.
				return false
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				if utils.IgnoreObject(e.ObjectOld) && !utils.IgnoreObject(e.ObjectNew) {
					// Don't skip the removal of the "ignore" annotation. We want to
					// reconcile when that happens.
					return true
				}
				// Otherwise, ignore updates to objects when metadata.Generation does not change.
				return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
			},
		}
		err = c.Watch(&source.Kind{Type: t}, &handler.EnqueueRequestForOwner{
			IsController: true,
			OwnerType:    &operator.Installation{},
		}, pred)
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch %s: %w", t, err)
		}
	}

	// Watch for changes to KubeControllersConfiguration.
	err = c.Watch(&source.Kind{Type: &crdv1.KubeControllersConfiguration{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-installation-controller failed to watch KubeControllersConfiguration resource: %w", err)
	}

	if r.enterpriseCRDsExist {
		// Watch for changes to primary resource ManagementCluster
		err = c.Watch(&source.Kind{Type: &operator.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %v", err)
		}

		// Watch for changes to primary resource ManagementClusterConnection
		err = c.Watch(&source.Kind{Type: &operator.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %v", err)
		}

		err = c.Watch(&source.Kind{Type: &operator.Authentication{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch primary resource: %v", err)
		}

		if err = utils.AddConfigMapWatch(c, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch ConfigMap %s: %w", render.ECKLicenseConfigMapName, err)
		}

		if err = utils.AddSecretsWatch(c, render.ElasticsearchAdminUserSecret, rmeta.OperatorNamespace()); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch Secret %s: %w", render.ElasticsearchAdminUserSecret, err)
		}

		if err = utils.AddSecretsWatch(c, relasticsearch.PublicCertSecret, rmeta.OperatorNamespace()); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch Secret '%s' in '%s' namespace: %w", relasticsearch.PublicCertSecret, rmeta.OperatorNamespace(), err)
		}

		if err = utils.AddSecretsWatch(c, render.KibanaPublicCertSecret, rmeta.OperatorNamespace()); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch Secret '%s' in '%s' namespace: %w", render.KibanaPublicCertSecret, rmeta.OperatorNamespace(), err)
		}

		// Watch the internal manager TLS secret in the calico namespace, where it's copied for kube-controllers.
		if err = utils.AddSecretsWatch(c, render.ManagerInternalTLSSecretName, common.CalicoNamespace); err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch secret '%s' in '%s' namespace: %w", render.ManagerInternalTLSSecretName, rmeta.OperatorNamespace(), err)
		}

		// Watch for changes to FelixConfiguration. Currently this is only used to grab the prometheusReporterPort which is enterprise-only.
		err = c.Watch(&source.Kind{Type: &crdv1.FelixConfiguration{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			return fmt.Errorf("tigera-installation-controller failed to watch FelixConfiguration resource: %w", err)
		}
	}

	return nil
}

// secondaryResources returns a list of the secondary resources that this controller
// monitors for changes. Add resources here which correspond to the resources created by
// this controller.
func secondaryResources() []client.Object {
	return []client.Object{
		&apps.DaemonSet{},
		&rbacv1.ClusterRole{},
		&rbacv1.ClusterRoleBinding{},
		&corev1.ServiceAccount{},
		&apiregv1.APIService{},
		&corev1.Service{},
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
	controller           controller.Controller
	watches              map[runtime.Object]struct{}
	autoDetectedProvider operator.Provider
	status               status.StatusManager
	typhaAutoscaler      *typhaAutoscaler
	namespaceMigration   migration.NamespaceMigration
	enterpriseCRDsExist  bool
	amazonCRDExists      bool
	migrationChecked     bool
	clusterDomain        string
}

// updateInstallationWithDefaults returns the default installation instance with defaults populated.
func updateInstallationWithDefaults(ctx context.Context, client client.Client, instance *operator.Installation, provider operator.Provider) error {
	// Determine the provider in use by combining any auto-detected value with any value
	// specified in the Installation CR. mergeProvider updates the CR with the correct value.
	err := mergeProvider(instance, provider)
	if err != nil {
		return err
	}

	var openshiftConfig *configv1.Network
	var kubeadmConfig *v1.ConfigMap
	if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
		openshiftConfig = &configv1.Network{}
		// If configured to run in openshift, then also fetch the openshift configuration API.
		err = client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig)
		if err != nil {
			return fmt.Errorf("Unable to read openshift network configuration: %s", err.Error())
		}
	} else {
		// Check if we're running on kubeadm by getting the config map.
		kubeadmConfig = &v1.ConfigMap{}
		key := types.NamespacedName{Name: kubeadmConfigMap, Namespace: metav1.NamespaceSystem}
		err = client.Get(ctx, key, kubeadmConfig)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("Unable to read kubeadm config map: %s", err.Error())
			}
			kubeadmConfig = nil
		}
	}
	awsNode := &apps.DaemonSet{}
	key := types.NamespacedName{Name: "aws-node", Namespace: metav1.NamespaceSystem}
	err = client.Get(ctx, key, awsNode)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("Unable to read aws-node daemonset: %s", err.Error())
		}
		awsNode = nil
	}

	err = mergeAndFillDefaults(instance, openshiftConfig, kubeadmConfig, awsNode)
	if err != nil {
		return err
	}
	return nil
}

// mergeAndFillDefaults merges in configuration from the Kubernetes provider, if applicable, and then
// populates defaults in the Installation instance.
func mergeAndFillDefaults(i *operator.Installation, o *configv1.Network, kubeadmConfig *v1.ConfigMap, awsNode *apps.DaemonSet) error {
	if o != nil {
		// Merge in OpenShift configuration.
		if err := updateInstallationForOpenshiftNetwork(i, o); err != nil {
			return fmt.Errorf("Could not resolve CalicoNetwork IPPool and OpenShift network: %s", err.Error())
		}
	} else if kubeadmConfig != nil {
		// Merge in kubeadm configuration.
		if err := updateInstallationForKubeadm(i, kubeadmConfig); err != nil {
			return fmt.Errorf("Could not resolve CalicoNetwork IPPool and kubeadm configuration: %s", err.Error())
		}
	}
	if awsNode != nil {
		if err := updateInstallationForAWSNode(i, awsNode); err != nil {
			return fmt.Errorf("Could not resolve AWS node configuration: %s", err.Error())
		}
	}

	return fillDefaults(i)
}

// fillDefaults populates the default values onto an Installation object.
func fillDefaults(instance *operator.Installation) error {
	// Populate the instance with defaults for any fields not provided by the user.
	if len(instance.Spec.Registry) != 0 && !strings.HasSuffix(instance.Spec.Registry, "/") {
		// Make sure registry always ends with a slash.
		instance.Spec.Registry = fmt.Sprintf("%s/", instance.Spec.Registry)
	}

	if len(instance.Spec.Variant) == 0 {
		// Default to installing Calico.
		instance.Spec.Variant = operator.Calico
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

	if instance.Spec.TyphaAffinity == nil {
		switch instance.Spec.KubernetesProvider {
		// in AKS, there is a feature called 'virtual-nodes' which represent azure's container service as a node in the kubernetes cluster.
		// virtual-nodes have many limitations, namely it's unable to run hostNetworked pods. virtual-kubelets are tainted to prevent pods from running on them,
		// but typha tolerates all taints and will run there.
		// as such, we add a required anti-affinity for virtual-nodes if running on azure
		case operator.ProviderAKS:
			instance.Spec.TyphaAffinity = &operator.TyphaAffinity{
				NodeAffinity: &operator.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
						NodeSelectorTerms: []v1.NodeSelectorTerm{{
							MatchExpressions: []v1.NodeSelectorRequirement{
								{
									Key:      "type",
									Operator: corev1.NodeSelectorOpNotIn,
									Values:   []string{"virtual-node"},
								},
								{
									Key:      "kubernetes.azure.com/cluster",
									Operator: v1.NodeSelectorOpExists,
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

	// Only default IP pools if explicitly nil; we use the empty slice to mean "no IP pools".
	// Only default IP pools if we're using Calico IPAM, otherwise there's no-one to use the IP pool.
	if instance.Spec.CalicoNetwork.IPPools == nil && instance.Spec.CNI.IPAM.Type == operator.IPAMPluginCalico {
		switch instance.Spec.KubernetesProvider {
		case operator.ProviderEKS:
			// On EKS, default to a CIDR that doesn't overlap with the host range,
			// and also use VXLAN encap by default.
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "172.16.0.0/16",
					Encapsulation: operator.EncapsulationVXLAN,
				},
			}
		default:
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{CIDR: "192.168.0.0/16"},
			}
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

	var v4pool, v6pool *operator.IPPool
	v4pool = render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
	v6pool = render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)

	if v4pool != nil {
		if v4pool.Encapsulation == "" {
			if instance.Spec.CNI.Type == operator.PluginCalico {
				v4pool.Encapsulation = operator.EncapsulationIPIP
			} else {
				v4pool.Encapsulation = operator.EncapsulationNone
			}
		}
		if v4pool.NATOutgoing == "" {
			v4pool.NATOutgoing = operator.NATOutgoingEnabled
		}
		if v4pool.NodeSelector == "" {
			v4pool.NodeSelector = operator.NodeSelectorDefault
		}
		if v4pool.BlockSize == nil {
			var twentySix int32 = 26
			v4pool.BlockSize = &twentySix
		}
		needIPv4Autodetection = true
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

	if v6pool != nil {
		if v6pool.Encapsulation == "" {
			v6pool.Encapsulation = operator.EncapsulationNone
		}
		if v6pool.NATOutgoing == "" {
			v6pool.NATOutgoing = operator.NATOutgoingDisabled
		}
		if v6pool.NodeSelector == "" {
			v6pool.NodeSelector = operator.NodeSelectorDefault
		}
		if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 == nil {
			// Default IPv6 address detection to "first found" if not specified.
			t := true
			instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 = &operator.NodeAddressAutodetection{
				FirstFound: &t,
			}
		}
		if v6pool.BlockSize == nil {
			var oneTwentyTwo int32 = 122
			v6pool.BlockSize = &oneTwentyTwo
		}
	}

	// While a number of the fields in this section are relevant to all CNI plugins,
	// there are some settings which are currently only applicable if using Calico CNI.
	// Handle those here.
	if instance.Spec.CNI.Type == operator.PluginCalico {
		if instance.Spec.CalicoNetwork.HostPorts == nil {
			var hp operator.HostPortsType
			if *instance.Spec.CalicoNetwork.LinuxDataplane == operator.LinuxDataplaneBPF {
				// Host ports not supported with BPF mode.
				hp = operator.HostPortsDisabled
			} else {
				hp = operator.HostPortsEnabled
			}
			instance.Spec.CalicoNetwork.HostPorts = &hp
		}

		if instance.Spec.CalicoNetwork.MultiInterfaceMode == nil {
			mm := operator.MultiInterfaceModeNone
			instance.Spec.CalicoNetwork.MultiInterfaceMode = &mm
		}
	}

	// If not specified by the user, set the flex volume plugin location based on platform.
	if len(instance.Spec.FlexVolumePath) == 0 {
		if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
			// In OpenShift 4.x, the location for flexvolume plugins has changed.
			// See: https://bugzilla.redhat.com/show_bug.cgi?id=1667606#c5
			instance.Spec.FlexVolumePath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
		} else if instance.Spec.KubernetesProvider == operator.ProviderGKE {
			instance.Spec.FlexVolumePath = "/home/kubernetes/flexvolume/"
		} else if instance.Spec.KubernetesProvider == operator.ProviderAKS {
			instance.Spec.FlexVolumePath = "/etc/kubernetes/volumeplugins/"
		} else {
			instance.Spec.FlexVolumePath = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
		}
	}

	// Default rolling update parameters.
	var one = intstr.FromInt(1)
	if instance.Spec.NodeUpdateStrategy.RollingUpdate == nil {
		instance.Spec.NodeUpdateStrategy.RollingUpdate = &apps.RollingUpdateDaemonSet{}
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
	if provider != operator.ProviderNone && cr.Spec.KubernetesProvider != operator.ProviderNone && cr.Spec.KubernetesProvider != provider {
		msg := "Installation spec.kubernetesProvider '%s' does not match auto-detected value '%s'"
		return fmt.Errorf(msg, cr.Spec.KubernetesProvider, provider)
	}

	// If we've reached this point, it means only one source of provider is being used - auto-detection or
	// user-provided, but not both. Or, it means that both have been specified but are the same.
	// If it's the CR provided one, then just use that. Otherwise, use the auto-detected one.
	if cr.Spec.KubernetesProvider == operator.ProviderNone {
		cr.Spec.KubernetesProvider = provider
	}
	log.WithValues("provider", cr.Spec.KubernetesProvider).V(1).Info("Determined provider")
	return nil
}

// Reconcile reads that state of the cluster for a Installation object and makes changes based on the state read
// and what is in the Installation.Spec. The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileInstallation) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling Installation.operator.tigera.io")

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
	status := instance.Status
	preDefaultPatchFrom := client.MergeFrom(instance.DeepCopy())

	// Mark CR found so we can report converter problems via tigerastatus
	r.status.OnCRFound()

	if !r.migrationChecked {
		// update Installation resource with existing install if it exists.
		nc, err := convert.NeedsConversion(ctx, r.client)
		if err != nil {
			r.SetDegraded("Error checking for existing installation", err, reqLogger)
			return reconcile.Result{}, err
		}
		if nc {
			install, err := convert.Convert(ctx, r.client)
			if err != nil {
				if errors.As(err, &convert.ErrIncompatibleCluster{}) {
					r.SetDegraded("Existing Calico installation can not be managed by Tigera Operator as it is configured in a way that Operator does not currently support. Please update your existing Calico install config", err, reqLogger)
					// We should always requeue a convert problem. Don't return error
					// to make sure we never back off retrying.
					return reconcile.Result{RequeueAfter: 15 * time.Second}, nil
				}
				r.SetDegraded("Error converting existing installation", err, reqLogger)
				return reconcile.Result{}, err
			}
			instance.Spec = utils.OverrideInstallationSpec(install.Spec, instance.Spec)
		}
	}

	// update Installation with defaults
	if err := updateInstallationWithDefaults(ctx, r.client, instance, r.autoDetectedProvider); err != nil {
		r.SetDegraded("Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Loaded config", "config", instance)

	// Validate the configuration.
	if err := validateCustomResource(instance); err != nil {
		r.SetDegraded("Invalid Installation provided", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
	// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
	// Note that we only write the 'base' installation back. We don't want to write the changes from 'overlay', as those should only
	// be stored in the 'overlay' resource.
	if err := r.client.Patch(ctx, instance, preDefaultPatchFrom); err != nil {
		r.SetDegraded("Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// update Installation with 'overlay'
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
			r.SetDegraded("Invalid computed config", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// now that migrated config is stored in the installation resource, we no longer need
	// to check if a migration is needed for the lifetime of the operator.
	r.migrationChecked = true

	// A status is needed at this point for operator scorecard tests.
	// status.variant is written later but for some tests the reconciliation
	// does not get to that point.
	if reflect.DeepEqual(status, operator.InstallationStatus{}) {
		instance.Status = operator.InstallationStatus{}
		if err := r.client.Status().Update(ctx, instance); err != nil {
			r.SetDegraded("Failed to write default status", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// If the autoscalar is degraded then trigger a run and recheck the degraded status. If it is still degraded after the
	// the run the reset the degraded status and requeue the request.
	if r.typhaAutoscaler.isDegraded() {
		if err := r.typhaAutoscaler.triggerRun(); err != nil {
			r.SetDegraded("Failed to scale typha", err, reqLogger)
			return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
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
			r.SetDegraded("Error discovering Tigera Secure availability", err, reqLogger)
		} else {
			r.SetDegraded("Cannot deploy Tigera Secure", fmt.Errorf("Missing Tigera Secure custom resource definitions"), reqLogger)
		}

		// Queue a retry. We don't want to watch the APIServer API since it might not exist and would cause
		// this controller to fail.
		reqLogger.Info("Scheduling a retry in 30 seconds")
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// The operator supports running without the AmazonCloudIntegration when it's CRD is not installed.
	// If, when this controller was started, the CRD didn't exist, but it does now, then reboot.
	if !r.amazonCRDExists {
		amazonCRDRequired, err := utils.RequiresAmazonController(r.config)
		if err != nil {
			r.SetDegraded("Error discovering AmazonCloudIntegration CRD", err, reqLogger)
			reqLogger.Info("Scheduling a retry in 30 seconds")
			return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
		}
		if amazonCRDRequired {
			log.Info("Rebooting to enable AWS controllers")
			os.Exit(0)
		}
	}

	// Query for pull secrets in operator namespace
	pullSecrets, err := utils.GetNetworkingPullSecrets(&instance.Spec, r.client)
	if err != nil {
		r.SetDegraded("Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	var managementCluster *operator.ManagementCluster
	var managementClusterConnection *operator.ManagementClusterConnection
	var logStorageExists bool
	var authentication *operator.Authentication
	var esLicenseType render.ElasticsearchLicenseType
	var elasticsearchSecret *corev1.Secret
	var kibanaSecret *corev1.Secret
	if r.enterpriseCRDsExist {
		logStorageExists, err = utils.LogStorageExists(ctx, r.client)
		if err != nil {
			log.Error(err, "Error checking if LogStorage exists")
			r.SetDegraded("Error checking if LogStorage exists", err, reqLogger)
			return reconcile.Result{}, err
		}

		managementCluster, err = utils.GetManagementCluster(ctx, r.client)
		if managementCluster != nil {
			if err != nil {
				log.Error(err, "Error reading ManagementCluster")
				r.status.SetDegraded("Error reading ManagementCluster", err.Error())
				return reconcile.Result{}, err
			}
		}

		managementClusterConnection, err = utils.GetManagementClusterConnection(ctx, r.client)
		if err != nil {
			log.Error(err, "Error reading ManagementClusterConnection")
			r.status.SetDegraded("Error reading ManagementClusterConnection", err.Error())
			return reconcile.Result{}, err
		}

		if managementClusterConnection != nil && managementCluster != nil {
			err = fmt.Errorf("having both a managementCluster and a managementClusterConnection is not supported")
			log.Error(err, "")
			r.status.SetDegraded(err.Error(), "")
			return reconcile.Result{}, err
		}

		authentication, err = utils.GetAuthentication(ctx, r.client)
		if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, err.Error())
			r.status.SetDegraded("An error occurred retrieving the authentication configuration", err.Error())
			return reconcile.Result{}, err
		}

		esLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, reqLogger)
		if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to get Elasticsearch license type", err.Error())
			return reconcile.Result{}, err
		}

		elasticsearchSecret, err = utils.GetSecret(ctx, r.client, esgateway.EsGatewayElasticPublicCertSecret, rmeta.OperatorNamespace())
		if err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to get Elasticsearch pub cert secret", err.Error())
			return reconcile.Result{}, err
		}

		kibanaSecret, err = utils.GetSecret(ctx, r.client, esgateway.EsGatewayKibanaPublicCertSecret, rmeta.OperatorNamespace())
		if err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded("Failed to get Kibana pub cert secret", err.Error())
			return reconcile.Result{}, err
		}
	}

	// If the Elasticsearch license type is basic OR there is an Authentication CR with OIDC type Tigera, then
	// enable the Elasticsearch OIDC workaround in kube controllers.
	enableESOIDCWorkaround := false
	if (authentication != nil && authentication.Spec.OIDC != nil && authentication.Spec.OIDC.Type == operator.OIDCTypeTigera) ||
		esLicenseType == render.ElasticsearchLicenseTypeBasic {
		enableESOIDCWorkaround = true
	}

	var managerInternalTLSSecret *corev1.Secret
	managerInternalTLSSecret, err = utils.ValidateCertPair(r.client,
		common.CalicoNamespace,
		render.ManagerInternalTLSSecretName,
		render.ManagerInternalSecretKeyName,
		render.ManagerInternalSecretCertName,
	)

	// Ensure that CA and TLS certificate for tigera-manager for internal
	// traffic within the K8s cluster exists and has valid FQDN manager service
	// names and localhost.
	if instance.Spec.Variant == operator.TigeraSecureEnterprise && managementCluster != nil {
		var err error
		svcDNSNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, r.clusterDomain)
		svcDNSNames = append(svcDNSNames, render.ManagerServiceIP)
		certDur := 825 * 24 * time.Hour // 825days*24hours: Create cert with a max expiration that macOS 10.15 will accept

		managerInternalTLSSecret, err = utils.EnsureCertificateSecret(
			render.ManagerInternalTLSSecretName, managerInternalTLSSecret, render.ManagerInternalSecretKeyName, render.ManagerInternalSecretCertName, certDur, svcDNSNames...,
		)

		if err != nil {
			r.status.SetDegraded(fmt.Sprintf("Error ensuring internal manager TLS certificate %q exists and has valid DNS names", render.ManagerInternalTLSSecretName), err.Error())
			return reconcile.Result{}, err
		}
	}

	var esAdminSecret *v1.Secret
	if instance.Spec.Variant == operator.TigeraSecureEnterprise {
		// Kube controllers no longer uses the admin secret to run it's administrative tasks on Elasticsearch.
		// Instead a username/password combo is randomly generated and stored in tigera-ee-kube-controllers-elasticsearch-access
		// and passed to the ES Gateway deployment to be used to detect requests from kube-controllers and swap in admin
		// level Elasticsearch credentials.
		esAdminSecret, err = utils.GetSecret(ctx, r.client, render.ElasticsearchKubeControllersUserSecret, common.CalicoNamespace)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	var typhaNodeTLS *render.TyphaNodeTLS
	if instance.Spec.CertificateManagement == nil {
		typhaNodeTLS, err = r.GetTyphaFelixTLSConfig()
		if err != nil {
			log.Error(err, "Error with Typha/Felix secrets")
			r.SetDegraded("Error with Typha/Felix secrets", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	birdTemplates, err := getBirdTemplates(r.client)
	if err != nil {
		log.Error(err, "Error retrieving confd templates")
		r.SetDegraded("Error retrieving confd templates", err, reqLogger)
		return reconcile.Result{}, err
	}

	bgpLayout, err := getConfigMap(r.client, render.BGPLayoutConfigMapName)
	if err != nil {
		log.Error(err, "Error retrieving BGP layout ConfigMap")
		r.SetDegraded("Error retrieving BGP layout ConfigMap", err, reqLogger)
		return reconcile.Result{}, err
	}

	if bgpLayout != nil {
		// Validate that BGP layout ConfigMap has the expected key.
		if _, ok := bgpLayout.Data[render.BGPLayoutConfigMapKey]; !ok {
			err = fmt.Errorf("BGP layout ConfigMap does not have %v key", render.BGPLayoutConfigMapKey)
			r.SetDegraded("Error in BGP layout ConfigMap", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	err = utils.GetK8sServiceEndPoint(r.client)
	if err != nil {
		log.Error(err, "Error reading services endpoint configmap")
		r.SetDegraded("Error reading services endpoint configmap", err, reqLogger)
		return reconcile.Result{}, err
	}

	openShiftOnAws := false
	if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
		openShiftOnAws, err = isOpenshiftOnAws(instance, ctx, r.client)
		if err != nil {
			log.Error(err, "Error checking if OpenShift is on AWS")
			r.SetDegraded("Error checking if OpenShift is on AWS", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Determine if we need to migrate resources from the kube-system namespace. If
	// we do then we'll render the Calico components with additional node selectors to
	// prevent scheduling, later we will run a migration that migrates nodes one by one
	// to mimic a 'normal' rolling update.
	needNsMigration, err := r.namespaceMigration.NeedsCoreNamespaceMigration(ctx)
	if err != nil {
		log.Error(err, "Error checking if namespace migration is needed")
		r.status.SetDegraded("Error checking if namespace migration is needed", err.Error())
		return reconcile.Result{}, err
	}

	var aci *operator.AmazonCloudIntegration
	if r.amazonCRDExists {
		aci, err = utils.GetAmazonCloudIntegration(ctx, r.client)
		if apierrors.IsNotFound(err) {
			aci = nil
		} else if err != nil {
			log.Error(err, "Error reading AmazonCloudIntegration")
			r.status.SetDegraded("Error reading AmazonCloudIntegration", err.Error())
			return reconcile.Result{}, err
		}
	}

	// nodeReporterMetricsPort is a port used in Enterprise to host internal metrics.
	// Operator is responsible for creating a service which maps to that port.
	// Here, we'll check the default felixconfiguration to see if the user is specifying
	// a non-default port, and use that value if they are.
	nodeReporterMetricsPort := defaultNodeReporterPort
	if instance.Spec.Variant == operator.TigeraSecureEnterprise {
		// Query the FelixConfiguration object. We'll use this to help configure felix.
		felixConfiguration := &crdv1.FelixConfiguration{}
		err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, felixConfiguration)
		if err != nil && !apierrors.IsNotFound(err) {
			r.SetDegraded("Unable to read FelixConfiguration", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Determine the port to use for nodeReporter metrics.
		if felixConfiguration.Spec.PrometheusReporterPort != nil {
			nodeReporterMetricsPort = *felixConfiguration.Spec.PrometheusReporterPort
		}

		if nodeReporterMetricsPort == 0 {
			err := errors.New("felixConfiguration prometheusReporterPort=0 not supported")
			r.SetDegraded("invalid metrics port", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Query the KubeControllersConfiguration object. We'll use this to help configure kube-controllers.
	kubeControllersConfig := &crdv1.KubeControllersConfiguration{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, kubeControllersConfig)
	if err != nil && !apierrors.IsNotFound(err) {
		r.SetDegraded("Unable to read KubeControllersConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Determine the port to use for kube-controllers metrics.
	kubeControllersMetricsPort := 0
	if kubeControllersConfig.Spec.PrometheusMetricsPort != nil {
		kubeControllersMetricsPort = *kubeControllersConfig.Spec.PrometheusMetricsPort
	}

	nodeAppArmorProfile := ""
	a := instance.GetObjectMeta().GetAnnotations()
	if val, ok := a[techPreviewFeatureSeccompApparmor]; ok {
		nodeAppArmorProfile = val
	}

	// Create a component handler to manage the rendered components.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired Calico components based on our configuration and then
	// create or update them.
	calico, err := render.Calico(
		k8sapi.Endpoint,
		&instance.Spec,
		logStorageExists,
		managementCluster,
		managementClusterConnection,
		authentication,
		pullSecrets,
		typhaNodeTLS,
		managerInternalTLSSecret,
		elasticsearchSecret,
		kibanaSecret,
		birdTemplates,
		instance.Spec.KubernetesProvider,
		aci,
		needNsMigration,
		nodeAppArmorProfile,
		r.clusterDomain,
		enableESOIDCWorkaround,
		esAdminSecret,
		kubeControllersMetricsPort,
		nodeReporterMetricsPort,
		bgpLayout,
	)
	if err != nil {
		log.Error(err, "Error with rendering Calico")
		r.SetDegraded("Error with rendering Calico resources", err, reqLogger)
		return reconcile.Result{}, err
	}

	components := []render.Component{}
	// If we're on OpenShift on AWS render a Job (and needed resources) to
	// setup the security groups we need for IPIP, BGP, and Typha communication.
	if openShiftOnAws {
		awsSetup, err := render.AWSSecurityGroupSetup(instance.Spec.ImagePullSecrets, &instance.Spec)
		if err != nil {
			// If there is a problem rendering this do not degrade or stop rendering
			// anything else.
			log.Info(err.Error())
		} else {
			components = append(components, awsSetup)
		}
	}
	components = append(components, calico.Render()...)

	imageSet, err := imageset.GetImageSet(ctx, r.client, instance.Spec.Variant)
	if err != nil {
		r.SetDegraded("Error getting ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		r.SetDegraded("Error validating ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ResolveImages(imageSet, components...); err != nil {
		r.SetDegraded("Error resolving ImageSet for components", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := handler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
			r.SetDegraded("Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// TODO: We handle too many components in this controller at the moment. Once we are done consolidating,
	// we can have the CreateOrUpdate logic handle this for us.
	r.status.AddDaemonsets([]types.NamespacedName{{Name: "calico-node", Namespace: "calico-system"}})
	r.status.AddDeployments([]types.NamespacedName{{Name: "calico-kube-controllers", Namespace: "calico-system"}})
	if instance.Spec.CertificateManagement != nil {
		r.status.AddCertificateSigningRequests(render.CSRLabelCalicoSystem, map[string]string{
			"k8s-app": render.CSRLabelCalicoSystem,
		})
	} else {
		r.status.RemoveCertificateSigningRequests(render.CSRLabelCalicoSystem)
	}

	// Run this after we have rendered our components so the new (operator created)
	// Deployments and Daemonset exist with our special migration nodeSelectors.
	if needNsMigration {
		if err := r.namespaceMigration.Run(ctx, reqLogger); err != nil {
			r.SetDegraded("error migrating resources to calico-system", err, reqLogger)
			// We should always requeue a migration problem. Don't return error
			// to make sure we never start backing off retrying.
			return reconcile.Result{Requeue: true}, nil
		}
		// Requeue so we can update our resources (without the migration changes)
		return reconcile.Result{Requeue: true}, nil
	} else if r.namespaceMigration.NeedCleanup() {
		if err := r.namespaceMigration.CleanupMigration(ctx); err != nil {
			r.SetDegraded("error migrating resources to calico-system", err, reqLogger)
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
			r.SetDegraded("error reading network MTU", err, reqLogger)
			return reconcile.Result{}, err
		}
	} else {
		// If neither is present, then we don't have MTU information available.
		// Auto-detection will still be used for Calico, but the operator won't know
		// what the value is.
		reqLogger.V(1).Info("Unable to determine MTU - no explicit config, and /var/lib/calico is not mounted")
	}

	// We have successfully reconciled the Calico installation.
	if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
		openshiftConfig := &configv1.Network{}
		err = r.client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig)
		if err != nil {
			r.SetDegraded("Unable to update OpenShift Network config: failed to read OpenShift network configuration", err, reqLogger)
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
			r.SetDegraded("Error patching openshift network status", err, reqLogger.WithValues("openshiftConfig", openshiftConfig))
			return reconcile.Result{}, err
		}
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Write updated status.
	instance.Status.MTU = int32(statusMTU)
	instance.Status.Variant = instance.Spec.Variant
	if imageSet == nil {
		instance.Status.ImageSet = ""
	} else {
		instance.Status.ImageSet = imageSet.Name
	}
	instance.Status.Computed = &instance.Spec
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}

	// Created successfully. Requeue anyway so that we perform periodic reconciliation.
	// This acts as a backstop to catch reconcile issues, and also makes sure we spot when
	// things change that might not trigger a reconciliation.
	reqLogger.V(1).Info("Finished reconciling network installation")
	return reconcile.Result{RequeueAfter: 5 * time.Minute}, nil
}

func readMTUFile() (int, error) {
	filename := "/var/lib/calico/mtu"
	data, err := ioutil.ReadFile(filename)
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
	if err != nil {
		return false
	}
	return true
}

func (r *ReconcileInstallation) SetDegraded(reason string, err error, log logr.Logger) {
	log.Error(err, reason)
	r.status.SetDegraded(reason, err.Error())
}

// GetTyphaFelixTLSConfig reads and validates the CA ConfigMap and Secrets for
// Typha and Felix configuration. It returns the validated resources or error
// if there was one.
func (r *ReconcileInstallation) GetTyphaFelixTLSConfig() (*render.TyphaNodeTLS, error) {
	// accumulate all the error messages so all problems with the certs
	// and CA are reported.
	errMsgs := []string{}
	ca, err := r.validateTyphaCAConfigMap()
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CA for Typha is invalid: %s", err))
	}

	node, err := utils.ValidateCertPair(
		r.client,
		rmeta.OperatorNamespace(),
		render.NodeTLSSecretName,
		render.TLSSecretKeyName,
		render.TLSSecretCertName,
	)
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Felix is invalid: %s", err))
	} else if node != nil {
		if node.Data != nil {
			// We need the CommonName, URISAN, or both to be set
			_, okCN := node.Data[render.CommonName]
			_, okUS := node.Data[render.URISAN]
			if !(okCN || okUS) {
				errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Felix does not contain common-name or uri-san"))
			}
		}
	}

	typha, err := utils.ValidateCertPair(
		r.client,
		rmeta.OperatorNamespace(),
		render.TyphaTLSSecretName,
		render.TLSSecretKeyName,
		render.TLSSecretCertName,
	)
	if err != nil {
		errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Typha is invalid: %s", err))
	} else if typha != nil {
		if typha.Data != nil {
			// We need the CommonName, URISAN, or both to be set
			_, okCN := typha.Data[render.CommonName]
			_, okUS := typha.Data[render.URISAN]
			if !(okCN || okUS) {
				errMsgs = append(errMsgs, fmt.Sprintf("CertPair for Typha does not contain common-name or uri-san"))
			}
		}
	}

	// CA, typha, and node are all not set
	allNil := (ca == nil && typha == nil && node == nil)
	// CA, typha, and node are all are set
	allSet := (ca != nil && typha != nil && node != nil)
	// All CA, typha, and node must be set or not set.
	if !(allNil || allSet) {
		errMsgs = append(errMsgs, fmt.Sprintf("Typha-Node CA and Secrets should all be set or none set: ca(%t) typha(%t) node(%t)", ca != nil, typha != nil, node != nil))
		errMsgs = append(errMsgs, "If not providing custom CA and certs, feel free to remove them from the operator namespace, they will be recreated")
	}

	// TODO: We could make sure both TLS Secrets were signed by the CA

	if len(errMsgs) != 0 {
		return nil, fmt.Errorf(strings.Join(errMsgs, ";"))
	}
	return &render.TyphaNodeTLS{CAConfigMap: ca, TyphaSecret: typha, NodeSecret: node}, nil
}

// validateTyphaCAConfigMap reads the Typha CA config map from the Operator
// namespace and validates that it has a CA Bundle. It returns the validated
// ConfigMap or an error.
func (r *ReconcileInstallation) validateTyphaCAConfigMap() (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      render.TyphaCAConfigMapName,
		Namespace: rmeta.OperatorNamespace(),
	}
	err := r.client.Get(context.Background(), cmNamespacedName, cm)
	if err != nil {
		// If the reason for the error is not found then that is acceptable
		// so return valid in that case.
		statErr, ok := err.(*apierrors.StatusError)
		if ok && statErr.ErrStatus.Reason == metav1.StatusReasonNotFound {
			return nil, nil
		} else {
			return nil, fmt.Errorf("Failed to read configmap %q from datastore: %s", render.TyphaCAConfigMapName, err)
		}
	}

	if val, ok := cm.Data[render.TyphaCABundleName]; !ok || len(val) == 0 {
		return nil, fmt.Errorf("ConfigMap %q does not have a field named %q", render.TyphaCAConfigMapName, render.TyphaCABundleName)
	}

	return cm, nil
}

func getConfigMap(client client.Client, cmName string) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: rmeta.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read ConfigMap %q: %s", cmName, err)
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
	if install.Spec.KubernetesProvider != operator.ProviderOpenShift {
		return false, nil
	}
	infra := configv1.Infrastructure{}
	// If configured to run in openshift, then also fetch the openshift configuration API.
	if err := client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, &infra); err != nil {
		return false, fmt.Errorf("Unable to read OpenShift infrastructure configuration: %s", err.Error())
	}
	return (infra.Status.Platform == "AWS"), nil
}

func updateInstallationForOpenshiftNetwork(i *operator.Installation, o *configv1.Network) error {
	// If CNI plugin is specified and not Calico then skip any CalicoNetwork initialization
	if i.Spec.CNI != nil && i.Spec.CNI.Type != operator.PluginCalico {
		return nil
	}
	if i.Spec.CalicoNetwork == nil {
		i.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}

	platformCIDRs := []string{}
	for _, c := range o.Spec.ClusterNetwork {
		platformCIDRs = append(platformCIDRs, c.CIDR)
	}
	return mergePlatformPodCIDRs(i, platformCIDRs)
}

func updateInstallationForKubeadm(i *operator.Installation, c *v1.ConfigMap) error {
	// If CNI plugin is specified and not Calico then skip any CalicoNetwork initialization
	if i.Spec.CNI != nil && i.Spec.CNI.Type != operator.PluginCalico {
		return nil
	}
	if i.Spec.CalicoNetwork == nil {
		i.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}

	platformCIDRs, err := extractKubeadmCIDRs(c)
	if err != nil {
		return err
	}
	return mergePlatformPodCIDRs(i, platformCIDRs)
}

func updateInstallationForAWSNode(i *operator.Installation, ds *apps.DaemonSet) error {
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

func mergePlatformPodCIDRs(i *operator.Installation, platformCIDRs []string) error {
	// If IPPools is nil, add IPPool with CIDRs detected from platform configuration.
	if i.Spec.CalicoNetwork.IPPools == nil {
		if len(platformCIDRs) == 0 {
			// If the platform has no CIDRs defined as well, then return and let the
			// normal defaulting happen.
			return nil
		}
		v4found := false
		v6found := false

		// Currently we only support a single IPv4 and a single IPv6 CIDR configured via the operator.
		// So, grab the 1st IPv4 and IPv6 cidrs we find and use those. This will allow the
		// operator to work in situations where there are more than one of each.
		for _, c := range platformCIDRs {
			addr, _, err := net.ParseCIDR(c)
			if err != nil {
				log.Error(err, "Failed to parse platform's pod network CIDR.")
				continue
			}

			if addr.To4() == nil {
				if v6found {
					continue
				}
				v6found = true
				i.Spec.CalicoNetwork.IPPools = append(i.Spec.CalicoNetwork.IPPools,
					operator.IPPool{CIDR: c})
			} else {
				if v4found {
					continue
				}
				v4found = true
				i.Spec.CalicoNetwork.IPPools = append(i.Spec.CalicoNetwork.IPPools,
					operator.IPPool{CIDR: c})
			}
			if v6found && v4found {
				break
			}
		}
	} else if len(i.Spec.CalicoNetwork.IPPools) == 0 {
		// Empty IPPools list so nothing to do.
		return nil
	} else {
		// Pools are configured on the Installation. Make sure they are compatible with
		// the configuration set in the underlying Kubernetes platform.
		for _, pool := range i.Spec.CalicoNetwork.IPPools {
			within := false
			for _, c := range platformCIDRs {
				within = within || cidrWithinCidr(c, pool.CIDR)
			}
			if !within {
				return fmt.Errorf("IPPool %v is not within the platform's configured pod network CIDR(s) %v", pool.CIDR, platformCIDRs)
			}
		}
	}
	return nil
}

// cidrWithinCidr checks that all IPs in the pool passed in are within the
// passed in CIDR
func cidrWithinCidr(cidr, pool string) bool {
	_, cNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	_, pNet, err := net.ParseCIDR(pool)
	if err != nil {
		return false
	}
	ipMin := pNet.IP
	pOnes, _ := pNet.Mask.Size()
	cOnes, _ := cNet.Mask.Size()

	// If the cidr contains the network (1st) address of the pool and the
	// prefix on the pool is larger than or equal to the cidr prefix (the pool size is
	// smaller than the cidr) then the pool network is within the cidr network.
	if cNet.Contains(ipMin) && pOnes >= cOnes {
		return true
	}
	return false
}
