// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package ippool

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operator "github.com/tigera/operator/api/v1"
	v1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const tigeraStatusName string = "ippools"

var log = logf.Log.WithName("controller_ippool")

func Add(mgr manager.Manager, opts options.AddOptions) error {
	r := &Reconciler{
		config:               mgr.GetConfig(),
		client:               mgr.GetClient(),
		scheme:               mgr.GetScheme(),
		watches:              make(map[runtime.Object]struct{}),
		autoDetectedProvider: opts.DetectedProvider,
		status:               status.New(mgr.GetClient(), tigeraStatusName, opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	c, err := ctrlruntime.NewController("tigera-ippool-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create tigera-ippool-controller: %w", err)
	}

	// Watch for changes to primary resource Installation
	err = c.WatchObject(&operator.Installation{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to APIServer
	err = c.WatchObject(&operator.APIServer{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create APIServer watch", "err", err)
		return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, tigeraStatusName); err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch calico Tigerastatus: %w", err)
	}

	// Watch for changes to IPPool.
	err = c.WatchObject(&crdv1.IPPool{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch IPPool resource: %w", err)
	}

	if r.autoDetectedProvider == operator.ProviderOpenShift {
		// Watch for openshift network configuration as well. If we're running in OpenShift, we need to
		// merge this configuration with our own and the write back the status object.
		err = c.WatchObject(&configv1.Network{}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("tigera-installation-controller failed to watch openshift network config: %w", err)
			}
		}
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to create periodic reconcile watch: %w", err)
	}
	return nil
}

var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	config               *rest.Config
	client               client.Client
	scheme               *runtime.Scheme
	watches              map[runtime.Object]struct{}
	autoDetectedProvider operator.Provider
	status               status.StatusManager
}

// hasOwner returns true if the given IP pool is owned by the given Installation object, and
// false otherwise.
func hasOwner(pool *crdv1.IPPool, installation *operator.Installation) bool {
	// Check the v1 object metadata.
	for _, o := range pool.OwnerReferences {
		if o.Name == installation.Name && o.UID == installation.UID {
			return true
		}
	}

	// Check the metadata annotation. This annotation includes the v3 object metadata.
	if pool.Annotations != nil {
		raw := pool.Annotations["projectcalico.org/metadata"]
		meta := metav1.ObjectMeta{}
		if err := json.Unmarshal([]byte(raw), &meta); err != nil {
			log.Error(err, "Failed to parse IPPool metadata annotation")
			return false
		}

		for _, o := range meta.OwnerReferences {
			if o.Name == installation.Name && o.UID == installation.UID {
				return true
			}
		}
	}
	return false
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

		// For each platform CIDR, add it as an IP pool.
		for _, c := range platformCIDRs {
			log.Info("Adding IP pool for platform CIDR", "cidr", c)
			addr, _, err := net.ParseCIDR(c)
			if err != nil {
				log.Error(err, "Failed to parse platform's pod network CIDR.")
				continue
			}

			if addr.To4() == nil {
				// Treat the first IPv6 CIDR as the default. Subsequent CIDRs will be named based on their CIDR.
				name := "default-ipv6-ippool"
				if v6found {
					name = ""
				}
				v6found = true
				i.Spec.CalicoNetwork.IPPools = append(i.Spec.CalicoNetwork.IPPools, operator.IPPool{Name: name, CIDR: c})
			} else {
				// Treat the first IPv4 CIDR as the default. Subsequent CIDRs will be named based on their CIDR.
				name := "default-ipv4-ippool"
				if v4found {
					name = ""
				}
				v4found = true
				i.Spec.CalicoNetwork.IPPools = append(i.Spec.CalicoNetwork.IPPools, operator.IPPool{Name: name, CIDR: c})
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

func updateInstallationForKubeadm(i *operator.Installation, c *corev1.ConfigMap) error {
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

// ValidatePools validates the IP pools specified in the Installation object.
func ValidatePools(instance *operator.Installation) error {
	cidrs := map[string]bool{}
	names := map[string]bool{}
	for _, pool := range instance.Spec.CalicoNetwork.IPPools {
		_, cidr, err := net.ParseCIDR(pool.CIDR)
		if err != nil {
			return fmt.Errorf("IP pool CIDR (%s) is invalid: %s", pool.CIDR, err)
		}

		// Validate that there is only a single instance of each CIDR and Name.
		if cidrs[pool.CIDR] {
			return fmt.Errorf("IP pool %v is specified more than once", pool.CIDR)
		}
		cidrs[pool.CIDR] = true
		if names[pool.Name] {
			return fmt.Errorf("IP pool %v is specified more than once", pool.Name)
		}
		names[pool.Name] = true

		// Verify NAT outgoing values.
		switch pool.NATOutgoing {
		case operator.NATOutgoingEnabled, operator.NATOutgoingDisabled:
		default:
			return fmt.Errorf("%s is invalid for natOutgoing, should be one of %s",
				pool.NATOutgoing, strings.Join(operator.NATOutgoingTypesString, ","))
		}

		// Verify the node selector.
		if pool.NodeSelector == "" {
			return fmt.Errorf("IP pool nodeSelector should not be empty")
		}
		if instance.Spec.CNI == nil {
			// We expect this to be defaulted by the core Installation controller prior to the IP pool controller
			// being invoked, but check just in case.
			return fmt.Errorf("No CNI plugin specified in Installation resource")
		}
		if instance.Spec.CNI.Type != operator.PluginCalico {
			if pool.NodeSelector != "all()" {
				return fmt.Errorf("IP pool nodeSelector (%s) should be 'all()' when using non-Calico CNI plugin", pool.NodeSelector)
			}
		}

		// Verify per-address-family settings.
		isIPv4 := !strings.Contains(pool.CIDR, ":")
		if isIPv4 {
			// This is an IPv4 pool.
			if pool.BlockSize != nil {
				if *pool.BlockSize > 32 || *pool.BlockSize < 20 {
					return fmt.Errorf("IPv4 pool block size must be greater than 19 and less than or equal to 32")
				}

				// Verify that the CIDR contains the blocksize.
				ones, _ := cidr.Mask.Size()
				if int32(ones) > *pool.BlockSize {
					return fmt.Errorf("IP pool size is too small. It must be equal to or greater than the block size.")
				}
			}
		} else {
			// This is an IPv6 pool.
			if pool.BlockSize != nil {
				if *pool.BlockSize > 128 || *pool.BlockSize < 116 {
					return fmt.Errorf("IPv6 pool block size must be greater than 115 and less than or equal to 128")
				}

				// Verify that the CIDR contains the blocksize.
				ones, _ := cidr.Mask.Size()
				if int32(ones) > *pool.BlockSize {
					return fmt.Errorf("IP pool size is too small. It must be equal to or greater than the block size.")
				}
			}
		}
	}
	return nil
}

// cidrToName returns a valid Kubernetes resource name given a CIDR. Kubernetes names must be valid DNS
// names. We do the following:
// - Expand the CIDR so that we get consistent results and remove IPv6 shorthand "::".
// - Replace any slashes with dashes.
// - Replace any : with dots.
func cidrToName(cidr string) (string, error) {
	// First, canonicalize the CIDR. e.g., 192.168.0.1/24 -> 192.168.0.0/24.
	_, nw, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	// Parse the CIDR and expand it to its full form.
	// e.g., fe80::/64 -> fe80:0000:0000:0000:0000:0000:0000:0000/64
	pre, err := netip.ParsePrefix(nw.String())
	if err != nil {
		return "", err
	}
	name := pre.Addr().StringExpanded()

	// Replace invalid characters.
	// e.g., fe80:0000:0000:0000:0000:0000:0000:0000/64 -> fe80.0000.0000.0000.0000.0000.0000.0000-64
	name = strings.ReplaceAll(name, ":", ".")
	name += fmt.Sprintf("-%d", pre.Bits())

	return name, nil
}

// fillDefaults fills in IP pool defaults on the Installation object. Defaulting of fields other than IP pools occurs
// in pkg/controller/installation/
func fillDefaults(ctx context.Context, client client.Client, instance *operator.Installation, currentPools *crdv1.IPPoolList) error {
	if instance.Spec.CNI == nil || instance.Spec.CNI.IPAM == nil {
		// These fields are needed for IP pool defaulting but defaulted themselves by the core Installation controller, which this controller waits for before
		// running. We should never hit this branch, but handle it just in case.
		return fmt.Errorf("Cannot perform IP pool defaulting until CNI configuration is available")
	}

	if currentPools == nil || len(currentPools.Items) == 0 {
		// Only add default CIDRs if there are no existing pools in the cluster. If there are existing pools in the cluster,
		// then we assume that the user has configured them correctly out-of-band and we should not install any others.
		if instance.Spec.KubernetesProvider == operator.ProviderOpenShift {
			// If configured to run in openshift, then also fetch the openshift configuration API.
			log.V(1).Info("Fetching OpenShift network configuration")
			openshiftConfig := &configv1.Network{}
			openshiftNetworkConfig := "cluster"
			if err := client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig); err != nil {
				return fmt.Errorf("Unable to read openshift network configuration: %s", err.Error())
			}

			// Merge in OpenShift configuration.
			if err := updateInstallationForOpenshiftNetwork(instance, openshiftConfig); err != nil {
				return fmt.Errorf("Could not resolve CalicoNetwork IPPool and OpenShift network: %s", err.Error())
			}
		} else {
			// Check if we're running on kubeadm by getting the config map.
			log.V(1).Info("Fetching kubeadm config map")
			kubeadmConfig := &corev1.ConfigMap{}
			key := types.NamespacedName{Name: kubeadmConfigMap, Namespace: metav1.NamespaceSystem}
			if err := client.Get(ctx, key, kubeadmConfig); err == nil {
				// We found the configmap - merge in kubeadm configuration.
				if err := updateInstallationForKubeadm(instance, kubeadmConfig); err != nil {
					return fmt.Errorf("Could not resolve CalicoNetwork IPPool and kubeadm configuration: %s", err.Error())
				}
			} else if !apierrors.IsNotFound(err) {
				return fmt.Errorf("Unable to read kubeadm config map: %s", err.Error())
			}
		}

		// Only default the IP pools if Calico IPAM is being used, and there are no IP pools specified.
		// Defaulting of the Spec.CNI field occurs in pkg/controller/installation/
		poolsUnspecified := instance.Spec.CalicoNetwork == nil || instance.Spec.CalicoNetwork.IPPools == nil
		calicoIPAM := instance.Spec.CNI != nil && instance.Spec.CNI.IPAM != nil && instance.Spec.CNI.IPAM.Type == operator.IPAMPluginCalico
		log.V(1).Info("Checking if we should default IP pool configuration", "calicoIPAM", calicoIPAM, "poolsUnspecified", poolsUnspecified)
		if poolsUnspecified && calicoIPAM {
			if instance.Spec.CalicoNetwork == nil {
				instance.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
			}

			switch instance.Spec.KubernetesProvider {
			case operator.ProviderEKS:
				// On EKS, default to a CIDR that doesn't overlap with the host range,
				// and also use VXLAN encap by default.
				instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
					{
						Name:          "default-ipv4-ippool",
						CIDR:          "172.16.0.0/16",
						Encapsulation: operator.EncapsulationVXLAN,
					},
				}
			default:
				instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
					{
						Name: "default-ipv4-ippool",
						CIDR: "192.168.0.0/16",
					},
				}
			}
		}
	} else if instance.Spec.CalicoNetwork == nil || instance.Spec.CalicoNetwork.IPPools == nil {
		// There are existing IP pools in the cluster, and the installation hasn't specified any. This means IP pools are
		// being managed out-of-bad of the operator API. So, default the installation field to an empty list,
		// which means "Don't install any IP pools".
		if instance.Spec.CalicoNetwork == nil {
			instance.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
		}
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{}
	}

	// If there are no CalicoNetwork settings, return early. The code after this point
	// assumes that there are CalicoNetwork settings to default.
	if instance.Spec.CalicoNetwork == nil {
		return nil
	}

	currentPoolLookup := map[string]string{}
	if currentPools != nil {
		for _, cur := range currentPools.Items {
			currentPoolLookup[cur.Spec.CIDR] = cur.Name
		}
	}

	// Default any fields on each IP pool declared in the Installation object.
	for i := 0; i < len(instance.Spec.CalicoNetwork.IPPools); i++ {
		pool := &instance.Spec.CalicoNetwork.IPPools[i]

		if len(pool.AllowedUses) == 0 {
			pool.AllowedUses = []operator.IPPoolAllowedUse{operator.IPPoolAllowedUseWorkload, operator.IPPoolAllowedUseTunnel}
		}

		// Do per-IP-family defaulting.
		addr, _, err := net.ParseCIDR(pool.CIDR)
		if err == nil && addr.To4() != nil {
			// This is an IPv4 pool.
			if pool.Encapsulation == "" {
				if instance.Spec.CNI.Type == operator.PluginCalico {
					pool.Encapsulation = operator.EncapsulationIPIP
				} else {
					pool.Encapsulation = operator.EncapsulationNone
				}
			}
			if pool.NATOutgoing == "" {
				pool.NATOutgoing = operator.NATOutgoingEnabled
			}
			if pool.NodeSelector == "" {
				pool.NodeSelector = operator.NodeSelectorDefault
			}
			if pool.BlockSize == nil {
				var twentySix int32 = 26
				pool.BlockSize = &twentySix
			}
		} else if err == nil && addr.To16() != nil {
			// This is an IPv6 pool.
			if pool.Encapsulation == "" {
				pool.Encapsulation = operator.EncapsulationNone
			}
			if pool.NATOutgoing == "" {
				pool.NATOutgoing = operator.NATOutgoingDisabled
			}
			if pool.NodeSelector == "" {
				pool.NodeSelector = operator.NodeSelectorDefault
			}
			if pool.BlockSize == nil {
				var oneTwentyTwo int32 = 122
				pool.BlockSize = &oneTwentyTwo
			}
		}

		// Default the name if it's not set.
		if pool.Name == "" {
			if name, ok := currentPoolLookup[pool.CIDR]; ok {
				// There's an existing IP pool with the same CIDR - use that. This allows us to
				// assume control of IP pools that are already in the cluster.
				pool.Name = name
			} else {
				// Use the CIDR to generate a name.
				pool.Name, err = cidrToName(pool.CIDR)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Reconcile reconciles IP pools in the cluster.
//
// - Query desired IP pools (from Installation)
// - Query existing IP pools owned by this controller
// - Reconcile the differences
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling IP pools")

	// Get the Installation object - this is the source of truth for IP pools managed by
	// this controller.
	installation := &operator.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, installation); err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	defer r.status.SetMetaData(&installation.ObjectMeta)

	// This controller relies on the core Installation controller to perform initial defaulting before it can continue.
	// The core installation controller adds a specific finalizer as part of performing defaulting,
	// so wait for that before we continue.
	finalizerExists := false
	for _, finalizer := range installation.GetFinalizers() {
		if finalizer == render.CalicoFinalizer {
			finalizerExists = true
			break
		}
	}
	if !finalizerExists {
		r.status.SetDegraded(operator.ResourceNotReady, "Waiting for Installation defaulting to occur", nil, reqLogger)
		return reconcile.Result{}, nil
	}
	if installation.Spec.CNI == nil || installation.Spec.CNI.Type == "" {
		r.status.SetDegraded(operator.ResourceNotReady, "Waiting for CNI type to be defaulted", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// If the installation is terminating, do nothing.
	if installation.DeletionTimestamp != nil {
		reqLogger.Info("Installation is terminating, skipping reconciliation")
		return reconcile.Result{}, nil
	}

	// Get all IP pools currently in the cluster.
	currentPools := &crdv1.IPPoolList{}
	err := r.client.List(ctx, currentPools)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operator.ResourceReadError, "error querying IP pools", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Write default IP pool configuration back to the Installation object using patch.
	preDefaultPatchFrom := client.MergeFrom(installation.DeepCopy())
	if err = fillDefaults(ctx, r.client, installation, currentPools); err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "error filling IP pool defaults", err, reqLogger)
		return reconcile.Result{}, err
	}
	if err = ValidatePools(installation); err != nil {
		r.status.SetDegraded(operator.InvalidConfigurationError, "error validating IP pool configuration", err, reqLogger)
		return reconcile.Result{}, err
	}
	if err := r.client.Patch(ctx, installation, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get the APIServer. If healthy, we'll use the projectcalico.org/v3 API for managing pools.
	// Otherwise, we'll use the internal v1 API for bootstrapping the cluster until the API server is available.
	// This controller will never delete pools using the v1 API, as deletion process is complex and only
	// properly handled when using the v3 API.
	apiserver, _, err := utils.GetAPIServer(ctx, r.client)
	if err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operator.ResourceNotReady, "Error querying APIServer", err, reqLogger)
		return reconcile.Result{}, err
	}
	apiAvailable := apiserver != nil && apiserver.Status.State == v1.TigeraStatusReady

	// Create a lookup map of pools owned by this controller for easy access.
	// This controller will ignore any IP pools that it itself did not create.
	ourPools := map[string]crdv1.IPPool{}
	for _, p := range currentPools.Items {
		if hasOwner(&p, installation) {
			// This pool is owned by the Installation object, so consider it ours.
			ourPools[p.Spec.CIDR] = p
		} else if p.Name == "default-ipv4-ippool" {
			// For legacy installs, this is the IP pool that was created. Consider it ours.
			ourPools[p.Spec.CIDR] = p
		}
	}
	reqLogger.V(1).Info("Found IP pools owned by us", "count", len(ourPools))

	// For each pool that is desired, but doesn't exist, create it.
	// We will install pools at start-of-day using the CRD API, but otherwise
	// we require the v3 API to be running. This is so that we properly leverage the v3 API's validation.
	toCreateOrUpdate := []client.Object{}
	for _, p := range installation.Spec.CalicoNetwork.IPPools {
		// We need to check if updates are required, but the installation uses the operator API format and the queried
		// pools are in crd.projectcalico.org/v1 format. Compare the pools using the crd.projectcalico.org/v1 format.
		v1res, err := p.ToProjectCalicoV1()
		if err != nil {
			r.status.SetDegraded(operator.ResourceValidationError, "error handling IP pool", err, reqLogger)
			return reconcile.Result{}, err
		}

		if pool, ok := ourPools[p.CIDR]; !ok || !reflect.DeepEqual(pool.Spec, v1res.Spec) {
			// The pool either doesn't exist, or it does exist but needs to be updated.
			if apiAvailable {
				// The v3 API is available, so use it to create / update the pool.
				v3res, err := v1ToV3(v1res)
				if err != nil {
					r.status.SetDegraded(operator.ResourceValidationError, "error handling IP pool", err, reqLogger)
					return reconcile.Result{}, err
				}
				toCreateOrUpdate = append(toCreateOrUpdate, v3res)
			} else if len(currentPools.Items) == 0 {
				// The v3 API is not available, but there are no pools in the cluster. Create them using the v1 API, as they are needed for bootstrapping.
				// Once the v3 API is available, we'll use that instead. Note that this is an imperfect solution - it still bypasses apiserver validation for
				// the initial creation of IP pools (although we expect them to be valid due to operator validation). If the bootstrap pools
				// are invalid and do not enable the Calico apiserver to launch successfully, then manual intervention will be required.
				toCreateOrUpdate = append(toCreateOrUpdate, v1res)
			} else {
				// The v3 API is not available, and there are existing pools in the cluster. We cannot create new pools until the v3 API is available.
				// The user may need to manually delete or update pools in order to allow the v3 API to launch successfully.
				reqLogger.Info("Comparing pools", "actual", pool, "desired", p)
				r.status.SetDegraded(operator.ResourceNotReady, "Unable to modify IP pools while Calico API server is unavailable", nil, reqLogger)
				return reconcile.Result{}, nil
			}
		}
	}

	// Check existing pools owned by this controller that are no longer in
	// the Installation resource.
	toDelete := []client.Object{}
	for cidr, v1res := range ourPools {
		reqLogger.WithValues("cidr", cidr).V(1).Info("Checking if pool is still valid")
		found := false
		for _, p := range installation.Spec.CalicoNetwork.IPPools {
			if p.CIDR == cidr {
				found = true
				break
			}
		}
		if !found {
			// This pool needs to be deleted. We only ever send deletes via the API server,
			// since deletion requires rather complex logic. If the API server isn't available,
			// we'll instead just mark the pool as disabled temporarily.
			reqLogger.WithValues("cidr", cidr).Info("Pool needs to be deleted")
			if apiAvailable {
				// v3 API is available - send a delete request.
				v3res, err := v1ToV3(&v1res)
				if err != nil {
					r.status.SetDegraded(operator.ResourceValidationError, "error handling IP pool", err, reqLogger)
					return reconcile.Result{}, err
				}
				toDelete = append(toDelete, v3res)
			} else {
				// v3 API is not available. Just mark the pool as disabled so that new allocations
				// don't come from this pool. We'll delete it once the API server is available.
				v1res.Spec.Disabled = true
				toCreateOrUpdate = append(toCreateOrUpdate, &v1res)
			}
		}
	}

	handler := utils.NewComponentHandler(log, r.client, r.scheme, installation)

	passThru := render.NewPassthroughWithLog(log, toCreateOrUpdate...)
	if err := handler.CreateOrUpdateOrDelete(ctx, passThru, nil); err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Error creating / updating IPPools", err, log)
		return reconcile.Result{}, err
	}
	delPassThru := render.NewDeletionPassthrough(toDelete...)
	if err := handler.CreateOrUpdateOrDelete(ctx, delPassThru, nil); err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Error deleting / updating IPPools", err, log)
		return reconcile.Result{}, err
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

	return reconcile.Result{}, nil
}

func CRDPoolsToOperator(crds []crdv1.IPPool) []v1.IPPool {
	pools := []v1.IPPool{}
	for _, p := range crds {
		pools = append(pools, CRDPoolToOperator(p))
	}
	return pools
}

func CRDPoolToOperator(crd crdv1.IPPool) v1.IPPool {
	pool := v1.IPPool{CIDR: crd.Spec.CIDR}

	// Set encap.
	switch crd.Spec.IPIPMode {
	case crdv1.IPIPModeAlways:
		pool.Encapsulation = v1.EncapsulationIPIP
	case crdv1.IPIPModeCrossSubnet:
		pool.Encapsulation = v1.EncapsulationIPIPCrossSubnet
	}
	switch crd.Spec.VXLANMode {
	case crdv1.VXLANModeAlways:
		pool.Encapsulation = v1.EncapsulationVXLAN
	case crdv1.VXLANModeCrossSubnet:
		pool.Encapsulation = v1.EncapsulationVXLANCrossSubnet
	}

	// Set NAT
	if crd.Spec.NATOutgoing {
		pool.NATOutgoing = v1.NATOutgoingEnabled
	}

	// Set BlockSize
	blockSize := int32(crd.Spec.BlockSize)
	pool.BlockSize = &blockSize

	// Set selector.
	pool.NodeSelector = crd.Spec.NodeSelector

	// Set BGP export.
	if crd.Spec.DisableBGPExport {
		t := true
		pool.DisableBGPExport = &t
	}

	for _, use := range crd.Spec.AllowedUses {
		pool.AllowedUses = append(pool.AllowedUses, operator.IPPoolAllowedUse(use))
	}

	return pool
}

func v1ToV3(v1pool *crdv1.IPPool) (*v3.IPPool, error) {
	bs, err := json.Marshal(v1pool)
	if err != nil {
		return nil, err
	}

	v3pool := v3.IPPool{}
	err = json.Unmarshal(bs, &v3pool)
	if err != nil {
		return nil, err
	}
	return &v3pool, nil
}
