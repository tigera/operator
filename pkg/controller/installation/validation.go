// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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
	"fmt"
	"net"
	"path"
	"strings"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1.Installation) error {
	if instance.Spec.CNI == nil {
		return fmt.Errorf("spec.cni must be defined")
	}

	// Perform validation based on the chosen CNI plugin.
	// For example, make sure the plugin is supported on the specified k8s provider.
	switch instance.Spec.CNI.Type {
	case operatorv1.PluginCalico:
		switch instance.Spec.CNI.IPAM.Type {
		case operatorv1.IPAMPluginCalico:
		case operatorv1.IPAMPluginHostLocal:
		default:
			return fmt.Errorf(
				"spec.cni.ipam.type %s is not compatible with spec.cni.type %s, valid IPAM values %s",
				instance.Spec.CNI.IPAM.Type, instance.Spec.CNI.Type,
				strings.Join([]string{
					operatorv1.IPAMPluginCalico.String(),
					operatorv1.IPAMPluginHostLocal.String()}, ",",
				),
			)
		}
	case operatorv1.PluginGKE:
		// The GKE CNI plugin is only supported on GKE or BYO.
		switch instance.Spec.KubernetesProvider {
		case operatorv1.ProviderGKE, "":
		default:
			return fmt.Errorf("spec.kubernetesProvider %s is not compatible with spec.cni.type %s",
				instance.Spec.KubernetesProvider, instance.Spec.CNI.Type)
		}

		switch instance.Spec.CNI.IPAM.Type {
		case operatorv1.IPAMPluginHostLocal:
		default:
			return fmt.Errorf(
				"spec.cni.ipam.type %s is not compatible with spec.cni.type %s, valid IPAM values %s",
				instance.Spec.CNI.IPAM.Type, instance.Spec.CNI.Type, operatorv1.IPAMPluginHostLocal)
		}
	case operatorv1.PluginAmazonVPC:
		// The AmazonVPC CNI plugin is only supported on EKS or BYO.
		switch instance.Spec.KubernetesProvider {
		case operatorv1.ProviderEKS, "":
		default:
			return fmt.Errorf("spec.kubernetesProvider %s is not compatible with spec.cni.type %s",
				instance.Spec.KubernetesProvider, instance.Spec.CNI.Type)
		}

		switch instance.Spec.CNI.IPAM.Type {
		case operatorv1.IPAMPluginAmazonVPC:
		default:
			return fmt.Errorf(
				"spec.cni.ipam.type  %s is not compatible with spec.cni.type %s, valid IPAM values %s",
				instance.Spec.CNI.IPAM.Type, instance.Spec.CNI.Type, operatorv1.IPAMPluginAmazonVPC)
		}
	case operatorv1.PluginAzureVNET:
		// The AzureVNET CNI plugin is only supported on AKS or BYO.
		switch instance.Spec.KubernetesProvider {
		case operatorv1.ProviderAKS, "":
		default:
			return fmt.Errorf("spec.kubernetesProvider %s is not compatible with spec.cni.type %s",
				instance.Spec.KubernetesProvider, instance.Spec.CNI.Type)
		}

		switch instance.Spec.CNI.IPAM.Type {
		case operatorv1.IPAMPluginAzureVNET:
		default:
			return fmt.Errorf(
				"spec.cni.ipam.type %s is not compatible with spec.cni.type %s, valid IPAM values %s",
				instance.Spec.CNI.IPAM.Type, instance.Spec.CNI.Type, operatorv1.IPAMPluginAzureVNET)
		}
	default:
		// The specified CNI plugin is not supported by this version of the operator.
		return fmt.Errorf("Invalid value '%s' for spec.cni.type, it should be one of %s",
			instance.Spec.CNI.Type, strings.Join(operatorv1.CNIPluginTypesString, ","))
	}

	// Verify Calico settings, if specified.
	if instance.Spec.CalicoNetwork != nil {

		nPools := len(instance.Spec.CalicoNetwork.IPPools)
		if nPools > 2 {
			return fmt.Errorf("Only one IPPool per version is allowed.")
		}

		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)

		if nPools == 2 && (v4pool == nil || v6pool == nil) {
			return fmt.Errorf("Only one IPPool per version is allowed.")
		}

		if v4pool != nil {
			_, cidr, err := net.ParseCIDR(v4pool.CIDR)
			if err != nil {
				return fmt.Errorf("ipPool.CIDR(%s) is invalid: %s", v4pool.CIDR, err)
			}

			if instance.Spec.CNI.Type == operatorv1.PluginCalico {
				// Verify the specified encapsulation type is valid.
				switch v4pool.Encapsulation {
				case operatorv1.EncapsulationIPIP, operatorv1.EncapsulationIPIPCrossSubnet:
					// IPIP currently requires BGP to be running in order to program routes.
					if instance.Spec.CalicoNetwork.BGP == nil || *instance.Spec.CalicoNetwork.BGP == operatorv1.BGPDisabled {
						return fmt.Errorf("IPIP encapsulation requires that BGP is enabled")
					}
				case operatorv1.EncapsulationVXLAN, operatorv1.EncapsulationVXLANCrossSubnet:
				case operatorv1.EncapsulationNone:
					// Unencapsulated currently requires BGP to be running in order to program routes.
					if instance.Spec.CalicoNetwork.BGP == nil || *instance.Spec.CalicoNetwork.BGP == operatorv1.BGPDisabled {
						return fmt.Errorf("Unencapsulated IP pools require that BGP is enabled")
					}
				default:
					return fmt.Errorf("%s is invalid for ipPool.encapsulation, should be one of %s",
						v4pool.Encapsulation, strings.Join(operatorv1.EncapsulationTypesString, ","))
				}
			} else {
				// Verify the specified encapsulation type is valid.
				switch v4pool.Encapsulation {
				case operatorv1.EncapsulationNone:
				default:
					return fmt.Errorf("%s is invalid for ipPool.encapsulation when using non-Calico CNI, should be None",
						v4pool.Encapsulation)
				}
				if instance.Spec.CalicoNetwork.BGP != nil && *instance.Spec.CalicoNetwork.BGP == operatorv1.BGPEnabled {
					return fmt.Errorf("BGP is not supported when using non-Calico CNI")
				}
				if v4pool.NodeSelector != "all()" {
					return fmt.Errorf("ipPool.nodeSelector (%s) should be 'all()'", v4pool.NodeSelector)
				}
			}

			if v4pool.NodeSelector == "" {
				return fmt.Errorf("ipPool.nodeSelector should not be empty")
			}

			// Verify NAT outgoing values.
			switch v4pool.NATOutgoing {
			case operatorv1.NATOutgoingEnabled, operatorv1.NATOutgoingDisabled:
			default:
				return fmt.Errorf("%s is invalid for ipPool.natOutgoing, should be one of %s",
					v4pool.NATOutgoing, strings.Join(operatorv1.NATOutgoingTypesString, ","))
			}

			if v4pool.BlockSize != nil {
				if *v4pool.BlockSize > 32 || *v4pool.BlockSize < 20 {
					return fmt.Errorf("ipPool.blockSize must be greater than 19 and less than or equal to 32")

				}

				// Verify that the CIDR contains the blocksize.
				ones, _ := cidr.Mask.Size()
				if int32(ones) > *v4pool.BlockSize {
					return fmt.Errorf("IP pool size is too small. It must be equal to or greater than the block size.")
				}
			}
		}

		if v6pool != nil {
			_, cidr, err := net.ParseCIDR(v6pool.CIDR)
			if err != nil {
				return fmt.Errorf("ipPool.CIDR(%s) is invalid: %s", v6pool.CIDR, err)
			}

			if v6pool.Encapsulation != operatorv1.EncapsulationNone {
				return fmt.Errorf("Encapsulation is not supported by IPv6 pools, but it is set for %s", v6pool.CIDR)
			}

			// Verify NAT outgoing values.
			switch v6pool.NATOutgoing {
			case operatorv1.NATOutgoingEnabled, operatorv1.NATOutgoingDisabled:
				// Valid.
			default:
				return fmt.Errorf("%s is invalid for ipPool.natOutgoing, should be one of %s",
					v6pool.NATOutgoing, strings.Join(operatorv1.NATOutgoingTypesString, ","))
			}

			if instance.Spec.CNI.Type != operatorv1.PluginCalico {
				if v6pool.NodeSelector != "all()" {
					return fmt.Errorf("ipPool.nodeSelector (%s) should be 'all()' when using non-Calico CNI plugin", v6pool.NodeSelector)
				}
			}
			if v6pool.NodeSelector == "" {
				return fmt.Errorf("ipPool.nodeSelector should not be empty")
			}

			if v6pool.BlockSize != nil {
				if *v6pool.BlockSize > 128 || *v6pool.BlockSize < 116 {
					return fmt.Errorf("ipPool.blockSize must be greater than 115 and less than or equal to 128")
				}

				// Verify that the CIDR contains the blocksize.
				ones, _ := cidr.Mask.Size()
				if int32(ones) > *v6pool.BlockSize {
					return fmt.Errorf("IP pool size is too small. It must be equal to or greater than the block size.")
				}
			}
		}

		if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 != nil {
			err := validateNodeAddressDetection(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4)
			if err != nil {
				return err
			}
		}

		if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 != nil {
			err := validateNodeAddressDetection(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6)
			if err != nil {
				return err
			}
		}

		if instance.Spec.CalicoNetwork.HostPorts != nil {
			if instance.Spec.CNI.Type != operatorv1.PluginCalico {
				return fmt.Errorf("spec.calicoNetwork.hostPorts is supported only for Calico CNI")
			}
			err := validateHostPorts(instance.Spec.CalicoNetwork.HostPorts)
			if err != nil {
				return err
			}
		}

		if instance.Spec.CalicoNetwork.MultiInterfaceMode != nil {
			if instance.Spec.CNI.Type != operatorv1.PluginCalico {
				return fmt.Errorf("spec.calicoNetwork.multiInterfaceMode is supported only for Calico CNI")
			}
		}

		if instance.Spec.CalicoNetwork.ContainerIPForwarding != nil {
			if instance.Spec.CNI.Type != operatorv1.PluginCalico {
				return fmt.Errorf("spec.calicoNetwork.containerIPForwarding is supported only for Calico CNI")
			}
		}
	}

	// Verify that the flexvolume path is valid - either "None" (to disable) or a valid absolute path.
	if instance.Spec.FlexVolumePath != "None" && !path.IsAbs(instance.Spec.FlexVolumePath) {
		return fmt.Errorf("Installation spec.FlexVolumePath '%s' is not an absolute path",
			instance.Spec.FlexVolumePath)
	}

	// We only support RollingUpdate for the node daemonset strategy.
	if instance.Spec.NodeUpdateStrategy.Type != appsv1.RollingUpdateDaemonSetStrategyType {
		return fmt.Errorf("Installation spec.NodeUpdateStrategy.type '%s' is not supported",
			instance.Spec.NodeUpdateStrategy.RollingUpdate)
	}

	return nil
}

// validateNodeAddressDetection checks that at most one form of IP auto-detection is configured per-family.
func validateNodeAddressDetection(ad *operatorv1.NodeAddressAutodetection) error {
	numEnabled := 0
	if len(ad.Interface) != 0 {
		numEnabled++
	}
	if len(ad.SkipInterface) != 0 {
		numEnabled++
	}
	if len(ad.CanReach) != 0 {
		numEnabled++
	}
	if ad.FirstFound != nil && *ad.FirstFound {
		numEnabled++
	}

	if numEnabled > 1 {
		return fmt.Errorf("no more than one node address autodetection method can be specified per-family")
	}
	return nil
}

func validateHostPorts(hp *operatorv1.HostPortsType) error {
	if hp == nil {
		return fmt.Errorf("HostPorts must be set, it should be one of %s",
			strings.Join(operatorv1.HostPortsTypesString, ","))
	}
	valid := false
	for _, t := range operatorv1.HostPortsTypes {
		if *hp == t {
			valid = true
		}
	}
	if !valid {
		return fmt.Errorf("%s is invalid for HostPorts, it should be one of %s",
			hp, strings.Join(operatorv1.HostPortsTypesString, ","))
	}

	return nil
}
