package convert

import (
	"fmt"
	"strconv"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

func handleMTU(c *components, install *Installation) error {
	var detectedMTU *int32

	m, err := c.node.getEnv(ctx, c.client, "calico-node", "FELIX_IPINIPMTU")
	if err != nil {
		return err
	}
	detectedMTU, err = compareMTU(m, detectedMTU)
	if err != nil {
		return err
	}

	m, err = c.node.getEnv(ctx, c.client, "calico-node", "FELIX_VXLANMTU")
	if err != nil {
		return err
	}
	detectedMTU, err = compareMTU(m, detectedMTU)
	if err != nil {
		return err
	}

	m, err = c.node.getEnv(ctx, c.client, "calico-node", "FELIX_WIREGUARDMTU")
	if err != nil {
		return err
	}
	detectedMTU, err = compareMTU(m, detectedMTU)
	if err != nil {
		return err
	}

	if c.calicoCNIConfig != nil {
		if c.calicoCNIConfig.MTU == -1 {
			// if MTU is -1, we assume it was us who replaced it when doing initial CNI
			// config loading. We need to pull it from the correct source
			mtuEnv, err := c.node.getEnv(ctx, c.client, containerInstallCNI, "CNI_MTU")
			if err != nil {
				return err
			}
			detectedMTU, err = compareMTU(mtuEnv, detectedMTU)
			if err != nil {
				return err
			}

		} else {
			// user must have hardcoded their CNI instead of using our cni templating engine.
			// use the hardcoded value.
			if m := int32(c.calicoCNIConfig.MTU); m != 0 {
				if detectedMTU != nil {
					// compare against detected MTU. they must match.
					if m != *detectedMTU {
						return ErrIncompatibleCluster{"MTUs across IPIP, VXLAN, and Wireguard must match."}
					}
				} else {
					// set detected MTU for later comparison against other sources
					detectedMTU = &m
				}
			}
		}
	}

	if detectedMTU != nil {
		if install.Spec.CalicoNetwork == nil {
			install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
		}
		install.Spec.CalicoNetwork.MTU = detectedMTU
	}

	return nil
}

// compareMTU compares two MTU values and ensures they match if both are set
func compareMTU(m *string, detectedMTU *int32) (*int32, error) {
	if m == nil {
		// if this mtu source is nil, return the currently detected mtu
		return detectedMTU, nil
	}

	// if it's not nil, convert it to a number, and compare it against the currently detected mtu
	i, err := strconv.Atoi(*m)
	if err != nil {
		return nil, fmt.Errorf("couldn't convert %s to integer: %v", *m, err)
	}
	mtu := int32(i)
	if detectedMTU != nil {
		// compare against detected MTU. they must match.
		if mtu != *detectedMTU {
			return nil, ErrIncompatibleCluster{"MTUs across IPIP, VXLAN, and Wireguard must match."}
		}
	}
	return &mtu, nil
}
