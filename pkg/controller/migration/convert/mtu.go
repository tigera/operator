package convert

import (
	"fmt"
	"strconv"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

func handleMTU(c *components, install *Installation) error {
	var (
		curMTU    *int32
		curMTUSrc string
	)

	for _, src := range []string{"FELIX_IPINIPMTU", "FELIX_VXLANMTU", "FELIX_WIREGUARDMTU"} {
		mtu, err := getMTU(c, containerCalicoNode, src)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %v", src, err)
		}

		// if this mtu source is not set, ignore
		if mtu == nil {
			continue
		}

		// compare against current mtu.
		if curMTU != nil && *curMTU != *mtu {
			return fmt.Errorf("detected mtu %s=%d does not match detected mtu %s=%d", src, *mtu, curMTUSrc, *curMTU)
		}

		curMTU, curMTUSrc = mtu, src
	}

	if c.calicoCNIConfig != nil {
		if c.calicoCNIConfig.MTU == -1 {
			// if MTU is -1, we assume it was us who replaced it when doing initial CNI
			// config loading. We need to pull it from the correct source
			mtu, err := getMTU(c, containerInstallCNI, "CNI_MTU")
			if err != nil {
				return err
			}

			if mtu == nil {
				// if not set, install-cni will use a known default mtu of 1500
				mtu = new(int32)
				*mtu = 1500
			}

			// compare against current mtu.
			if curMTU != nil && *curMTU != *mtu {
				return fmt.Errorf("detected mtu %s=%d does not match detected mtu %s=%d", "CNI_MTU", *mtu, curMTUSrc, *curMTU)
			}
			curMTU, curMTUSrc = mtu, "CNI_MTU"

		} else {
			// user must have hardcoded their CNI instead of using the cni templating engine.
			// use the hardcoded value.
			mtu := int32(c.calicoCNIConfig.MTU)
			if curMTU != nil && *curMTU != mtu {
				return ErrIncompatibleCluster{"MTUs across IPIP, VXLAN, and Wireguard must match."}
			}
			// set detected MTU for later comparison against other sources
			curMTU = &mtu
		}
	}

	if curMTU != nil {
		if install.Spec.CalicoNetwork == nil {
			install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
		}
		install.Spec.CalicoNetwork.MTU = curMTU
	}

	return nil
}

// getMTU retrieves an mtu value from the calico-node container, returning the
func getMTU(c *components, container, key string) (*int32, error) {
	m, err := c.node.getEnv(ctx, c.client, container, key)
	if err != nil {
		return nil, err
	}

	if m == nil {
		return nil, nil
	}

	// if it's not nil, convert it to a number, and compare it against the currently detected mtu
	i, err := strconv.ParseInt(*m, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("couldn't convert %s to integer: %v", *m, err)
	}
	mtu := int32(i)
	return &mtu, nil
}
