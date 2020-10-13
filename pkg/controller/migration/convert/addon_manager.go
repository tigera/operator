package convert

import operatorv1 "github.com/tigera/operator/api/v1"

func handleAddonManager(c *components, install *operatorv1.Installation) error {
	if _, ok := c.node.Labels["addonmanager.kubernetes.io/mode"]; ok {
		return ErrIncompatibleCluster{
			component: ComponentCalicoNode,
			err:       "can't modify components managed by addon-manager",
		}
	}

	if c.typha != nil {
		if _, ok := c.typha.Labels["addonmanager.kubernetes.io/mode"]; ok {
			return ErrIncompatibleCluster{
				component: ComponentTypha,
				err:       "can't modify components managed by addon-manager",
			}
		}
	}

	if c.kubeControllers != nil {
		if _, ok := c.kubeControllers.Labels["addonmanager.kubernetes.io/mode"]; ok {
			return ErrIncompatibleCluster{
				component: ComponentKubeControllers,
				err:       "can't modify components managed by addon-manager",
			}
		}
	}

	return nil
}
