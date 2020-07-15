package convert

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

func handleCore(c *components, install *Installation) error {
	dsType, err := c.node.getEnv(ctx, c.client, "calico-node", "DATASTORE_TYPE")
	if err != nil {
		return err
	}
	if dsType != nil && *dsType != "kubernetes" {
		return ErrIncompatibleCluster{"only DATASTORE_TYPE=kubernetes is supported at this time"}
	}

	// resource limits
	node := getContainer(c.node.Spec.Template.Spec, "calico-node")
	if len(node.Resources.Limits) > 0 || len(node.Resources.Requests) > 0 {
		install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
			ComponentName:        operatorv1.ComponentNameNode,
			ResourceRequirements: node.Resources.DeepCopy(),
		})
	}

	// TODO: handle these vars appropriately
	c.node.ignoreEnv("calico-node", "WAIT_FOR_DATASTORE")
	c.node.ignoreEnv("calico-node", "CLUSTER_TYPE")
	c.node.ignoreEnv("calico-node", "NODENAME")
	c.node.ignoreEnv("calico-node", "CALICO_DISABLE_FILE_LOGGING")

	return nil
}
