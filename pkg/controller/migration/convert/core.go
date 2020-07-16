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

	// node resource limits
	node := getContainer(c.node.Spec.Template.Spec, "calico-node")
	if len(node.Resources.Limits) > 0 || len(node.Resources.Requests) > 0 {
		install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
			ComponentName:        operatorv1.ComponentNameNode,
			ResourceRequirements: node.Resources.DeepCopy(),
		})
	}

	// kube-controllers
	kubeControllers := getContainer(c.kubeControllers.Spec.Template.Spec, "calico-kube-controllers")
	if len(kubeControllers.Resources.Limits) > 0 || len(kubeControllers.Resources.Requests) > 0 {
		install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
			ComponentName:        operatorv1.ComponentNameKubeControllers,
			ResourceRequirements: kubeControllers.Resources.DeepCopy(),
		})
	}

	// typha resource limits. typha is optional so check for nil first
	typha := getContainer(c.typha.Spec.Template.Spec, "calico-typha")
	if typha != nil && (len(typha.Resources.Limits) > 0 || len(typha.Resources.Requests) > 0) {
		install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
			ComponentName:        operatorv1.ComponentNameTypha,
			ResourceRequirements: typha.Resources.DeepCopy(),
		})
	}

	// TODO: handle these vars appropriately
	c.node.ignoreEnv("calico-node", "WAIT_FOR_DATASTORE")
	c.node.ignoreEnv("calico-node", "CLUSTER_TYPE")
	c.node.ignoreEnv("calico-node", "NODENAME")
	c.node.ignoreEnv("calico-node", "CALICO_DISABLE_FILE_LOGGING")

	return nil
}
