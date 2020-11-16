package convert

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
)

func checkTypha(c *components, _ *operatorv1.Installation) error {
	if c.typha != nil {
		if c.typha.Spec.Replicas == nil {
			return nil
		}

		curReplicas := int(*c.typha.Spec.Replicas)

		if curReplicas == 0 {
			return nil
		}

		nodes := corev1.NodeList{}
		err := c.client.List(ctx, &nodes)
		if err != nil {
			return fmt.Errorf("failed to get nodes: %v", err)
		}
		nodeCount := len(nodes.Items)
		// If the number of current typha replicas plus the number of expected replicas of the operator deployed typhas is less than the node count then we can continue.
		if nodeCount >= curReplicas+utils.GetExpectedTyphaScale(nodeCount) {
			return nil
		}

		return fmt.Errorf("Not enough nodes available for typha deployment. Have %d nodes with %d typha replicas currently deployed and %d additional typhas are needed during migration", nodeCount, curReplicas, utils.GetExpectedTyphaScale(nodeCount))
	}

	return nil
}
