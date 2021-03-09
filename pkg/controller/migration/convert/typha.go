package convert

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
)

const (
	containerTypha = "calico-typha"
)

func checkTypha(c *components, _ *operatorv1.Installation) error {
	if c.typha == nil {
		return nil
	}
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

	return ErrIncompatibleCluster{
		err: fmt.Sprintf("Not enough nodes available for typha deployment. Have %d nodes with %d typha replicas currently deployed and %d additional typhas are needed during migration",
			nodeCount, curReplicas, utils.GetExpectedTyphaScale(nodeCount)),
		component: ComponentTypha,
	}
}

// handleTyphaMetrics is a migration handler which detects custom prometheus settings for typha and
// carries those options forward via the TyphaMetricsPort field.
func handleTyphaMetrics(c *components, install *operatorv1.Installation) error {
	if c.typha == nil {
		return nil
	}
	metricsEnabled, err := getEnv(ctx, c.client, c.typha.Spec.Template.Spec, ComponentTypha, containerTypha, "TYPHA_PROMETHEUSMETRICSENABLED")
	if err != nil {
		return err
	}
	if metricsEnabled != nil && strings.ToLower(*metricsEnabled) == "true" {
		var _9091 int32 = 9091
		install.Spec.TyphaMetricsPort = &_9091
		port, err := getEnv(ctx, c.client, c.typha.Spec.Template.Spec, ComponentTypha, containerTypha, "TYPHA_PROMETHEUSMETRICSPORT")
		if err != nil {
			return err
		}
		if port != nil {
			p, err := strconv.ParseInt(*port, 10, 32)
			if err != nil || p <= 0 || p > 65535 {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("invalid port defined in TYPHA_PROMETHEUSMETRICSPORT=%s", *port),
					component: ComponentTypha,
					fix:       "adjust it to be within the range of 1-65535 or remove the env var",
				}
			}
			i := int32(p)
			install.Spec.TyphaMetricsPort = &i
		}
	}

	return nil
}
