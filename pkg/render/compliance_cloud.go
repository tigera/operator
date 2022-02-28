package render

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// replaceESIndexFixs adds the ELASTIC_INDEX_MIDFIX env variable as the tenant ID and changes the ELASTIC_INDEX_SUFFIX
// to be the actual cluster name (as opposed to <tenant_id>.<cluster_name> as it currently does). This is needed only
// for certain components that replace the cluster name with managed cluster names, i.e. compliance server.
func (c *complianceComponent) replaceESIndexFixsEnvs(container corev1.Container) corev1.Container {
	// c.esClusterConfig.ClusterName() is likely not the "actual" cluster name, it contains the tenant id as well so
	// we need to strip that out.
	actualClusterName := c.cfg.ESClusterConfig.ClusterName()

	clusterNameParts := strings.Split(c.cfg.ESClusterConfig.ClusterName(), ".")
	if len(clusterNameParts) > 1 {
		actualClusterName = clusterNameParts[1]
	}

	newEnv := make([]corev1.EnvVar, 0, len(container.Env))
	for _, env := range container.Env {
		if env.Name == "ELASTIC_INDEX_SUFFIX" {
			continue
		}
		newEnv = append(newEnv, env)
	}

	newEnv = append(newEnv,
		corev1.EnvVar{Name: "ELASTIC_INDEX_MIDFIX", Value: c.cfg.TenantID},
		corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: actualClusterName})

	container.Env = newEnv

	return container
}
