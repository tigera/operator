package render

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
)

const (
	CloudComplianceServerPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "cloud-" + ComplianceServerName
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

func (c *complianceComponent) cloudComplianceServerAllowTigeraNetworkPolicy(issuerURL string) *v3.NetworkPolicy {
	issuerDomain := strings.TrimPrefix(issuerURL, "https://")
	issuerDomain = strings.TrimSuffix(issuerDomain, "/")

	egressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports:   []numorstring.Port{{MinPort: 443, MaxPort: 443}},
				Domains: []string{issuerDomain},
			},
		},
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CloudComplianceServerPolicyName,
			Namespace: ComplianceNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(ComplianceServerName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}
