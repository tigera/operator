// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

// setTenantAndCluster sets the TENANT_ID and CLUSTER_NAME env variables to the correct values.
//
// The CLUSTER_NAME variable may have already been set by the render code, but in a multi-tenant environment the value
// will not be correct as it will also include the tenant ID. This function corrects that.
func (c *complianceComponent) setTenantAndCluster(container corev1.Container) corev1.Container {
	// c.esClusterConfig.ClusterName() is likely not the "actual" cluster name, it contains the tenant id as well so
	// we need to strip that out.
	actualClusterName := c.cfg.ESClusterConfig.ClusterName()
	clusterNameParts := strings.Split(c.cfg.ESClusterConfig.ClusterName(), ".")
	if len(clusterNameParts) > 1 {
		actualClusterName = clusterNameParts[1]
	}

	// Set the TENANT_ID variable.
	container.Env = append(container.Env, []corev1.EnvVar{
		{Name: "TENANT_ID", Value: c.cfg.TenantID},
	}...)

	// Update the CLUSTER_NAME variable if present.
	newEnv := []corev1.EnvVar{}
	for _, e := range container.Env {
		if e.Name == "CLUSTER_NAME" {
			newEnv = append(newEnv, corev1.EnvVar{
				Name:  "CLUSTER_NAME",
				Value: actualClusterName,
			})
			continue
		}
		newEnv = append(newEnv, e)
	}

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
