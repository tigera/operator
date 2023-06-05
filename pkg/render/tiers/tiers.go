// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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

package tiers

import (
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ClusterDNSPolicyName   = networkpolicy.TigeraComponentPolicyPrefix + "cluster-dns"
	NodeLocalDNSPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "node-local-dns"
)

var TigeraNamespaceSelector = createNamespaceSelector(
	common.CalicoNamespace,
	render.GuardianNamespace,
	render.ComplianceNamespace,
	render.DexNamespace,
	render.ElasticsearchNamespace,
	render.LogCollectorNamespace,
	render.IntrusionDetectionNamespace,
	render.KibanaNamespace,
	render.ManagerNamespace,
	render.ECKOperatorNamespace,
	render.PacketCaptureNamespace,
	render.PolicyRecommendationNamespace,
	common.TigeraPrometheusNamespace,
	rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise),
	"tigera-skraper",
)

var defaultTierOrder = 100.0

func Tiers(cfg *Config) render.Component {
	return tiersComponent{cfg: cfg}
}

type Config struct {
	Openshift      bool
	DNSEgressCIDRs DNSEgressCIDR
}

type DNSEgressCIDR struct {
	IPV4 []string
	IPV6 []string
}

type tiersComponent struct {
	cfg *Config
}

func (t tiersComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (t tiersComponent) Objects() ([]client.Object, []client.Object) {
	objsToCreate := []client.Object{
		t.allowTigeraTier(),
		t.allowTigeraClusterDNSPolicy(),
	}

	objsToDelete := []client.Object{}

	if len(t.cfg.DNSEgressCIDRs.IPV4) > 0 || len(t.cfg.DNSEgressCIDRs.IPV6) > 0 {
		objsToCreate = append(objsToCreate, t.allowTigeraNodeLocalDNSPolicy())
	} else {
		objsToDelete = append(objsToDelete, t.allowTigeraNodeLocalDNSPolicy())
	}

	return objsToCreate, objsToDelete
}

func (t tiersComponent) Ready() bool {
	return true
}

func (t tiersComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (t tiersComponent) allowTigeraTier() *v3.Tier {
	return &v3.Tier{
		TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: networkpolicy.TigeraComponentTierName,
			Labels: map[string]string{
				"projectcalico.org/system-tier": "true",
			},
		},
		Spec: v3.TierSpec{
			Order: &defaultTierOrder,
		},
	}
}

func (t tiersComponent) allowTigeraClusterDNSPolicy() *v3.NetworkPolicy {
	var dnsPolicySelector string
	var dnsPolicyNamespace string
	if t.cfg.Openshift {
		dnsPolicySelector = "dns.operator.openshift.io/daemonset-dns == 'default'"
		dnsPolicyNamespace = "openshift-dns"
	} else {
		dnsPolicySelector = "k8s-app == 'kube-dns'"
		dnsPolicyNamespace = "kube-system"
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ClusterDNSPolicyName,
			Namespace: dnsPolicyNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: dnsPolicySelector,
			Ingress: []v3.Rule{
				{
					Action: v3.Allow,
					Source: v3.EntityRule{
						NamespaceSelector: "all()",
						Selector:          TigeraNamespaceSelector,
					},
				},
				{
					Action: v3.Pass,
				},
			},
			Egress: []v3.Rule{
				{
					Action: v3.Allow,
				},
			},
			Types: []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
		},
	}
}

func (t tiersComponent) allowTigeraNodeLocalDNSPolicy() *v3.GlobalNetworkPolicy {
	nodeLocalDNSPolicySelector := TigeraNamespaceSelector

	nodeLocalDNSPolicy := &v3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalNetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: NodeLocalDNSPolicyName,
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Order:    &networkpolicy.AfterHighPrecendenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: nodeLocalDNSPolicySelector,
			Egress:   []v3.Rule{},
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		},
	}

	egressRuleTemplate := v3.Rule{
		Action: v3.Allow,
		Destination: v3.EntityRule{
			// NodeLocal DNSCache creates and listens on the kube-dns ClusterIP on each node, so we can use
			// kube-dns ClusterIPs address directly in the policy where a normal service IP wouldn't match.
			Nets:  []string{},
			Ports: networkpolicy.Ports(53),
		},
		Protocol: &networkpolicy.UDPProtocol,
	}

	if len(t.cfg.DNSEgressCIDRs.IPV4) > 0 {
		IPV4Rule := egressRuleTemplate
		IPV4Rule.Destination.Nets = append(IPV4Rule.Destination.Nets, t.cfg.DNSEgressCIDRs.IPV4...)

		nodeLocalDNSPolicy.Spec.Egress = append(nodeLocalDNSPolicy.Spec.Egress, IPV4Rule)
	}

	if len(t.cfg.DNSEgressCIDRs.IPV6) > 0 {
		IPV6Rule := egressRuleTemplate
		IPV6Rule.Destination.Nets = append(IPV6Rule.Destination.Nets, t.cfg.DNSEgressCIDRs.IPV6...)

		nodeLocalDNSPolicy.Spec.Egress = append(nodeLocalDNSPolicy.Spec.Egress, IPV6Rule)
	}

	return nodeLocalDNSPolicy
}

func createNamespaceSelector(namespaces ...string) string {
	var builder strings.Builder
	builder.WriteString("projectcalico.org/namespace in {")
	for idx, namespace := range namespaces {
		builder.WriteByte('\'')
		builder.WriteString(namespace)
		builder.WriteByte('\'')
		if idx != len(namespaces)-1 {
			builder.WriteByte(',')
		}
	}
	builder.WriteByte('}')
	return builder.String()
}
