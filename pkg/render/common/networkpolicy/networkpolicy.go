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

package networkpolicy

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
)

const (
	TigeraComponentTierName              = "allow-tigera"
	TigeraComponentPolicyPrefix          = TigeraComponentTierName + "."
	TigeraComponentDefaultDenyPolicyName = TigeraComponentPolicyPrefix + "default-deny"
)

var (
	TCPProtocol               = numorstring.ProtocolFromString(numorstring.ProtocolTCP)
	UDPProtocol               = numorstring.ProtocolFromString(numorstring.ProtocolUDP)
	HighPrecedenceOrder       = 1.0
	AfterHighPrecendenceOrder = 10.0
)

// AppendDNSEgressRules appends a rule to the provided slice that allows DNS egress. The appended rule utilizes label selectors and ports.
func AppendDNSEgressRules(egressRules []v3.Rule, openShift bool) []v3.Rule {
	if openShift {
		egressRules = append(egressRules, []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &UDPProtocol,
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'openshift-dns'",
					Selector:          "dns.operator.openshift.io/daemonset-dns == 'default'",
					Ports:             Ports(5353),
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &TCPProtocol,
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'openshift-dns'",
					Selector:          "dns.operator.openshift.io/daemonset-dns == 'default'",
					Ports:             Ports(5353),
				},
			},
		}...)
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &UDPProtocol,
			Destination: v3.EntityRule{
				NamespaceSelector: "projectcalico.org/name == 'kube-system'",
				Selector:          "k8s-app == 'kube-dns'",
				Ports:             Ports(53),
			},
		})
	}

	return egressRules
}

// CreateEntityRule creates an entity rule that matches traffic using label selectors based on namespace, deployment name, and port.
func CreateEntityRule(namespace string, deploymentName string, ports ...uint16) v3.EntityRule {
	return v3.EntityRule{
		NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace),
		Selector:          fmt.Sprintf("k8s-app == '%s'", deploymentName),
		Ports:             Ports(ports...),
	}
}

// CreateSourceEntityRule creates a conventional entity rule that matches ingress traffic based on namespace and deployment name.
func CreateSourceEntityRule(namespace string, deploymentName string) v3.EntityRule {
	return v3.EntityRule{
		Selector:          fmt.Sprintf("k8s-app == '%s'", deploymentName),
		NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace),
	}
}

// AppendServiceSelectorDNSEgressRules is equivalent to AppendDNSEgressRules, utilizing service selector instead of label selector and ports.
func AppendServiceSelectorDNSEgressRules(egressRules []v3.Rule, openShift bool) []v3.Rule {
	if openShift {
		egressRules = append(egressRules, []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &UDPProtocol,
				Destination: v3.EntityRule{
					Services: &v3.ServiceMatch{
						Namespace: "default",
						Name:      "openshift-dns",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &TCPProtocol,
				Destination: v3.EntityRule{
					Services: &v3.ServiceMatch{
						Namespace: "default",
						Name:      "openshift-dns",
					},
				},
			},
		}...)
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &UDPProtocol,
			Destination: v3.EntityRule{
				Services: &v3.ServiceMatch{
					Namespace: "kube-system",
					Name:      "kube-dns",
				},
			},
		})
	}

	return egressRules
}

// CreateServiceSelectorEntityRule creates an entity rule that matches traffic based on service name and namespace.
func CreateServiceSelectorEntityRule(namespace string, name string) v3.EntityRule {
	return v3.EntityRule{
		Services: &v3.ServiceMatch{
			Namespace: namespace,
			Name:      name,
		},
	}
}

func KubernetesAppSelector(deploymentNames ...string) string {
	expressions := []string{}
	for _, deploymentName := range deploymentNames {
		expressions = append(expressions, fmt.Sprintf("k8s-app == '%s'", deploymentName))
	}
	return strings.Join(expressions, " || ")
}

func Ports(ports ...uint16) []numorstring.Port {
	nsPorts := []numorstring.Port{}
	for _, port := range ports {
		nsPorts = append(nsPorts, numorstring.Port{MinPort: port, MaxPort: port})
	}

	return nsPorts
}

func AllowTigeraDefaultDeny(namespace string) *v3.NetworkPolicy {
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TigeraComponentDefaultDenyPolicyName,
			Namespace: namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     TigeraComponentTierName,
			Selector: "all()",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
		},
	}
}

// Entity rules not belonging to Calico/Tigera components.
var KubeAPIServerEntityRule = v3.EntityRule{
	NamespaceSelector: "projectcalico.org/name == 'default'",
	Selector:          "(provider == 'kubernetes' && component == 'apiserver' && endpoints.projectcalico.org/serviceName == 'kubernetes')",
	Ports:             Ports(443, 6443, 12388),
}

var KubeAPIServerServiceSelectorEntityRule = v3.EntityRule{
	Services: &v3.ServiceMatch{
		Namespace: "default",
		Name:      "kubernetes",
	},
}

// Helper creates a helper for building network policies for multi-tenant capable components.
// It takes two arguments:
// - mt: true if running in multi-tenant mode, false otherwise.
// - ns: The tenant's namespce.
func Helper(mt bool, ns string) *NetworkPolicyHelper {
	return &NetworkPolicyHelper{
		multiTenant: mt,
		ns:          ns,
	}
}

// DefaultHelper returns a NetworkPolicyHelper configured for services that
// only run in single-tenant clusters.
func DefaultHelper() *NetworkPolicyHelper {
	return &NetworkPolicyHelper{
		multiTenant: false,
		ns:          "",
	}
}

type NetworkPolicyHelper struct {
	multiTenant bool
	ns          string
}

func (h *NetworkPolicyHelper) namespace(def string) string {
	if !h.multiTenant {
		return def
	}
	return h.ns
}

// ESGatewayEntityRule returns an entity rule that selects es-gateway pods in the given namespace.
func (h *NetworkPolicyHelper) ESGatewayEntityRule() v3.EntityRule {
	return CreateEntityRule(h.namespace("tigera-elasticsearch"), "tigera-secure-es-gateway", 5554)
}

func (h *NetworkPolicyHelper) ESGatewaySourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("tigera-elasticsearch"), "tigera-secure-es-gateway")
}

func (h *NetworkPolicyHelper) ESGatewayServiceSelectorEntityRule() v3.EntityRule {
	return CreateServiceSelectorEntityRule(h.namespace("tigera-elasticsearch"), "tigera-secure-es-gateway-http")
}

func (h *NetworkPolicyHelper) LinseedEntityRule() v3.EntityRule {
	return CreateEntityRule(h.namespace("tigera-elasticsearch"), "tigera-linseed", 8444)
}

func (h *NetworkPolicyHelper) LinseedSourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("tigera-elasticsearch"), "tigera-linseed")
}

func (h *NetworkPolicyHelper) LinseedServiceSelectorEntityRule() v3.EntityRule {
	return CreateServiceSelectorEntityRule(h.namespace("tigera-elasticsearch"), "tigera-linseed")
}

func (h *NetworkPolicyHelper) ManagerEntityRule() v3.EntityRule {
	return CreateEntityRule(h.namespace("tigera-manager"), "tigera-manager", 9443)
}

func (h *NetworkPolicyHelper) ManagerSourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("tigera-manager"), "tigera-manager")
}

func (h *NetworkPolicyHelper) PolicyRecommendationSourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("tigera-policy-recommendation"), "tigera-policy-recommendation")
}

const PrometheusSelector = "k8s-app == 'tigera-prometheus'"

var PrometheusEntityRule = v3.EntityRule{
	NamespaceSelector: "projectcalico.org/name == 'tigera-prometheus'",
	Selector:          PrometheusSelector,
	Ports:             Ports(9095),
}

var PrometheusSourceEntityRule = v3.EntityRule{
	NamespaceSelector: "name == 'tigera-prometheus'",
	Selector:          PrometheusSelector,
}
