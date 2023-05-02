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

const TigeraComponentTierName = "allow-tigera"
const TigeraComponentPolicyPrefix = TigeraComponentTierName + "."
const TigeraComponentDefaultDenyPolicyName = TigeraComponentPolicyPrefix + "default-deny"

var TCPProtocol = numorstring.ProtocolFromString(numorstring.ProtocolTCP)
var UDPProtocol = numorstring.ProtocolFromString(numorstring.ProtocolUDP)
var HighPrecedenceOrder = 1.0
var AfterHighPrecendenceOrder = 10.0

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
		NamespaceSelector: fmt.Sprintf("name == '%s'", namespace),
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

// The entity rules below are extracted from render subpackages to prevent cyclic dependencies.
var ESGatewayEntityRule = CreateEntityRule("tigera-elasticsearch", "tigera-secure-es-gateway", 5554)
var ESGatewaySourceEntityRule = CreateSourceEntityRule("tigera-elasticsearch", "tigera-secure-es-gateway")
var ESGatewayServiceSelectorEntityRule = CreateServiceSelectorEntityRule("tigera-elasticsearch", "tigera-secure-es-gateway-http")

var LinseedEntityRule = CreateEntityRule("tigera-elasticsearch", "tigera-linseed", 8444)
var LinseedSourceEntityRule = CreateSourceEntityRule("tigera-elasticsearch", "tigera-linseed")
var LinseedServiceSelectorEntityRule = CreateServiceSelectorEntityRule("tigera-elasticsearch", "tigera-linseed")

const PrometheusSelector = "(app == 'prometheus' && prometheus == 'calico-node-prometheus') || (app.kubernetes.io/name == 'prometheus' && prometheus == 'calico-node-prometheus')"

var PrometheusEntityRule = v3.EntityRule{
	NamespaceSelector: "projectcalico.org/name == 'tigera-prometheus'",
	Selector:          PrometheusSelector,
	Ports:             Ports(9095),
}
var PrometheusSourceEntityRule = v3.EntityRule{
	NamespaceSelector: "name == 'tigera-prometheus'",
	Selector:          PrometheusSelector,
}
