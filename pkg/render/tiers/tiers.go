// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	"fmt"
	"net"
	"strings"

	"github.com/tigera/api/pkg/lib/numorstring"
	"github.com/tigera/operator/pkg/render/monitor"

	"github.com/tigera/operator/pkg/render/kubecontrollers"

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
	APIServerPolicyName  = networkpolicy.TigeraComponentPolicyPrefix + "cnx-apiserver-access"
	ClusterDNSPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "cluster-dns"

	// Rendered here rather than kubecontrollers since creation of NetworkPolicy depends on the API server, which depends on installation controller.
	KubeControllerPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "kube-controller-access"

	// Rendered here rather than apiserver since creation of NetworkPolicy depends on the API server.
	PacketCapturePolicyName = networkpolicy.TigeraComponentPolicyPrefix + render.PacketCaptureName

	// Rendered here rather than guardian since creation of its containing Tier needs license pushed from management cluster, which depends on guardian.
	GuardianPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "guardian-access"

	// Reconciled here rather than monitor since creation of guardian depends on resources from monitor.
	PrometheusPolicyName         = networkpolicy.TigeraComponentPolicyPrefix + "prometheus"
	PrometheusAPIPolicyName      = networkpolicy.TigeraComponentPolicyPrefix + "tigera-prometheus-api"
	PrometheusOperatorPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "prometheus-operator"
	AlertManagerPolicyName       = networkpolicy.TigeraComponentPolicyPrefix + monitor.CalicoNodeAlertmanager
	MeshAlertManagerPolicyName   = AlertManagerPolicyName + "-mesh"
)

var DNSIngressNamespaceSelector = createDNSIngressNamespaceSelector(
	render.GuardianNamespace,
	render.ComplianceNamespace,
	render.DexNamespace,
	render.ElasticsearchNamespace,
	render.LogCollectorNamespace,
	render.IntrusionDetectionNamespace,
	render.KibanaNamespace,
	render.ManagerNamespace,
	common.TigeraPrometheusNamespace,
	"tigera-skraper",
	render.ECKOperatorNamespace,
	render.PacketCaptureNamespace,
	rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise),
	common.CalicoNamespace,
)

var alertManagerSelector = fmt.Sprintf(
	"(app == 'alertmanager' && alertmanager == '%[1]s') || (app.kubernetes.io/name == 'alertmanager' && alertmanager == '%[1]s')",
	monitor.CalicoNodeAlertmanager,
)
var defaultTierOrder = 100.0

func Tiers(cfg *Config) render.Component {
	return tiersComponent{cfg: cfg}
}

type Config struct {
	Openshift                   bool
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
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
		t.allowTigeraAPIServerPolicy(),
		t.allowTigeraKubeControllersPolicy(),
		t.allowTigeraPacketCapturePolicy(),
		t.allowTigeraAlertManagerPolicy(),
		t.allowTigeraAlertManagerMeshPolicy(),
		t.allowTigeraPrometheusPolicy(),
		t.allowTigeraPrometheusAPIPolicy(),
		t.allowTigeraPrometheusOperatorPolicy(),
		prometheusAllowTigeraDefaultDeny(),
	}

	if t.cfg.ManagementClusterConnection != nil {
		guardianAccessPolicy, err := t.guardianAllowTigeraPolicy()
		if err == nil {
			objsToCreate = append(objsToCreate, guardianAccessPolicy, guardianDefaultDenyAllowTigeraPolicy())
		}
	}

	// Delete equivalent policies under different namespaced names previously managed outside the operator.
	objsToDelete := []client.Object{}
	if !t.cfg.Openshift {
		objsToDelete = append(objsToDelete, &v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.kube-dns", Namespace: "kube-system"}})
		objsToDelete = append(objsToDelete, &v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.kube-dns-egress", Namespace: "kube-system"}})
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
						Selector:          DNSIngressNamespaceSelector,
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

// Allow the Kubernetes API Server access to Calico Enterprise API Server.
func (t *tiersComponent) allowTigeraAPIServerPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			// Pass to subsequent tiers for further enforcement
			Action: v3.Pass,
		},
	}...)

	// The ports Calico Enterprise API Server and Calico Enterprise Query Server are configured to listen on.
	ingressPorts := networkpolicy.Ports(443, render.ApiServerPort, render.QueryServerPort, 10443)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerPolicyName,
			Namespace: rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise),
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector("tigera-apiserver"),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					// This policy allows Calico Enterprise API Server access from anywhere.
					Source: v3.EntityRule{
						Nets: []string{"0.0.0.0/0"},
					},
					Destination: v3.EntityRule{
						Ports: ingressPorts,
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source: v3.EntityRule{
						Nets: []string{"::/0"},
					},
					Destination: v3.EntityRule{
						Ports: ingressPorts,
					},
				},
			},
			Egress: egressRules,
		},
	}
}

func (t *tiersComponent) allowTigeraKubeControllersPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(443, 6443, 12388),
			},
		},
	}...)

	if t.cfg.ManagementClusterConnection != nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.GuardianEntityRule,
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.ManagerEntityRule,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeControllerPolicyName,
			Namespace: common.CalicoNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(kubecontrollers.KubeController),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

func (t *tiersComponent) allowTigeraPacketCapturePolicy() *v3.NetworkPolicy {
	managedCluster := t.cfg.ManagementClusterConnection != nil
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)
	if !managedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.DexEntityRule,
		})
	}

	ingressRules := []v3.Rule{}
	if managedCluster {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   render.GuardianSourceEntityRule,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(render.PacketCapturePort),
			},
		})
	} else {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   render.ManagerSourceEntityRule,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(render.PacketCapturePort),
			},
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PacketCapturePolicyName,
			Namespace: render.PacketCaptureNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(render.PacketCaptureName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}

func (t *tiersComponent) guardianAllowTigeraPolicy() (*v3.NetworkPolicy, error) {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.PacketCaptureEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.PrometheusEntityRule,
		},
	}...)

	// Assumes address has the form "host:port", required by net.Dial for TCP.
	host, port, err := net.SplitHostPort(t.cfg.ManagementClusterConnection.Spec.ManagementClusterAddr)
	if err != nil {
		return nil, err
	}
	parsedPort, err := numorstring.PortFromString(port)
	if err != nil {
		return nil, err
	}
	parsedIp := net.ParseIP(host)
	if parsedIp == nil {
		// Assume host is a valid hostname.
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Domains: []string{host},
				Ports:   []numorstring.Port{parsedPort},
			},
		})
	} else {
		var netSuffix string
		if parsedIp.To4() != nil {
			netSuffix = "/32"
		} else {
			netSuffix = "/128"
		}

		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets:  []string{parsedIp.String() + netSuffix},
				Ports: []numorstring.Port{parsedPort},
			},
		})
	}

	egressRules = append(egressRules, v3.Rule{Action: v3.Pass})

	guardianIngressDestinationEntityRule := v3.EntityRule{Ports: networkpolicy.Ports(8080)}
	ingressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.FluentdSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.ComplianceBenchmarkerSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.ComplianceReporterSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.ComplianceSnapshotterSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.ComplianceControllerSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.IntrusionDetectionSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      render.IntrusionDetectionInstallerSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: guardianIngressDestinationEntityRule,
		},
	}

	policy := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianPolicyName,
			Namespace: render.GuardianNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(render.GuardianName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}

	return policy, nil
}

// Creates a network policy to allow traffic to Alertmanager (TCP port 9093).
func (t *tiersComponent) allowTigeraAlertManagerPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		// Allows all egress traffic from AlertManager.
		Action:   v3.Allow,
		Protocol: &networkpolicy.TCPProtocol,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      AlertManagerPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: alertManagerSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(monitor.AlertmanagerPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic between Alertmanagers for HA configuration (TCP port 6783).
func (t *tiersComponent) allowTigeraAlertManagerMeshPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(9094),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.UDPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(9094),
			},
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      MeshAlertManagerPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: alertManagerSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Selector: alertManagerSelector,
						Ports:    networkpolicy.Ports(9094),
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.UDPProtocol,
					Destination: v3.EntityRule{
						Selector: alertManagerSelector,
						Ports:    networkpolicy.Ports(9094),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic to access the Prometheus (TCP port 9095).
func (t *tiersComponent) allowTigeraPrometheusPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access for Felix metrics
				Ports: networkpolicy.Ports(9081, 9091),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access for BGP metrics
				Ports: networkpolicy.Ports(9900),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(monitor.AlertmanagerPort),
			},
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.DexEntityRule,
		},
	}...)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.PrometheusSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(monitor.PrometheusProxyPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic to access through tigera-prometheus-api
func (t *tiersComponent) allowTigeraPrometheusAPIPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.PrometheusEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusAPIPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector("tigera-prometheus-api"),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(monitor.PrometheusProxyPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow the prometheus-operatorto access the kube-apiserver
func (t *tiersComponent) allowTigeraPrometheusOperatorPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, t.cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.KubeAPIServerEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusOperatorPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: "operator == 'prometheus'",
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

func prometheusAllowTigeraDefaultDeny() *v3.NetworkPolicy {
	return networkpolicy.AllowTigeraDefaultDeny(common.TigeraPrometheusNamespace)
}

func guardianDefaultDenyAllowTigeraPolicy() *v3.NetworkPolicy {
	return networkpolicy.AllowTigeraDefaultDeny(render.GuardianNamespace)
}

func createDNSIngressNamespaceSelector(namespaces ...string) string {
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
