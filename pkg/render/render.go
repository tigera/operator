// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"bytes"
	"fmt"

	"github.com/openshift/library-go/pkg/crypto"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	TyphaCAConfigMapName = "typha-ca"
	TyphaCABundleName    = "caBundle"
	TyphaTLSSecretName   = "typha-certs"
	NodeTLSSecretName    = "node-certs"
	TLSSecretCertName    = "cert.crt"
	TLSSecretKeyName     = "key.key"
	CommonName           = "common-name"
	URISAN               = "uri-san"
)

type Component interface {
	// Objects returns all objects this component contains.
	Objects() []runtime.Object

	// Ready returns true if the component is ready to be created.
	Ready() bool
}

// A Renderer is capable of generating components to be installed on the cluster.
type Renderer interface {
	Render() []Component
}

type TyphaNodeTLS struct {
	CAConfigMap *corev1.ConfigMap
	TyphaSecret *corev1.Secret
	NodeSecret  *corev1.Secret
}

func Calico(
	cr *operator.Installation,
	pullSecrets []*corev1.Secret,
	typhaNodeTLS *TyphaNodeTLS,
	bt map[string]string,
	p operator.Provider,
	nc NetworkConfig,
) (Renderer, error) {

	tcms := []*corev1.ConfigMap{}
	tss := []*corev1.Secret{}

	if typhaNodeTLS == nil {
		typhaNodeTLS = &TyphaNodeTLS{}
	}

	// Check the CA configMap and Secrets to ensure they are a valid combination and
	// if the TLS info needs to be created.
	// We should have them all or none.
	if typhaNodeTLS.CAConfigMap == nil {
		if typhaNodeTLS.TyphaSecret != nil || typhaNodeTLS.NodeSecret != nil {
			return nil, fmt.Errorf("Typha-Felix CA config map did not exist and neither should the Secrets (%v)", typhaNodeTLS)
		}
		var err error
		typhaNodeTLS, err = createTLS()
		if err != nil {
			return nil, fmt.Errorf("Failed to create Typha TLS: %s", err)
		}
		tcms = append(tcms, typhaNodeTLS.CAConfigMap)
		tss = append(tss, typhaNodeTLS.TyphaSecret, typhaNodeTLS.NodeSecret)
	} else {
		// CA ConfigMap exists
		if typhaNodeTLS.TyphaSecret == nil || typhaNodeTLS.NodeSecret == nil {
			return nil, fmt.Errorf("Typha-Felix CA config map exists and so should the Secrets.")
		}
	}

	// Create copy to go into Calico Namespace
	tcm := typhaNodeTLS.CAConfigMap.DeepCopy()
	tcm.ObjectMeta = metav1.ObjectMeta{Name: typhaNodeTLS.CAConfigMap.Name, Namespace: CalicoNamespace}
	tcms = append(tcms, tcm)

	ts := typhaNodeTLS.TyphaSecret.DeepCopy()
	ts.ObjectMeta = metav1.ObjectMeta{Name: ts.Name, Namespace: CalicoNamespace}
	ns := typhaNodeTLS.NodeSecret.DeepCopy()
	ns.ObjectMeta = metav1.ObjectMeta{Name: ns.Name, Namespace: CalicoNamespace}
	tss = append(tss, ts, ns)

	return calicoRenderer{
		installation:  cr,
		pullSecrets:   pullSecrets,
		typhaNodeTLS:  typhaNodeTLS,
		tlsConfigMaps: tcms,
		tlsSecrets:    tss,
		birdTemplates: bt,
		provider:      p,
		networkConfig: nc,
	}, nil
}

func createTLS() (*TyphaNodeTLS, error) {
	// Make CA
	ca, err := makeCA()
	if err != nil {
		return nil, err
	}
	crtContent := &bytes.Buffer{}
	keyContent := &bytes.Buffer{}
	if err := ca.Config.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}

	tntls := TyphaNodeTLS{}
	// Take CA cert and create ConfigMap
	data := make(map[string]string)
	data[TyphaCABundleName] = crtContent.String()
	tntls.CAConfigMap = &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaCAConfigMapName,
			Namespace: OperatorNamespace(),
		},
		Data: data,
	}

	// Create TLS Secret for Felix using ca from above
	tntls.NodeSecret, err = createOperatorTLSSecret(ca,
		NodeTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		[]crypto.CertificateExtensionFunc{setClientAuth},
		"typha-client")
	if err != nil {
		return nil, err
	}
	// Set the CommonName used to create cert
	tntls.NodeSecret.Data[CommonName] = []byte("typha-client")

	// Create TLS Secret for Felix using ca from above
	tntls.TyphaSecret, err = createOperatorTLSSecret(ca,
		TyphaTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		[]crypto.CertificateExtensionFunc{setServerAuth},
		"typha-server")
	if err != nil {
		return nil, err
	}
	// Set the CommonName used to create cert
	tntls.TyphaSecret.Data[CommonName] = []byte("typha-server")

	return &tntls, nil
}

type calicoRenderer struct {
	installation  *operator.Installation
	pullSecrets   []*corev1.Secret
	typhaNodeTLS  *TyphaNodeTLS
	tlsConfigMaps []*corev1.ConfigMap
	tlsSecrets    []*corev1.Secret
	birdTemplates map[string]string
	provider      operator.Provider
	networkConfig NetworkConfig
}

func (r calicoRenderer) Render() []Component {
	var components []Component
	components = appendNotNil(components, CustomResourceDefinitions(r.installation))
	components = appendNotNil(components, PriorityClassDefinitions(r.installation))
	components = appendNotNil(components, Namespaces(r.installation, r.provider == operator.ProviderOpenShift, r.pullSecrets))
	components = appendNotNil(components, ConfigMaps(r.tlsConfigMaps))
	components = appendNotNil(components, Secrets(r.tlsSecrets))
	components = appendNotNil(components, Typha(r.installation, r.provider, r.typhaNodeTLS))
	components = appendNotNil(components, Node(r.installation, r.provider, r.networkConfig, r.birdTemplates, r.typhaNodeTLS))
	components = appendNotNil(components, KubeControllers(r.installation))
	components = appendNotNil(components, ClusterRoles(r.installation))
	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}

type clusterRolesComponent struct {
	cr *operator.Installation
}

func ClusterRoles(cr *operator.Installation) *clusterRolesComponent {
	return &clusterRolesComponent{cr}
}

func (c *clusterRolesComponent) Objects() []runtime.Object {
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		return []runtime.Object{c.tigeraUserClusterRole(), c.tigeraNetworkAdminClusterRole()}
	}

	return []runtime.Object{}
}

func (c *clusterRolesComponent) Ready() bool {
	return true
}

// tigeraUserClusterRole returns a cluster role for a default Tigera Secure user.
func (c *clusterRolesComponent) tigeraUserClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// List requests that the Tigera manager needs.
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
				"",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "ee-calico-tiered-policy-passthru" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"namespaces",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
			},
			Verbs: []string{"watch", "list"},
		},
		// Access to statistics.
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:tigera-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		// Access to policies in the default tier
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"tiers"},
			ResourceNames: []string{"default"},
			Verbs:         []string{"get"},
		},
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// List and view the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
			},
			Verbs: []string{"get", "watch", "list"},
		},
	}

	// If this is a managed cluster the rule to access the clusters indices in Elasticsearch need to be added to the management
	// cluster
	if c.cr.Spec.ClusterManagementType != operator.ClusterManagementTypeManaged {
		// Access to flow logs, audit logs, and statistics
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "events", "dns",
			},
			Verbs: []string{"get"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-ui-user",
		},
		Rules: rules,
	}
}

// tigeraNetworkAdminClusterRole returns a cluster role for a Tigera Secure manager network admin.
func (c *clusterRolesComponent) tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// Full access to all network policies
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "ee-calico-tiered-policy-passthru" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"globalnetworksets",
				"networksets",
				"managedclusters",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// Additional "list" requests that the Tigera Secure manager needs
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"watch", "list"},
		},
		// Access to statistics.
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:tigera-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		// Manage globalreport configuration, view report generation status, and list reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports/status"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		// Access to cluster information containing Calico and EE versions from the UI.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// Manage the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
	}

	// If this is a managed cluster the rule to access the clusters indices in Elasticsearch need to be added to the management
	// cluster
	if c.cr.Spec.ClusterManagementType != operator.ClusterManagementTypeManaged {
		// Access to flow logs, audit logs, and statistics
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "events", "dns",
			},
			Verbs: []string{"get"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-network-admin",
		},
		Rules: rules,
	}
}
