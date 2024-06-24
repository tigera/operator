// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	APIServerPort       = 5443
	APIServerPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "cnx-apiserver-access"

	auditLogsVolumeName   = "tigera-audit-logs"
	auditPolicyVolumeName = "tigera-audit-policy"
)

const (
	QueryServerPort        = 8080
	QueryserverNamespace   = "tigera-system"
	QueryserverServiceName = "tigera-api"

	// Use the same API server container name for both OSS and Enterprise.
	APIServerContainerName                  = "calico-apiserver"
	APIServerK8sAppName                     = "calico-apiserver"
	TigeraAPIServerQueryServerContainerName = "tigera-queryserver"

	calicoAPIServerTLSSecretName                    = "calico-apiserver-certs"
	tigeraAPIServerTLSSecretName                    = "tigera-apiserver-certs"
	APIServerSecretsRBACName                        = "tigera-extension-apiserver-secrets-access"
	MultiTenantManagedClustersAccessClusterRoleName = "tigera-managed-cluster-access"
)

var TigeraAPIServerEntityRule = v3.EntityRule{
	Services: &v3.ServiceMatch{
		Namespace: QueryserverNamespace,
		Name:      QueryserverServiceName,
	},
}

// The following functions are helpers for determining resource names based on
// the configured product variant.
func ProjectCalicoAPIServerTLSSecretName(v operatorv1.ProductVariant) string {
	if v == operatorv1.Calico {
		return calicoAPIServerTLSSecretName
	}
	return tigeraAPIServerTLSSecretName
}

func ProjectCalicoAPIServerServiceName(v operatorv1.ProductVariant) string {
	if v == operatorv1.Calico {
		return "calico-api"
	}
	return "tigera-api"
}

func APIServerServiceAccountName(v operatorv1.ProductVariant) string {
	if v == operatorv1.Calico {
		return "calico-apiserver"
	}
	return "tigera-apiserver"
}

func APIServer(cfg *APIServerConfiguration) (Component, error) {
	return &apiServerComponent{
		cfg: cfg,
	}, nil
}

func APIServerPolicy(cfg *APIServerConfiguration) Component {
	return NewPassthrough(allowTigeraAPIServerPolicy(cfg))
}

// APIServerConfiguration contains all the config information needed to render the component.
type APIServerConfiguration struct {
	K8SServiceEndpoint          k8sapi.ServiceEndpoint
	Installation                *operatorv1.InstallationSpec
	APIServer                   *operatorv1.APIServerSpec
	ForceHostNetwork            bool
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	TLSKeyPair                  certificatemanagement.KeyPairInterface
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	TrustedBundle               certificatemanagement.TrustedBundle
	MultiTenant                 bool
}

type apiServerComponent struct {
	cfg              *APIServerConfiguration
	apiServerImage   string
	queryServerImage string
}

func (c *apiServerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.apiServerImage, err = components.GetReference(components.ComponentAPIServer, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
		c.queryServerImage, err = components.GetReference(components.ComponentQueryServer, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	} else {
		if operatorv1.IsFIPSModeEnabled(c.cfg.Installation.FIPSMode) {
			c.apiServerImage, err = components.GetReference(components.ComponentCalicoAPIServerFIPS, reg, path, prefix, is)
			if err != nil {
				errMsgs = append(errMsgs, err.Error())
			}
		} else {
			c.apiServerImage, err = components.GetReference(components.ComponentCalicoAPIServer, reg, path, prefix, is)
			if err != nil {
				errMsgs = append(errMsgs, err.Error())
			}
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *apiServerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func populateLists(create []client.Object, dels []client.Object, f func() (client.Object, client.Object)) ([]client.Object, []client.Object) {
	c, d := f()
	create = append(create, c)
	dels = append(dels, d)
	return create, dels
}

func (c *apiServerComponent) Objects() ([]client.Object, []client.Object) {
	// Start with all of the cluster-scoped resources that are used for both Calico and Calico Enterprise.
	// When switching between Calico / Enterprise, these objects are simply updated in-place.
	globalObjects := []client.Object{
		c.calicoCustomResourcesClusterRole(),
		c.calicoCustomResourcesClusterRoleBinding(),
	}

	// These objects are global, and have different names based on Calico or Calico Enterprise.
	// We need to delete the object for the variant that we're not currently installilng.
	objsToDelete := []client.Object{}
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.delegateAuthClusterRoleBinding)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.authClusterRole)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.authClusterRoleBinding)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.authReaderRoleBinding)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.webhookReaderClusterRole)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.webhookReaderClusterRoleBinding)

	// Namespaced objects that are common between Calico and Calico Enterprise. They don't need to be explicitly
	// deleted, since they will be garbage collected on namespace deletion.
	namespacedObjects := []client.Object{}
	// Add in image pull secrets.
	secrets := secret.CopyToNamespace(rmeta.APIServerNamespace(c.cfg.Installation.Variant), c.cfg.PullSecrets...)
	namespacedObjects = append(namespacedObjects, secret.ToRuntimeObjects(secrets...)...)

	namespacedObjects = append(namespacedObjects,
		c.apiServerServiceAccount(),
		c.apiServerDeployment(),
		c.apiServerService(),
		c.apiServerPodDisruptionBudget(),
	)

	// Add in certificates for API server TLS.
	if !c.cfg.TLSKeyPair.UseCertificateManagement() {
		globalObjects = append(globalObjects, c.apiServiceRegistration(c.cfg.TLSKeyPair.GetCertificatePEM()))
	} else {
		globalObjects = append(globalObjects, c.apiServiceRegistration(c.cfg.Installation.CertificateManagement.CACert))
	}

	// Global enterprise-only objects.
	globalEnterpriseObjects := []client.Object{
		CreateNamespace(rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise), c.cfg.Installation.KubernetesProvider, PSSPrivileged),
		c.tigeraCustomResourcesClusterRole(),
		c.tigeraCustomResourcesClusterRoleBinding(),
		c.tierGetterClusterRole(),
		c.kubeControllerMgrTierGetterClusterRoleBinding(),
		c.uisettingsgroupGetterClusterRole(),
		c.kubeControllerMgrUisettingsgroupGetterClusterRoleBinding(),
		c.tieredPolicyPassthruClusterRole(),
		c.tieredPolicyPassthruClusterRolebinding(),
		c.uiSettingsPassthruClusterRole(),
		c.uiSettingsPassthruClusterRolebinding(),
	}

	if !c.cfg.MultiTenant {
		// These resources are only installed in zero-tenant clusters. Multi-tenant clusters don't use the default
		// RBAC resources.
		globalEnterpriseObjects = append(globalEnterpriseObjects,
			c.tigeraUserClusterRole(),
			c.tigeraNetworkAdminClusterRole(),
		)
	}

	if c.cfg.ManagementCluster != nil {
		if c.cfg.MultiTenant {
			// Multi-tenant management cluster API servers need access to per-tenant CA secrets in order to sign
			// per-tenant guardian certificates when creating ManagedClusters.
			globalEnterpriseObjects = append(globalEnterpriseObjects, c.multiTenantSecretsRBAC()...)
			// Multi-tenant management cluster components impersonate the single-tenant canonical service account
			// in order to retrieve informations from the managed cluster. A cluster role will be created and each
			// component will create a role binding in the tenant namespace
			globalEnterpriseObjects = append(globalEnterpriseObjects, c.multiTenantManagedClusterAccessClusterRoles()...)
		} else {
			globalEnterpriseObjects = append(globalEnterpriseObjects, c.secretsRBAC()...)
		}
	} else {
		// If we're not a management cluster, the API server doesn't need permissions to access secrets.
		objsToDelete = append(objsToDelete, c.multiTenantSecretsRBAC()...)
		objsToDelete = append(objsToDelete, c.secretsRBAC()...)
		objsToDelete = append(objsToDelete, c.multiTenantManagedClusterAccessClusterRoles()...)
	}

	// Namespaced enterprise-only objects.
	namespacedEnterpriseObjects := []client.Object{
		c.auditPolicyConfigMap(),
	}
	if c.cfg.TrustedBundle != nil {
		namespacedEnterpriseObjects = append(namespacedEnterpriseObjects, c.cfg.TrustedBundle.ConfigMap(QueryserverNamespace))
	}

	// Global OSS-only objects.
	globalCalicoObjects := []client.Object{
		CreateNamespace(rmeta.APIServerNamespace(operatorv1.Calico), c.cfg.Installation.KubernetesProvider, PSSPrivileged),
	}

	// Compile the final arrays based on the variant.
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// Create any enterprise specific objects.
		globalObjects = append(globalObjects, globalEnterpriseObjects...)
		namespacedObjects = append(namespacedObjects, namespacedEnterpriseObjects...)

		// Explicitly delete any global OSS objects.
		// Namespaced objects will be handled by namespace deletion.
		objsToDelete = append(objsToDelete, globalCalicoObjects...)
	} else {
		// Create any Calico-only objects
		globalObjects = append(globalObjects, globalCalicoObjects...)

		// Add in a NetworkPolicy.
		namespacedObjects = append(namespacedObjects, c.networkPolicy())

		// Explicitly delete any global enterprise objects.
		// Namespaced objects will be handled by namespace deletion.
		objsToDelete = append(objsToDelete, globalEnterpriseObjects...)
	}

	objsToCreate := append(globalObjects, namespacedObjects...)
	return objsToCreate, objsToDelete
}

func (c *apiServerComponent) Ready() bool {
	return true
}

// For legacy reasons we use apiserver: true here instead of the k8s-app: name label,
// so we need to set it explicitly rather than use the common labeling logic.
func (c *apiServerComponent) deploymentSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"apiserver": "true",
		},
	}
}

// Determine names based on the configured variant
// It takes two name as parameters, enterpriseName and ossName, and returns name and nameToDelete.
func (c *apiServerComponent) resourceNameBasedOnVariant(enterpriseName, ossName string) (string, string) {
	var name, nameToDelete string
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = enterpriseName
		nameToDelete = ossName
	case operatorv1.Calico:
		name = ossName
		nameToDelete = enterpriseName
	}
	return name, nameToDelete
}

func (c *apiServerComponent) apiServerPodDisruptionBudget() *policyv1.PodDisruptionBudget {
	maxUnavailable := intstr.FromInt(1)
	name, _ := c.resourceNameBasedOnVariant("tigera-apiserver", "calico-apiserver")
	return &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector:       c.deploymentSelector(),
		},
	}
}

// apiServiceRegistration creates an API service that registers Tigera Secure APIs (and API server).
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) apiServiceRegistration(cert []byte) *apiregv1.APIService {
	// The APIService is the same for OSS and Enterprise, with the exception that
	// it points to a different Service and Namespace for each.
	s := &apiregv1.APIService{
		TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "v3.projectcalico.org",
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                "projectcalico.org",
			VersionPriority:      200,
			GroupPriorityMinimum: 1500,
			Service: &apiregv1.ServiceReference{
				Name:      ProjectCalicoAPIServerServiceName(c.cfg.Installation.Variant),
				Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			},
			Version:  "v3",
			CABundle: cert,
		},
	}
	return s
}

// delegateAuthClusterRoleBinding creates a clusterrolebinding that allows the API server to delegate
// authn/authz requests to main API server.
//
// Both Calico and Calico Enterprise, but different names.
func (c *apiServerComponent) delegateAuthClusterRoleBinding() (client.Object, client.Object) {
	// Determine names based on the configured variant.
	name, nameToDelete := c.resourceNameBasedOnVariant("tigera-apiserver-delegate-auth", "calico-apiserver-delegate-auth")
	return &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     "system:auth-delegator",
				APIGroup: "rbac.authorization.k8s.io",
			},
		}, &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameToDelete,
			},
		}
}

// authReaderRoleBinding creates a rolebinding that allows the API server to access the
// extension-apiserver-authentication configmap. That configmap contains the client CA file that
// the main API server was configured with.
//
// Both Calico and Calico Enterprise, but different names.
func (c *apiServerComponent) authReaderRoleBinding() (client.Object, client.Object) {
	name, nameToDelete := c.resourceNameBasedOnVariant("tigera-auth-reader", "calico-apiserver-auth-reader")
	return &rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "kube-system",
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "extension-apiserver-authentication-reader",
				APIGroup: "rbac.authorization.k8s.io",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
		}, &rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameToDelete,
				Namespace: "kube-system",
			},
		}
}

// apiServerServiceAccount creates the service account used by the API server.
//
// Both Calico and Calico Enterprise, but in different namespaces.
func (c *apiServerComponent) apiServerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
			Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
		},
	}
}

func allowTigeraAPIServerPolicy(cfg *APIServerConfiguration) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
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
		{
			// Pass to subsequent tiers for further enforcement
			Action: v3.Pass,
		},
	}...)

	// The ports Calico Enterprise API Server and Calico Enterprise Query Server are configured to listen on.
	ingressPorts := networkpolicy.Ports(443, APIServerPort, QueryServerPort, 10443)

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

// calicoCustomResourcesClusterRole creates a clusterrole that gives permissions to access backing CRDs and k8s networkpolicies.
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) calicoCustomResourcesClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Core Kubernetes resources.
			APIGroups: []string{""},
			Resources: []string{
				"nodes",
				"namespaces",
				"pods",
				"serviceaccounts",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			// Kubernetes network policy resources.
			APIGroups: []string{
				"networking.k8s.io",
			},
			Resources: []string{
				"networkpolicies",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			// Core Calico backing storage.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{
				"globalnetworkpolicies",
				"networkpolicies",
				"caliconodestatuses",
				"clusterinformations",
				"hostendpoints",
				"globalnetworksets",
				"networksets",
				"bgpconfigurations",
				"bgpfilters",
				"bgppeers",
				"felixconfigurations",
				"kubecontrollersconfigurations",
				"ippools",
				"ipreservations",
				"ipamblocks",
				"blockaffinities",
				"ipamconfigs",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
				"create",
				"update",
				"delete",
				"patch",
			},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-crds",
		},
		Rules: rules,
	}
}

// calicoCustomResourcesClusterRoleBinding creates a clusterrolebinding that applies calicoCustomResourcesClusterRole to
// the calico-apiserver service account.
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) calicoCustomResourcesClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-apiserver-access-calico-crds",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
				Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-crds",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// authClusterRole returns the cluster role to create, and one to delete, based on the variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) authClusterRole() (client.Object, client.Object) {
	name, nameToDelete := c.resourceNameBasedOnVariant("tigera-extension-apiserver-auth-access", "calico-extension-apiserver-auth-access")
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"configmaps",
			},
			Verbs: []string{
				"list",
				"watch",
			},
			ResourceNames: []string{
				"extension-apiserver-authentication",
			},
		},
		{
			APIGroups: []string{
				"rbac.authorization.k8s.io",
			},
			Resources: []string{
				"clusterroles",
				"clusterrolebindings",
				"roles",
				"rolebindings",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
	}

	if c.cfg.OpenShift {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.Privileged},
		})
	}

	return &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Rules: rules,
		}, &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameToDelete,
			},
		}
}

// multiTenantSecretsRBAC provides the tigera API server with the ability to read secrets on the cluster.
// This is needed in multi-tenant management clusters only, in order to read tenant secrets for signing managed cluster certificates.
func (c *apiServerComponent) multiTenantSecretsRBAC() []client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			Verbs:         []string{"get"},
			ResourceNames: []string{c.tunnelSecretName()},
		},
	}

	return []client.Object{
		// Return the cluster role itself.
		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: APIServerSecretsRBACName,
			},
			Rules: rules,
		},

		// And a binding to attach it to the API server.
		&rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: APIServerSecretsRBACName,
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     APIServerSecretsRBACName,
				APIGroup: "rbac.authorization.k8s.io",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
		},
	}
}

func (c *apiServerComponent) tunnelSecretName() string {
	secretName := VoltronTunnelSecretName
	if c.cfg.ManagementCluster != nil && c.cfg.ManagementCluster.Spec.TLS != nil && c.cfg.ManagementCluster.Spec.TLS.SecretName != "" {
		secretName = c.cfg.ManagementCluster.Spec.TLS.SecretName
	}
	return secretName
}

// secretsRBAC provides the tigera API server with the ability to read secrets from the API server's namespace.
func (c *apiServerComponent) secretsRBAC() []client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			Verbs:         []string{"get"},
			ResourceNames: []string{c.tunnelSecretName()},
		},
	}

	return []client.Object{
		// Return the role itself.
		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      APIServerSecretsRBACName,
				Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			},
			Rules: rules,
		},

		// And a binding to attach it to the API server.
		&rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      APIServerSecretsRBACName,
				Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     APIServerSecretsRBACName,
				APIGroup: "rbac.authorization.k8s.io",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
		},
	}
}

// authClusterRoleBinding returns a clusterrolebinding to create, and a clusterrolebinding to delete.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) authClusterRoleBinding() (client.Object, client.Object) {
	name, nameToDelete := c.resourceNameBasedOnVariant("tigera-extension-apiserver-auth-access", "calico-extension-apiserver-auth-access")
	return &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     name,
				APIGroup: "rbac.authorization.k8s.io",
			},
		}, &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameToDelete,
			},
		}
}

// webhookReaderClusterRole returns a ClusterRole to read MutatingWebhookConfigurations and ValidatingWebhookConfigurations and an
// equivalent one to delete based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) webhookReaderClusterRole() (client.Object, client.Object) {
	name, nameToDelete := c.resourceNameBasedOnVariant("tigera-webhook-reader", "calico-webhook-reader")
	return &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{
						"admissionregistration.k8s.io",
					},
					Resources: []string{
						"mutatingwebhookconfigurations", "validatingwebhookconfigurations",
					},
					Verbs: []string{
						"get",
						"list",
						"watch",
					},
				},
			},
		}, &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameToDelete,
			},
		}
}

// webhookReaderClusterRoleBinding binds the apiserver ServiceAccount to the webhook-reader. It also returns a version to
// delete, based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) webhookReaderClusterRoleBinding() (client.Object, client.Object) {
	name, nameToDelete := c.resourceNameBasedOnVariant("tigera-apiserver-webhook-reader", "calico-apiserver-webhook-reader")
	var refName string
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		refName = "tigera-webhook-reader"
	case operatorv1.Calico:
		refName = "calico-webhook-reader"
	}
	return &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     refName,
				APIGroup: "rbac.authorization.k8s.io",
			},
		}, &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: nameToDelete},
		}
}

// apiServerService creates a service backed by the API server and - for enterprise - query server.
//
// Both Calico and Calico Enterprise, different namespaces.
func (c *apiServerComponent) apiServerService() *corev1.Service {
	s := &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ProjectCalicoAPIServerServiceName(c.cfg.Installation.Variant),
			Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			Labels:    map[string]string{"k8s-app": QueryserverServiceName},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "apiserver",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(APIServerPort),
				},
			},
			Selector: map[string]string{
				"apiserver": "true",
			},
		},
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// Add port for queryserver if enterprise.
		s.Spec.Ports = append(s.Spec.Ports,
			corev1.ServicePort{
				Name:       "queryserver",
				Port:       QueryServerPort,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromInt(QueryServerPort),
			},
		)
	}
	return s
}

// apiServer creates a deployment containing the API and query servers.
func (c *apiServerComponent) apiServerDeployment() *appsv1.Deployment {
	name, _ := c.resourceNameBasedOnVariant("tigera-apiserver", "calico-apiserver")
	hostNetwork := c.hostNetwork()
	dnsPolicy := corev1.DNSClusterFirst
	if hostNetwork {
		// Adjust DNS policy so we can access in-cluster services.
		dnsPolicy = corev1.DNSClusterFirstWithHostNet
	}

	var initContainers []corev1.Container
	if c.cfg.TLSKeyPair.UseCertificateManagement() {
		// Use the same CSR init container name for both OSS and Enterprise.
		initContainer := c.cfg.TLSKeyPair.InitContainer(rmeta.APIServerNamespace(c.cfg.Installation.Variant))
		initContainer.Name = fmt.Sprintf("%s-%s", calicoAPIServerTLSSecretName, certificatemanagement.CSRInitContainerName)
		initContainers = append(initContainers, initContainer)
	}

	annotations := map[string]string{
		c.cfg.TLSKeyPair.HashAnnotationKey(): c.cfg.TLSKeyPair.HashAnnotationValue(),
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			Labels: map[string]string{
				"apiserver": "true",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Installation.ControlPlaneReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: c.deploymentSelector(),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
					Labels: map[string]string{
						"apiserver": "true",
					},
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					DNSPolicy:          dnsPolicy,
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					HostNetwork:        hostNetwork,
					ServiceAccountName: APIServerServiceAccountName(c.cfg.Installation.Variant),
					Tolerations:        c.tolerations(),
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					InitContainers:     initContainers,
					Containers: []corev1.Container{
						c.apiServerContainer(),
					},
					Volumes: c.apiServerVolumes(),
				},
			},
		},
	}

	if c.cfg.Installation.ControlPlaneReplicas != nil && *c.cfg.Installation.ControlPlaneReplicas > 1 {
		d.Spec.Template.Spec.Affinity = podaffinity.NewPodAntiAffinity(name, rmeta.APIServerNamespace(c.cfg.Installation.Variant))
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		d.Spec.Template.Spec.Containers = append(d.Spec.Template.Spec.Containers, c.queryServerContainer())

		if c.cfg.TrustedBundle != nil {
			trustedBundleHashAnnotations := c.cfg.TrustedBundle.HashAnnotations()
			for k, v := range trustedBundleHashAnnotations {
				d.Spec.Template.ObjectMeta.Annotations[k] = v
			}
		}
	}

	if overrides := c.cfg.APIServer.APIServerDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(d, overrides)
	}

	return d
}

func (c *apiServerComponent) hostNetwork() bool {
	hostNetwork := c.cfg.ForceHostNetwork
	if (c.cfg.Installation.KubernetesProvider.IsEKS() || c.cfg.Installation.KubernetesProvider.IsTKG()) &&
		c.cfg.Installation.CNI != nil &&
		c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		// Workaround the fact that webhooks don't work for non-host-networked pods
		// when in this networking mode on EKS or TKG, because the control plane nodes don't run
		// Calico.
		hostNetwork = true
	}
	return hostNetwork
}

// apiServerContainer creates the API server container.
func (c *apiServerComponent) apiServerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		c.cfg.TLSKeyPair.VolumeMount(c.SupportedOSType()),
	}
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{Name: auditLogsVolumeName, MountPath: "/var/log/calico/audit"},
			corev1.VolumeMount{Name: auditPolicyVolumeName, MountPath: "/etc/tigera/audit"},
		)
	}

	env := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
	}

	if c.cfg.MultiTenant {
		env = append(env, corev1.EnvVar{Name: "MULTI_TENANT_ENABLED", Value: "true"})
	}

	env = append(env, c.cfg.K8SServiceEndpoint.EnvVars(c.hostNetwork(), c.cfg.Installation.KubernetesProvider)...)

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	apiServer := corev1.Container{
		Name:            APIServerContainerName,
		Image:           c.apiServerImage,
		ImagePullPolicy: ImagePullPolicy(),
		Args:            c.startUpArgs(),
		Env:             env,
		VolumeMounts:    volumeMounts,
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/readyz",
					Port:   intstr.FromInt(APIServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			// We expect the readiness probe to contact kube-apiserver.
			// A longer period is chosen to minimize load.
			PeriodSeconds: 60,
		},
	}
	// In case of OpenShift, apiserver needs privileged access to write audit logs to host path volume.
	// Audit logs are owned by root on hosts so we need to be root user and group. Audit logs are supported only in Enterprise version.
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		apiServer.SecurityContext = securitycontext.NewRootContext(c.cfg.OpenShift)
	} else {
		apiServer.SecurityContext = securitycontext.NewNonRootContext()
	}

	return apiServer
}

func (c *apiServerComponent) startUpArgs() []string {
	args := []string{
		fmt.Sprintf("--secure-port=%d", APIServerPort),
		fmt.Sprintf("--tls-private-key-file=%s", c.cfg.TLSKeyPair.VolumeMountKeyFilePath()),
		fmt.Sprintf("--tls-cert-file=%s", c.cfg.TLSKeyPair.VolumeMountCertificateFilePath()),
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		args = append(args,
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		)
	}

	if c.cfg.ManagementCluster != nil {
		args = append(args, "--enable-managed-clusters-create-api=true")
		if c.cfg.ManagementCluster.Spec.Address != "" {
			args = append(args, fmt.Sprintf("--managementClusterAddr=%s", c.cfg.ManagementCluster.Spec.Address))
		}
		if c.cfg.ManagementCluster.Spec.TLS != nil && c.cfg.ManagementCluster.Spec.TLS.SecretName == ManagerTLSSecretName {
			args = append(args, "--managementClusterCAType=Public")
			args = append(args, fmt.Sprintf("--tunnelSecretName=%s", c.cfg.ManagementCluster.Spec.TLS.SecretName))
		}
	}

	return args
}

// queryServerContainer creates the query server container.
func (c *apiServerComponent) queryServerContainer() corev1.Container {
	env := []corev1.EnvVar{
		// Set queryserver logging to "info"
		{Name: "LOGLEVEL", Value: "info"},
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "LISTEN_ADDR", Value: fmt.Sprintf(":%d", QueryServerPort)},
		{Name: "TLS_CERT", Value: fmt.Sprintf("/%s/tls.crt", ProjectCalicoAPIServerTLSSecretName(c.cfg.Installation.Variant))},
		{Name: "TLS_KEY", Value: fmt.Sprintf("/%s/tls.key", ProjectCalicoAPIServerTLSSecretName(c.cfg.Installation.Variant))},
		{Name: "FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode)},
	}
	if c.cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "TRUSTED_BUNDLE_PATH", Value: c.cfg.TrustedBundle.MountPath()})
	}

	env = append(env, c.cfg.K8SServiceEndpoint.EnvVars(c.hostNetwork(), c.cfg.Installation.KubernetesProvider)...)

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	volumeMounts := []corev1.VolumeMount{
		c.cfg.TLSKeyPair.VolumeMount(c.SupportedOSType()),
	}
	if c.cfg.TrustedBundle != nil {
		volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)
	}

	container := corev1.Container{
		Name:            TigeraAPIServerQueryServerContainerName,
		Image:           c.queryServerImage,
		ImagePullPolicy: ImagePullPolicy(),
		Env:             env,
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt(QueryServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}
	return container
}

// apiServerVolumes creates the volumes used by the API server deployment.
func (c *apiServerComponent) apiServerVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		c.cfg.TLSKeyPair.Volume(),
	}
	hostPathType := corev1.HostPathDirectoryOrCreate
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		volumes = append(volumes,
			corev1.Volume{
				Name: auditLogsVolumeName,
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/log/calico/audit",
						Type: &hostPathType,
					},
				},
			},
			corev1.Volume{
				Name: auditPolicyVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: auditPolicyVolumeName},
						Items: []corev1.KeyToPath{
							{
								Key:  "config",
								Path: "policy.conf",
							},
						},
					},
				},
			},
		)

		if c.cfg.TrustedBundle != nil {
			volumes = append(volumes, c.cfg.TrustedBundle.Volume())
		}
	}

	return volumes
}

// tolerations creates the tolerations used by the API server deployment.
func (c *apiServerComponent) tolerations() []corev1.Toleration {
	if c.hostNetwork() {
		return rmeta.TolerateAll
	}
	return append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
}

// networkPolicy returns a NP to allow traffic to the API server. This prevents it from
// being cut off from the main API server. The enterprise equivalent is currently handled in manifests.
//
// Calico only.
func (c *apiServerComponent) networkPolicy() *netv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	p := intstr.FromInt(5443)
	return &netv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "allow-apiserver", Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant)},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: *c.deploymentSelector(),
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					Ports: []netv1.NetworkPolicyPort{
						{
							Protocol: &tcp,
							Port:     &p,
						},
					},
				},
			},
		},
	}
}

// tigeraCustomResourcesClusterRole creates a clusterrole that gives permissions to access backing CRDs
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraCustomResourcesClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Calico Enterprise backing storage.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{
				"stagedkubernetesnetworkpolicies",
				"stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tiers",
				"licensekeys",
				"alertexceptions",
				"globalalerts",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"globalreporttypes",
				"globalreports",
				"remoteclusterconfigurations",
				"managedclusters",
				"packetcaptures",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"deeppacketinspections",
				"deeppacketinspections/status",
				"uisettingsgroups",
				"uisettings",
				"externalnetworks",
				"egressgatewaypolicies",
				"securityeventwebhooks",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
				"create",
				"update",
				"delete",
				"patch",
			},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-crds",
		},
		Rules: rules,
	}
}

// tigeraCustomResourcesClusterRoleBinding creates a clusterrolebinding that applies tigeraCustomResourcesClusterRole to
// the tigera-apiserver service account.
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraCustomResourcesClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-access-tigera-crds",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName(c.cfg.Installation.Variant),
				Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-crds",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// tierGetterClusterRole creates a clusterrole that gives permissions to get tiers.
//
// Calico Enterprise only
func (c *apiServerComponent) tierGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tier-getter",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get"},
			},
		},
	}
}

// kubeControllerMgrTierGetterClusterRoleBinding creates a rolebinding that allows the k8s kube-controller manager to
// get tiers. In k8s 1.15+, cascading resource deletions (for instance pods for a replicaset) failed
// due to k8s kube-controller not having permissions to get tiers.
//
// Calico Enterprise only
func (c *apiServerComponent) kubeControllerMgrTierGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tier-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-tier-getter",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "system:kube-controller-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}
}

// uisettingsgroupGetterClusterRole creates a clusterrole that gives permissions to get uisettingsgroups.
//
// Calico Enterprise only
func (c *apiServerComponent) uisettingsgroupGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-uisettingsgroup-getter",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"uisettingsgroups",
				},
				Verbs: []string{"get"},
			},
		},
	}
}

// kubeControllerMgrUisettingsgroupGetterClusterRoleBinding creates a rolebinding that allows the k8s kube-controller
// manager to get uisettingsgroups.
//
// In k8s 1.15+, cascading resource deletions (for instance pods for a replicaset) failed due to k8s kube-controller
// not having permissions to get tiers. UISettings and UISettingsGroups RBAC works in a similar way to tiered policy
// and so we need similar RBAC for UISettingsGroups.
//
// Calico Enterprise only
func (c *apiServerComponent) kubeControllerMgrUisettingsgroupGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-uisettingsgroup-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-uisettingsgroup-getter",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "system:kube-controller-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}
}

// tigeraUserClusterRole returns a cluster role for a default Calico Enterprise user.
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraUserClusterRole() *rbacv1.ClusterRole {
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
			// irrespective of the Calico RBAC scheme (see the ClusterRole "tigera-tiered-policy-passthrough" for
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
				"policyrecommendationscopes",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
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
		// Access to policies in all tiers
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
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
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		// A POST to AuthorizationReviews lets the UI determine what features it can enable.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authorizationreviews"},
			Verbs:     []string{"create"},
		},
		// User can:
		// - read UISettings in the cluster-settings group
		// - read and write UISettings in the user-settings group
		// Default settings group and settings are created in manager.go.
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups"},
			Verbs:         []string{"get"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"get", "list", "watch"},
			ResourceNames: []string{"cluster-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"user-settings"},
		},
		// Allow the user to read applicationlayers to detect if WAF is enabled/disabled.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get"},
		},
		// Allow the user to read services to view WAF configuration.
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to read felixconfigurations to detect if wireguard and/or other features are enabled.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		// Allow the user to only view securityeventwebhooks.
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list"},
		},
	}

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.cfg.ManagementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics.
		// Access to log into Kibana for oidc users.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "recommendations",
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
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// Full access to all network policies
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "tigera-tiered-policy-passthrough" for
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
				"packetcaptures",
				"policyrecommendationscopes",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		// Additional "list" requests that the Tigera Secure manager needs
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"watch", "list"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
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
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// A POST to AuthorizationReviews lets the UI determine what features it can enable.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authorizationreviews"},
			Verbs:     []string{"create"},
		},
		// User can:
		// - read and write UISettings in the cluster-settings group, and rename the group
		// - read and write UISettings in the user-settings group, and rename the group
		// Default settings group and settings are created in manager.go.
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups"},
			Verbs:         []string{"get", "patch", "update"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		// Allow the user to read and write applicationlayers to enable/disable WAF.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get", "update", "patch", "create", "delete"},
		},
		// Allow the user to read services to view WAF configuration.
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		// Allow the user to read felixconfigurations to detect if wireguard and/or other features are enabled.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		// Allow the user to perform CRUD operations on securityeventwebhooks.
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list", "update", "patch", "create", "delete"},
		},
		// Allow the user to create secrets.
		{
			APIGroups: []string{""},
			Resources: []string{
				"secrets",
			},
			Verbs: []string{"create"},
		},
		// Allow the user to patch webhooks-secret secret.
		{
			APIGroups: []string{""},
			Resources: []string{
				"secrets",
			},
			ResourceNames: []string{
				"webhooks-secret",
			},
			Verbs: []string{"patch"},
		},
	}

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.cfg.ManagementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics.
		// Elasticsearch superuser access once logged into Kibana.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "elasticsearch_superuser", "recommendations",
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

// tieredPolicyPassthruClusterRole creates a clusterrole that is used to control the RBAC
// mechanism for Tigera Secure tiered policy.
//
// Calico Enterprise only
func (c *apiServerComponent) tieredPolicyPassthruClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tiered-policy-passthrough",
		},
		// If tiered policy is enabled we allow all authenticated users to access the main tier resource, instead
		// restricting access using the tier.xxx resource type. Kubernetes NetworkPolicy and the
		// StagedKubernetesNetworkPolicy are handled using normal (non-tiered) RBAC.
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"networkpolicies", "globalnetworkpolicies", "stagednetworkpolicies", "stagedglobalnetworkpolicies"},
				Verbs:     []string{"*"},
			},
		},
	}
}

// tieredPolicyPassthruClusterRolebinding creates a clusterrolebinding that applies tieredPolicyPassthruClusterRole to all users.
//
// Calico Enterprise only
func (c *apiServerComponent) tieredPolicyPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tiered-policy-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-tiered-policy-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// uiSettingsPassthruClusterRole creates a clusterrole that is used to control the RBAC mechanism for Tigera UI Settings.
// RBAC for these is handled within the Tigera API Server which checks uisettingsgroups/data permissions for the user.
//
// Calico Enterprise only
func (c *apiServerComponent) uiSettingsPassthruClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-uisettings-passthrough",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettings"},
				Verbs:     []string{"*"},
			},
		},
	}
}

// uiSettingsPassthruClusterRolebinding creates a clusterrolebinding that applies uiSettingsPassthruClusterRole to all
// users.
//
// Calico Enterprise only.
func (c *apiServerComponent) uiSettingsPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-uisettings-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-uisettings-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// auditPolicyConfigMap returns a configmap with contents to configure audit logging for
// projectcalico.org/v3 APIs.
//
// Calico Enterprise only
func (c *apiServerComponent) auditPolicyConfigMap() *corev1.ConfigMap {
	const defaultAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  omitStages:
  - RequestReceived
  verbs:
  - create
  - patch
  - update
  - delete
  resources:
  - group: projectcalico.org
    resources:
    - globalnetworkpolicies
    - networkpolicies
    - stagedglobalnetworkpolicies
    - stagednetworkpolicies
    - stagedkubernetesnetworkpolicies
    - globalnetworksets
    - networksets
    - tiers
    - hostendpoints`

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			// This object is for Enterprise only, so pass it explicitly.
			Namespace: rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise),
			Name:      auditPolicyVolumeName,
		},
		Data: map[string]string{
			"config": defaultAuditPolicy,
		},
	}
}

func (c *apiServerComponent) multiTenantManagedClusterAccessClusterRoles() []client.Object {
	var objects []client.Object
	objects = append(objects, &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: MultiTenantManagedClustersAccessClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs: []string{
					// The Authentication Proxy in Voltron checks if Enterprise Components (using impersonation headers for
					// the service in the canonical namespace) can get a managed clusters before sending the request down the tunnel.
					// This ClusterRole will be assigned to each component using a RoleBinding in the canonical or tenant namespace.
					"get",
				},
			},
		},
	})

	return objects
}
