// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"net/url"
	"strings"

	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

type ContainerName string

const (
	APIServerPort       = 5443
	APIServerPortName   = "apiserver"
	APIServerPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "apiserver-access"

	// ComponentNameAPIServer is the extension key under which a variant registers
	// its API server modifier and image override.
	ComponentNameAPIServer = "apiserver"
)

const (
	APIServerResourceName  = "apiserver"
	APIServerNamespace     = common.CalicoNamespace
	QueryServerPort        = 8080
	QueryServerPortName    = "queryserver"
	QueryserverNamespace   = "calico-system"
	QueryserverServiceName = "calico-api"

	// Use the same API server container name for both OSS and Enterprise.
	APIServerName                                         = "calico-apiserver"
	APIServerContainerName                  ContainerName = "calico-apiserver"
	TigeraAPIServerQueryServerContainerName ContainerName = "tigera-queryserver"

	CalicoAPIServerTLSSecretName = "calico-apiserver-certs"
	APIServerServiceName         = "calico-api"
	APIServerServiceAccountName  = "calico-apiserver"

	APIServerSecretsRBACName                                      = "calico-extension-apiserver-secrets-access"
	MultiTenantManagedClustersAccessClusterRoleName               = "calico-managed-cluster-access"
	ManagedClustersWatchClusterRoleName                           = "calico-managed-cluster-watch"
	L7AdmissionControllerContainerName              ContainerName = "calico-l7-admission-controller"
	L7AdmissionControllerPort                                     = 6443
	L7AdmissionControllerPortName                                 = "l7admctrl"
)

var (
	TigeraAPIServerEntityRule = v3.EntityRule{
		Services: &v3.ServiceMatch{
			Namespace: QueryserverNamespace,
			Name:      QueryserverServiceName,
		},
	}

	// allVerbs is a list of all verbs that are supported by the API server, used
	// for tiered policy passthrough.
	allVerbs = []string{
		"get",
		"list",
		"watch",
		"create",
		"update",
		"patch",
		"delete",
		"deletecollection",
	}
)

func APIServer(cfg *APIServerConfiguration) (Component, error) {
	return &apiServerComponent{
		cfg: cfg,
	}, nil
}

func APIServerPolicy(cfg *APIServerConfiguration) Component {
	return NewPassthrough(
		[]client.Object{calicoSystemAPIServerPolicy(cfg)},
		[]client.Object{
			// allow-tigera Tier was renamed to calico-system
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("apiserver-access", APIServerNamespace),
		},
	)
}

// APIServerConfiguration contains all the config information needed to render the component.
type APIServerConfiguration struct {
	K8SServiceEndpoint           k8sapi.ServiceEndpoint
	K8SServiceEndpointPodNetwork k8sapi.ServiceEndpoint
	Installation                 *operatorv1.InstallationSpec
	APIServer                    *operatorv1.APIServerSpec
	ForceHostNetwork             bool
	ApplicationLayer             *operatorv1.ApplicationLayer
	ManagementCluster            *operatorv1.ManagementCluster
	ManagementClusterConnection  *operatorv1.ManagementClusterConnection
	TLSKeyPair                   certificatemanagement.KeyPairInterface
	PullSecrets                  []*corev1.Secret
	OpenShift                    bool
	TrustedBundle                certificatemanagement.TrustedBundle
	MultiTenant                  bool
	KeyValidatorConfig           authentication.KeyValidatorConfig
	KubernetesVersion            *common.VersionInfo
	ClusterDomain                string

	// Whether or not we should run the aggregation API server for projectcalico.org/v3 APIs
	// as part of this component.
	RequiresAggregationServer bool

	// Whether or not the API server deployment must run a query server alongside the API
	// server. The deployment (and its supporting objects) are rendered when either an
	// aggregation API server or a query server is required. The query server itself, and
	// the rest of its supporting configuration, is layered on by the variant's modifier.
	RequiresQueryServer bool

	// When certificate management is enabled, we need a separate init container to create a cert, running
	// with the same permissions as query server.
	QueryServerTLSKeyPairCertificateManagementOnly certificatemanagement.KeyPairInterface
}

type apiServerComponent struct {
	cfg                             *APIServerConfiguration
	calicoImage                     string
	l7AdmissionControllerEnvoyImage string
	dikastesImage                   string
}

// APIServerExtensionContext carries the API server's render configuration and resolved
// image to a variant modifier. The modifier uses these to build variant-specific objects
// and to layer additional containers, volumes, and configuration onto the rendered
// deployment.
type APIServerExtensionContext struct {
	Config      *APIServerConfiguration
	CalicoImage string
}

// ModifierKey implements render.Extensible: the API server's variant-specific objects are
// applied by the modifier registered under this key.
func (c *apiServerComponent) ModifierKey() string { return ComponentNameAPIServer }

// ExtensionContext implements render.ExtensionContextProvider, handing the modifier the
// config and resolved image it needs.
func (c *apiServerComponent) ExtensionContext() any {
	return APIServerExtensionContext{Config: c.cfg, CalicoImage: c.calicoImage}
}

func (c *apiServerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	if c.cfg.RequiresAggregationServer || c.cfg.RequiresQueryServer {
		c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if c.cfg.IsSidecarInjectionEnabled() {
		c.l7AdmissionControllerEnvoyImage, err = components.GetReference(components.ComponentEnvoyProxy, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
		c.dikastesImage, err = components.GetReference(components.ComponentDikastes, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *apiServerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *apiServerComponent) Objects() ([]client.Object, []client.Object) {
	// Cluster-scoped resources used by the API server, independent of variant. Any
	// variant-specific objects are layered on by the variant's modifier.
	globalObjects := []client.Object{
		c.calicoCustomResourcesClusterRole(),
		c.calicoCustomResourcesClusterRoleBinding(),
		c.tierGetterClusterRole(),
		c.kubeControllerMgrTierGetterClusterRoleBinding(),
		c.delegateAuthClusterRoleBinding(),
		c.webhookReaderClusterRole(),
		c.webhookReaderClusterRoleBinding(),
	}

	objsToDelete := []client.Object{}
	namespacedObjects := []client.Object{}

	// Add in image pull secrets.
	secrets := secret.CopyToNamespace(APIServerNamespace, c.cfg.PullSecrets...)
	namespacedObjects = append(namespacedObjects, secret.ToRuntimeObjects(secrets...)...)

	// The deployment and its supporting objects are needed when running the aggregation API server
	// or when a query server runs alongside it (the query server is added by a variant modifier).
	if c.cfg.RequiresAggregationServer || c.cfg.RequiresQueryServer {
		namespacedObjects = append(namespacedObjects,
			c.apiServerServiceAccount(),
			c.apiServerDeployment(),
			c.apiServerService(),
			c.apiServerPodDisruptionBudget(),
		)
	} else {
		objsToDelete = append(objsToDelete,
			&corev1.ServiceAccount{TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: APIServerServiceAccountName, Namespace: APIServerNamespace}},
			&appsv1.Deployment{TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}, ObjectMeta: metav1.ObjectMeta{Name: APIServerName, Namespace: APIServerNamespace}},
			&corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: APIServerServiceName, Namespace: APIServerNamespace}},
			&policyv1.PodDisruptionBudget{TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}, ObjectMeta: metav1.ObjectMeta{Name: APIServerName, Namespace: APIServerNamespace}},
		)
	}

	// These are objects that only need to exist when we are running an aggregation API server to
	// serve projectcalico.org/v3 APIs. If using CRDs for this API group, we can remove these objects.
	aggregationAPIServerObjects := []client.Object{
		c.calicoPolicyPassthruClusterRole(),
		c.calicoPolicyPassthruClusterRolebinding(),
		c.authClusterRole(),
		c.authClusterRoleBinding(),
		c.authReaderRoleBinding(),
	}

	// Add in certificates for API server TLS.
	if !c.cfg.TLSKeyPair.UseCertificateManagement() {
		aggregationAPIServerObjects = append(aggregationAPIServerObjects, c.apiServiceRegistration(c.cfg.TLSKeyPair.GetCertificatePEM()))
	} else {
		aggregationAPIServerObjects = append(aggregationAPIServerObjects, c.apiServiceRegistration(c.cfg.Installation.CertificateManagement.CACert))
	}

	// The sidecar mutating webhook is driven by ApplicationLayer configuration, not by variant.
	if c.cfg.IsSidecarInjectionEnabled() {
		namespacedObjects = append(namespacedObjects, c.sidecarMutatingWebhookConfig())
	} else {
		objsToDelete = append(objsToDelete, &admregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: common.SidecarMutatingWebhookConfigName}})
	}

	// Clean up deprecated k8s NetworkPolicy, regardless of variant,
	// avoiding leftovers in the case of switching between variants.
	objsToDelete = append(objsToDelete, &netv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "allow-apiserver", Namespace: APIServerNamespace},
	})

	// Add or remove the aggregation API server objects as needed.
	if c.cfg.RequiresAggregationServer {
		// Include the aggregation API server objects.
		globalObjects = append(globalObjects, aggregationAPIServerObjects...)
	} else {
		// If we're not running an aggregation API server, we need to delete the objects that are only needed for it.
		objsToDelete = append(objsToDelete, aggregationAPIServerObjects...)
	}

	// Explicitly delete any renamed/deprecated objects.
	objsToDelete = append(objsToDelete, c.getDeprecatedResources()...)
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

func (c *apiServerComponent) apiServerPodDisruptionBudget() *policyv1.PodDisruptionBudget {
	maxUnavailable := intstr.FromInt(1)
	return &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerName,
			Namespace: APIServerNamespace,
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
				Name:      APIServerServiceName,
				Namespace: APIServerNamespace,
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
func (c *apiServerComponent) delegateAuthClusterRoleBinding() client.Object {
	// Determine names based on the configured variant.
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-apiserver-delegate-auth",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "system:auth-delegator",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// authReaderRoleBinding creates a rolebinding that allows the API server to access the
// extension-apiserver-authentication configmap. That configmap contains the client CA file that
// the main API server was configured with.
//
// Both Calico and Calico Enterprise, but different names.
func (c *apiServerComponent) authReaderRoleBinding() client.Object {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-apiserver-auth-reader",
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
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
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
			Name:      APIServerServiceAccountName,
			Namespace: APIServerNamespace,
		},
	}
}

func calicoSystemAPIServerPolicy(cfg *APIServerConfiguration) *v3.NetworkPolicy {
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
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: DexEntityRule,
		},
		{
			// Allow queryserver to reach Linseed for policy activity enrichment.
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().LinseedEntityRule(),
		},
	}...)

	if cfg.KeyValidatorConfig != nil {
		if parsedURL, err := url.Parse(cfg.KeyValidatorConfig.Issuer()); err == nil {
			oidcEgressRule := networkpolicy.GetOIDCEgressRule(parsedURL)
			egressRules = append(egressRules, oidcEgressRule)
		}
	}

	if r, err := cfg.K8SServiceEndpoint.DestinationEntityRule(); r != nil && err == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: *r,
		})
	}

	// add pass after all egress rules
	egressRules = append(egressRules, v3.Rule{
		// Pass to subsequent tiers for further enforcement
		Action: v3.Pass,
	})

	apiServerContainerPort := GetContainerPort(cfg, APIServerContainerName).ContainerPort
	queryServerContainerPort := GetContainerPort(cfg, TigeraAPIServerQueryServerContainerName).ContainerPort
	l7AdmCtrlContainerPort := GetContainerPort(cfg, L7AdmissionControllerContainerName).ContainerPort

	// The ports Calico Enterprise API Server and Calico Enterprise Query Server are configured to listen on.
	ingressPorts := networkpolicy.Ports(443, uint16(apiServerContainerPort), uint16(queryServerContainerPort), 10443)
	if cfg.IsSidecarInjectionEnabled() {
		ingressPorts = append(ingressPorts, numorstring.Port{MinPort: uint16(l7AdmCtrlContainerPort), MaxPort: uint16(l7AdmCtrlContainerPort)})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerPolicyName,
			Namespace: APIServerNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(APIServerName),
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
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies"},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			// Kubernetes cluster network policy resources.
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			// Core Calico backing storage.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"globalnetworkpolicies",
				"networkpolicies",
				"stagedkubernetesnetworkpolicies",
				"stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
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
				"tiers",
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
	//nolint:staticcheck // Ignore QF1001 could apply De Morgan's law
	if c.cfg.KubernetesVersion == nil || !(c.cfg.KubernetesVersion != nil && c.cfg.KubernetesVersion.Major < 2 && c.cfg.KubernetesVersion.Minor < 30) {
		// If the kubernetes version is higher than 1.30, we add extra RBAC permissions to allow establishing watches.
		// https://v1-30.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
		rules = append(rules, rbacv1.PolicyRule{
			// Kubernetes validating admission policy resources.
			APIGroups: []string{"admissionregistration.k8s.io"},
			Resources: []string{
				"validatingadmissionpolicies",
				"validatingadmissionpolicybindings",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		})
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
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
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
func (c *apiServerComponent) authClusterRole() client.Object {
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
		},
			// Starting with OCP 4.20, these permissions are required at startup when it sets up watches.
			rbacv1.PolicyRule{
				APIGroups: []string{"config.openshift.io"},
				Resources: []string{"infrastructures"},
				Verbs:     []string{"get", "list", "watch"},
			},
		)
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-extension-apiserver-auth-access",
		},
		Rules: rules,
	}
}

// authClusterRoleBinding returns a clusterrolebinding to create, and a clusterrolebinding to delete.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) authClusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-extension-apiserver-auth-access",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-extension-apiserver-auth-access",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// webhookReaderClusterRole returns a ClusterRole to read MutatingWebhookConfigurations and ValidatingWebhookConfigurations and an
// equivalent one to delete based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) webhookReaderClusterRole() client.Object {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-webhook-reader",
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
	}
}

// webhookReaderClusterRoleBinding binds the apiserver ServiceAccount to the webhook-reader. It also returns a version to
// delete, based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) webhookReaderClusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      APIServerServiceAccountName,
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-webhook-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func GetContainerPort(cfg *APIServerConfiguration, containerName ContainerName) *operatorv1.APIServerDeploymentContainerPort {
	// Try to get the override port
	if cfg != nil &&
		cfg.APIServer != nil &&
		cfg.APIServer.APIServerDeployment != nil &&
		cfg.APIServer.APIServerDeployment.Spec != nil &&
		cfg.APIServer.APIServerDeployment.Spec.Template != nil &&
		cfg.APIServer.APIServerDeployment.Spec.Template.Spec != nil {

		containers := cfg.APIServer.APIServerDeployment.Spec.Template.Spec.Containers
		if len(containers) > 0 {
			for _, container := range containers {
				if container.Name == string(containerName) && len(container.Ports) > 0 {
					return &operatorv1.APIServerDeploymentContainerPort{
						ContainerPort: container.Ports[0].ContainerPort,
						Name:          container.Ports[0].Name,
					}
				}
			}
		}
	}

	// If no override port is found, return the default port
	switch containerName {
	case APIServerContainerName:
		return &operatorv1.APIServerDeploymentContainerPort{ContainerPort: APIServerPort}
	case TigeraAPIServerQueryServerContainerName:
		return &operatorv1.APIServerDeploymentContainerPort{ContainerPort: QueryServerPort}
	case L7AdmissionControllerContainerName:
		return &operatorv1.APIServerDeploymentContainerPort{ContainerPort: L7AdmissionControllerPort}
	}

	return nil
}

// apiServerService creates a service backed by the API server. A variant modifier may add
// additional ports (e.g. the query server port).
func (c *apiServerComponent) apiServerService() *corev1.Service {
	apiServerTargetPort := GetContainerPort(c.cfg, APIServerContainerName)
	l7AdmissionControllerTargetPort := GetContainerPort(c.cfg, L7AdmissionControllerContainerName)

	s := &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerServiceName,
			Namespace: APIServerNamespace,
			Labels:    map[string]string{"k8s-app": QueryserverServiceName},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       APIServerPortName,
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(apiServerTargetPort.ContainerPort),
				},
			},
			Selector: map[string]string{
				"apiserver": "true",
			},
		},
	}

	if c.cfg.IsSidecarInjectionEnabled() {
		s.Spec.Ports = append(s.Spec.Ports,
			corev1.ServicePort{
				Name:       L7AdmissionControllerPortName,
				Port:       L7AdmissionControllerPort,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromInt32(l7AdmissionControllerTargetPort.ContainerPort),
			},
		)
	}

	return s
}

// apiServer creates a deployment containing the API and query servers.
func (c *apiServerComponent) apiServerDeployment() *appsv1.Deployment {
	hostNetwork := c.hostNetwork()
	dnsPolicy := corev1.DNSClusterFirst
	deploymentStrategyType := appsv1.RollingUpdateDeploymentStrategyType
	if hostNetwork {
		// Adjust DNS policy so we can access in-cluster services.
		dnsPolicy = corev1.DNSClusterFirstWithHostNet
		deploymentStrategyType = appsv1.RecreateDeploymentStrategyType
	}

	annotations := map[string]string{
		c.cfg.TLSKeyPair.HashAnnotationKey(): c.cfg.TLSKeyPair.HashAnnotationValue(),
	}

	var initContainers []corev1.Container
	if c.cfg.TLSKeyPair.UseCertificateManagement() {
		if c.cfg.RequiresAggregationServer {
			// Only include the API server init container if we're running the aggregation API server!
			initContainerAPIServer := c.cfg.TLSKeyPair.InitContainer(APIServerNamespace, c.apiServerContainer().SecurityContext)
			initContainerAPIServer.Name = fmt.Sprintf("%s-%s", CalicoAPIServerTLSSecretName, certificatemanagement.CSRInitContainerName)
			initContainers = append(initContainers, initContainerAPIServer)
		}

		initContainerQueryServer := c.cfg.QueryServerTLSKeyPairCertificateManagementOnly.InitContainer(APIServerNamespace, securitycontext.NewNonRootContext())
		annotations[c.cfg.QueryServerTLSKeyPairCertificateManagementOnly.HashAnnotationKey()] = c.cfg.QueryServerTLSKeyPairCertificateManagementOnly.HashAnnotationValue()
		initContainers = append(initContainers, initContainerQueryServer)
	}

	// Determine which containers to run. A variant modifier may add additional
	// containers (e.g. the query server).
	containers := []corev1.Container{}
	if c.cfg.RequiresAggregationServer {
		containers = append(containers, c.apiServerContainer())
	}
	if c.cfg.IsSidecarInjectionEnabled() {
		containers = append(containers, c.l7AdmissionControllerContainer())
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      APIServerName,
			Namespace: APIServerNamespace,
			Labels: map[string]string{
				"apiserver": "true",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Installation.ControlPlaneReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: deploymentStrategyType,
			},
			Selector: c.deploymentSelector(),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIServerName,
					Namespace: APIServerNamespace,
					Labels: map[string]string{
						"apiserver": "true",
					},
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					DNSPolicy:          dnsPolicy,
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					HostNetwork:        hostNetwork,
					ServiceAccountName: APIServerServiceAccountName,
					Tolerations:        c.tolerations(),
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					InitContainers:     initContainers,
					Containers:         containers,
					Volumes:            c.apiServerVolumes(),
				},
			},
		},
	}

	if c.cfg.Installation.ControlPlaneReplicas != nil && *c.cfg.Installation.ControlPlaneReplicas > 1 {
		d.Spec.Template.Spec.Affinity = podaffinity.NewPodAntiAffinity(APIServerName, []string{APIServerNamespace, "tigera-system", "calico-apiserver"})
	}

	if overrides := c.cfg.APIServer.APIServerDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(d, overrides)
	}

	return d
}

// apiServer creates a MutatingWebhookConfiguration for sidecars.
func (c *apiServerComponent) sidecarMutatingWebhookConfig() *admregv1.MutatingWebhookConfiguration {
	var cacert []byte
	svcPort := GetContainerPort(c.cfg, L7AdmissionControllerContainerName).ContainerPort

	svcpath := "/sidecar-webhook"
	svcref := admregv1.ServiceReference{
		Name:      QueryserverServiceName,
		Namespace: QueryserverNamespace,
		Path:      &svcpath,
		Port:      &svcPort,
	}
	failpol := admregv1.Fail
	labelsel := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"applicationlayer.projectcalico.org/sidecar": "true",
		},
	}
	rules := []admregv1.RuleWithOperations{
		{
			Rule: admregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
			},
			Operations: []admregv1.OperationType{admregv1.Create},
		},
	}
	sidefx := admregv1.SideEffectClassNone
	if !c.cfg.TLSKeyPair.UseCertificateManagement() {
		cacert = c.cfg.TLSKeyPair.GetIssuer().GetCertificatePEM()
	} else {
		cacert = c.cfg.Installation.CertificateManagement.CACert
	}
	mwc := admregv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "MutatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{Name: common.SidecarMutatingWebhookConfigName},
		Webhooks: []admregv1.MutatingWebhook{
			{
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admregv1.WebhookClientConfig{
					Service:  &svcref,
					CABundle: cacert,
				},
				Name:           "sidecar.projectcalico.org",
				FailurePolicy:  &failpol,
				ObjectSelector: &labelsel,
				Rules:          rules,
				SideEffects:    &sidefx,
			},
		},
	}

	return &mwc
}

func (c *apiServerComponent) hostNetwork() bool {
	return HostNetwork(c.cfg)
}

// HostNetwork reports whether the API server deployment runs on the host network,
// accounting for both the forced setting and the provider-driven requirement.
func HostNetwork(cfg *APIServerConfiguration) bool {
	if cfg.ForceHostNetwork {
		return true
	}
	return HostNetworkRequired(cfg.Installation)
}

func HostNetworkRequired(installation *operatorv1.InstallationSpec) bool {
	if (installation.KubernetesProvider.IsEKS() || installation.KubernetesProvider.IsTKG()) &&
		installation.CNI != nil &&
		installation.CNI.Type == operatorv1.PluginCalico {
		// Workaround the fact that webhooks don't work for non-host-networked pods
		// when in this networking mode on EKS or TKG, because the control plane nodes don't run
		// Calico.
		return true
	}
	return false
}

// apiServerContainer creates the API server container.
func (c *apiServerComponent) apiServerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		c.cfg.TLSKeyPair.VolumeMount(c.SupportedOSType()),
	}

	env := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
	}

	if c.cfg.MultiTenant {
		env = append(env, corev1.EnvVar{Name: "MULTI_TENANT_ENABLED", Value: "true"})
	}

	if c.hostNetwork() {
		env = append(env, c.cfg.K8SServiceEndpoint.EnvVars()...)
	} else {
		env = append(env, c.cfg.K8SServiceEndpointPodNetwork.EnvVars()...)
	}

	// set Log_LEVEL for apiserver container
	if logging := c.cfg.APIServer.Logging; logging != nil &&
		logging.APIServerLogging != nil && logging.APIServerLogging.LogSeverity != nil {
		env = append(env,
			corev1.EnvVar{Name: "LOG_LEVEL", Value: strings.ToLower(string(*logging.APIServerLogging.LogSeverity))})
	} else {
		// set default LOG_LEVEL to info when not set by the user
		env = append(env, corev1.EnvVar{Name: "LOG_LEVEL", Value: "info"})
	}

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	apiServerTargetPort := GetContainerPort(c.cfg, APIServerContainerName).ContainerPort

	apiServer := corev1.Container{
		Name:         string(APIServerContainerName),
		Image:        c.calicoImage,
		Command:      []string{components.CalicoBinaryPath, "component", "apiserver"},
		Args:         c.startUpArgs(),
		Env:          env,
		VolumeMounts: volumeMounts,
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/readyz",
					Port:   intstr.FromInt32(apiServerTargetPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			// We expect the readiness probe to contact kube-apiserver.
			// A longer period is chosen to minimize load.
			PeriodSeconds: 60,
		},
	}
	apiServer.SecurityContext = securitycontext.NewNonRootContext()

	return apiServer
}

func (c *apiServerComponent) startUpArgs() []string {
	apiServerTargetPort := GetContainerPort(c.cfg, APIServerContainerName).ContainerPort

	args := []string{
		fmt.Sprintf("--secure-port=%d", apiServerTargetPort),
		fmt.Sprintf("--tls-private-key-file=%s", c.cfg.TLSKeyPair.VolumeMountKeyFilePath()),
		fmt.Sprintf("--tls-cert-file=%s", c.cfg.TLSKeyPair.VolumeMountCertificateFilePath()),
	}

	if c.cfg.ManagementCluster != nil {
		args = append(args, "--enable-managed-clusters-create-api=true")
		if c.cfg.ManagementCluster.Spec.Address != "" {
			args = append(args, fmt.Sprintf("--managementClusterAddr=%s", c.cfg.ManagementCluster.Spec.Address))
		}
		if c.cfg.ManagementCluster.Spec.TLS != nil && c.cfg.ManagementCluster.Spec.TLS.SecretName != "" {
			if c.cfg.ManagementCluster.Spec.TLS.SecretName == ManagerTLSSecretName {
				args = append(args, "--managementClusterCAType=Public")
			}
			args = append(args, fmt.Sprintf("--tunnelSecretName=%s", c.cfg.ManagementCluster.Spec.TLS.SecretName))
		}
	}
	if c.cfg.KubernetesVersion != nil && c.cfg.KubernetesVersion.Major < 2 && c.cfg.KubernetesVersion.Minor < 30 {
		// Disable this API as it is not available by default. If we don't, the server fails to start, due to trying to
		// establish watches for unavailable APIs.
		args = append(args, "--enable-validating-admission-policy=false")
	}
	return args
}

// apiServerVolumes creates the volumes used by the API server deployment.
func (c *apiServerComponent) apiServerVolumes() []corev1.Volume {
	volumes := []corev1.Volume{
		c.cfg.TLSKeyPair.Volume(),
	}
	if c.cfg.QueryServerTLSKeyPairCertificateManagementOnly != nil {
		volumes = append(volumes, c.cfg.QueryServerTLSKeyPairCertificateManagementOnly.Volume())
	}

	if c.cfg.ManagementClusterConnection != nil {
		// Optional: the Secret is delivered over the Guardian tunnel, which can't be
		// established until calico-apiserver is Ready.
		volumes = append(volumes, corev1.Volume{
			Name: LinseedTokenVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf(LinseedTokenSecret, "calico-apiserver"),
					Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					Optional:   ptr.To(true),
				},
			},
		})
	}

	return volumes
}

// tolerations creates the tolerations used by the API server deployment.
func (c *apiServerComponent) tolerations() []corev1.Toleration {
	if c.hostNetwork() {
		return rmeta.TolerateBootstrap
	}
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	return tolerations
}

// tierGetterClusterRole creates a clusterrole that gives permissions to get tiers.
func (c *apiServerComponent) tierGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-tier-getter",
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
func (c *apiServerComponent) kubeControllerMgrTierGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-tier-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-tier-getter",
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

// calicoPolicyPassthruClusterRole creates a clusterrole that is used to control the RBAC
// mechanism for Calico tiered policy.
func (c *apiServerComponent) calicoPolicyPassthruClusterRole() *rbacv1.ClusterRole {
	resources := []string{"networkpolicies", "globalnetworkpolicies"}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-tiered-policy-passthrough",
		},
		// If tiered policy is enabled we allow all authenticated users to access the main tier resource, instead
		// restricting access using the tier.xxx resource type. Kubernetes NetworkPolicy and
		// StagedKubernetesNetworkPolicy objects are handled using normal (non-tiered) RBAC.
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: resources,
				Verbs:     allVerbs,
			},
		},
	}
}

// calicoPolicyPassthruClusterRolebinding creates a clusterrolebinding that applies calicoPolicyPassthruClusterRole to all users.
func (c *apiServerComponent) calicoPolicyPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-tiered-policy-passthrough",
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
			Name:     "calico-tiered-policy-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func (c *apiServerComponent) getDeprecatedResources() []client.Object {
	var renamedRscList []client.Object

	// renamed clusterrole tigera-crds to tigera-apiserver
	renamedRscList = append(renamedRscList, &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-crds",
		},
	})

	// renamed clusterrolebinding tigera-apiserver-access-tigera-crds to tigera-apiserver
	renamedRscList = append(renamedRscList, &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-access-tigera-crds",
		},
	})

	// Renamed ClusterRoleBinding tigera-tier-getter to calico-tier-getter since Tier is available in OSS.
	// Deleting an object that was never created (e.g. in a fresh OSS install) is a no-op.
	renamedRscList = append(renamedRscList, &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tier-getter",
		},
	})
	// Renamed ClusterRole tigera-tier-getter to calico-tier-getter since Tier is available in OSS
	renamedRscList = append(renamedRscList, &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tier-getter",
		},
	})

	renamedRscList = append(renamedRscList, &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-apiserver",
		},
	})

	renamedRscList = append(renamedRscList, &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-system",
		},
	})

	// Renamed ClusterRole tigera-managed-cluster-watch to calico-managed-cluster-watch
	renamedRscList = append(renamedRscList, &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-managed-cluster-watch"},
	})

	return renamedRscList
}

func (cfg *APIServerConfiguration) IsSidecarInjectionEnabled() bool {
	return cfg.ApplicationLayer != nil &&
		cfg.ApplicationLayer.Spec.SidecarInjection != nil &&
		*cfg.ApplicationLayer.Spec.SidecarInjection == operatorv1.SidecarEnabled
}

func (c *apiServerComponent) l7AdmissionControllerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		c.cfg.TLSKeyPair.VolumeMount(c.SupportedOSType()),
	}

	l7AdmissionControllerTargetPort := GetContainerPort(c.cfg, L7AdmissionControllerContainerName).ContainerPort

	dataplane := "iptables"
	if c.cfg.Installation.IsNftables() {
		dataplane = "nftables"
	}

	l7AdmssCtrl := corev1.Container{
		Name:    string(L7AdmissionControllerContainerName),
		Image:   c.calicoImage,
		Command: []string{components.CalicoBinaryPath, "component", "l7-admission-controller"},
		Env: []corev1.EnvVar{
			{
				Name:  "L7ADMCTRL_TLSCERTPATH",
				Value: c.cfg.TLSKeyPair.VolumeMountCertificateFilePath(),
			},
			{
				Name:  "L7ADMCTRL_TLSKEYPATH",
				Value: c.cfg.TLSKeyPair.VolumeMountKeyFilePath(),
			},
			{
				Name:  "L7ADMCTRL_ENVOYIMAGE",
				Value: c.l7AdmissionControllerEnvoyImage,
			},
			{
				Name:  "L7ADMCTRL_DIKASTESIMAGE",
				Value: c.dikastesImage,
			},
			{
				Name:  "L7ADMCTRL_LISTENADDR",
				Value: fmt.Sprintf(":%d", l7AdmissionControllerTargetPort),
			},
			{
				Name:  "DATAPLANE",
				Value: dataplane,
			},
		},
		VolumeMounts: volumeMounts,
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/live",
					Port:   intstr.FromInt32(l7AdmissionControllerTargetPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
		},
	}

	return l7AdmssCtrl
}
