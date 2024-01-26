// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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
	"crypto/x509"
	"fmt"

	"k8s.io/apiserver/pkg/authentication/serviceaccount"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"

	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

// The names of the components related to the PolicyRecommendation APIs related rendered objects.
const (
	ElasticsearchPolicyRecommendationUserSecret = "tigera-ee-policy-recommendation-elasticsearch-access"

	PolicyRecommendationName                  = "tigera-policy-recommendation"
	PolicyRecommendationNamespace             = PolicyRecommendationName
	PolicyRecommendationPodSecurityPolicyName = PolicyRecommendationName
	PolicyRecommendationPolicyName            = networkpolicy.TigeraComponentPolicyPrefix + PolicyRecommendationName

	PolicyRecommendationTLSSecretName                                   = "policy-recommendation-tls"
	PolicyRecommendationMultiTenantManagedClustersAccessClusterRoleName = "tigera-policy-recommendation-managed-cluster-access"
)

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(PolicyRecommendationTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

// PolicyRecommendationConfiguration contains all the config information needed to render the component.
type PolicyRecommendationConfiguration struct {
	ClusterDomain                  string
	Installation                   *operatorv1.InstallationSpec
	ManagedCluster                 bool
	Openshift                      bool
	PullSecrets                    []*corev1.Secret
	TrustedBundle                  certificatemanagement.TrustedBundle
	PolicyRecommendationCertSecret certificatemanagement.KeyPairInterface

	// Whether the cluster supports pod security policies.
	UsePSP            bool
	Namespace         string
	BindingNamespaces []string

	// Whether or not to run the rendered components in multi-tenant mode.
	Tenant          *operatorv1.Tenant
	ExternalElastic bool

	PolicyRecommendation *operatorv1.PolicyRecommendation
}

type policyRecommendationComponent struct {
	cfg   *PolicyRecommendationConfiguration
	image string
}

func PolicyRecommendation(cfg *PolicyRecommendationConfiguration) Component {
	return &policyRecommendationComponent{
		cfg: cfg,
	}
}

func (pr *policyRecommendationComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := pr.cfg.Installation.Registry
	path := pr.cfg.Installation.ImagePath
	prefix := pr.cfg.Installation.ImagePrefix

	var err error
	pr.image, err = components.GetReference(components.ComponentPolicyRecommendation, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return nil
}

func (pr *policyRecommendationComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (pr *policyRecommendationComponent) Objects() ([]client.Object, []client.Object) {
	// Management and managed clusters need API access to the resources defined in the policy
	// recommendation cluster role
	objs := []client.Object{
		CreateNamespace(pr.cfg.Namespace, pr.cfg.Installation.KubernetesProvider, PSSRestricted),
		pr.serviceAccount(),
		pr.clusterRole(),
		pr.clusterRoleBinding(),
		networkpolicy.AllowTigeraDefaultDeny(pr.cfg.Namespace),
	}
	if pr.cfg.Tenant.MultiTenant() {
		objs = append(objs, pr.multiTenantManagedClustersAccess()...)
	}

	if pr.cfg.ManagedCluster {
		// No further resources are needed for managed clusters
		return objs, nil
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(pr.cfg.Namespace, pr.cfg.PullSecrets...)...)...)

	// The deployment is created on management/standalone clusters only
	objs = append(objs,
		pr.allowTigeraPolicyForPolicyRecommendation(),
		pr.deployment(),
	)

	if pr.cfg.UsePSP {
		objs = append(objs, pr.podSecurityPolicy())
	}

	return objs, nil
}

func (pr *policyRecommendationComponent) Ready() bool {
	return true
}

func (pr *policyRecommendationComponent) clusterRole() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworksets",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
		{
			// Add read access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{
				"flows",
			},
			Verbs: []string{"get"},
		},
	}

	if !pr.cfg.ManagedCluster {
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys", "managedclusters"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "list", "watch"},
			},
		}...)
	}

	if pr.cfg.UsePSP {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{PolicyRecommendationPodSecurityPolicyName},
		})
	}

	if pr.cfg.Tenant.MultiTenant() {
		// These rules are used by policy-recommendation in a management cluster serving multiple tenants in order to appear to managed
		// clusters as the expected serviceaccount. They're only needed when there are multiple tenants sharing the same
		// management cluster.
		rules = append(rules, []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{PolicyRecommendationName},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
				ResourceNames: []string{
					serviceaccount.AllServiceAccountsGroup,
					"system:authenticated",
					fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, PolicyRecommendationNamespace),
				},
			},
		}...)
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PolicyRecommendationName,
		},
		Rules: rules,
	}
}

func (pr *policyRecommendationComponent) clusterRoleBinding() client.Object {
	return rcomponents.ClusterRoleBinding(PolicyRecommendationName, PolicyRecommendationName, PolicyRecommendationNamespace, pr.cfg.BindingNamespaces)
}

func (pr *policyRecommendationComponent) multiTenantManagedClustersAccess() []client.Object {
	var objects []client.Object
	objects = append(objects, &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PolicyRecommendationMultiTenantManagedClustersAccessClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs: []string{
					// The Authentication Proxy in Voltron checks if PolicyRecommendation (either using impersonation
					// headers for tigera-policy-recommendation service in tigera-policy-recommendation namespace or
					// the actual account in a single tenant setup) can get a managed clusters before sending the
					// request down the tunnel
					"get",
				},
			},
		},
	})

	// In a single tenant setup we want to create a cluster role that binds using service account
	// tigera-policy-recommendation from tigera-policy-recommendation namespace. In a multi-tenant setup
	// PolicyRecommendation Controller from the tenant's namespace impersonates service tigera-policy-recommendation
	// from tigera-policy-recommendation namespace
	objects = append(objects, &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PolicyRecommendationMultiTenantManagedClustersAccessClusterRoleName},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     PolicyRecommendationMultiTenantManagedClustersAccessClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			// requests for policy recommendation to managed clusters are done using service account tigera-policy-recommendation
			// from tigera-policy-recommendation namespace regardless of tenancy mode (single tenant or multi-tenant)
			{
				Kind:      "ServiceAccount",
				Name:      PolicyRecommendationName,
				Namespace: PolicyRecommendationNamespace,
			},
		},
	})

	return objects
}
func (pr *policyRecommendationComponent) podSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy(PolicyRecommendationPodSecurityPolicyName)
}

// deployment returns the policy recommendation deployments. It assumes that this is defined for
// management and standalone clusters only.
func (pr *policyRecommendationComponent) deployment() *appsv1.Deployment {
	envs := []corev1.EnvVar{
		{
			Name:  "LOG_LEVEL",
			Value: "Info",
		},
		{
			Name:  "MULTI_CLUSTER_FORWARDING_CA",
			Value: pr.cfg.TrustedBundle.MountPath(),
		},
		{
			Name:  "MULTI_CLUSTER_FORWARDING_ENDPOINT",
			Value: ManagerService(pr.cfg.Tenant),
		},
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(pr.SupportedOSType(), pr.cfg.ClusterDomain, LinseedNamespace(pr.cfg.Tenant)),
		},
		{
			Name:  "LINSEED_CA",
			Value: pr.cfg.TrustedBundle.MountPath(),
		},
		{
			Name:  "LINSEED_CLIENT_CERT",
			Value: pr.cfg.PolicyRecommendationCertSecret.VolumeMountCertificateFilePath(),
		},
		{
			Name:  "LINSEED_CLIENT_KEY",
			Value: pr.cfg.PolicyRecommendationCertSecret.VolumeMountKeyFilePath(),
		},
		{
			Name:  "LINSEED_TOKEN",
			Value: GetLinseedTokenPath(false),
		},
	}

	if pr.cfg.Tenant != nil {
		if pr.cfg.ExternalElastic {
			envs = append(envs, corev1.EnvVar{Name: "TENANT_ID", Value: pr.cfg.Tenant.Spec.ID})
		}

		if pr.cfg.Tenant.MultiTenant() {
			envs = append(envs, corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: pr.cfg.Tenant.Namespace})
		}
	}

	volumeMounts := pr.cfg.TrustedBundle.VolumeMounts(pr.SupportedOSType())
	volumeMounts = append(volumeMounts, pr.cfg.PolicyRecommendationCertSecret.VolumeMount(pr.SupportedOSType()))

	controllerContainer := corev1.Container{
		Name:            "policy-recommendation-controller",
		Image:           pr.image,
		ImagePullPolicy: ImagePullPolicy(),
		Env:             envs,
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}

	volumes := []corev1.Volume{
		pr.cfg.TrustedBundle.Volume(),
		pr.cfg.PolicyRecommendationCertSecret.Volume(),
	}
	var initContainers []corev1.Container
	if pr.cfg.PolicyRecommendationCertSecret != nil && pr.cfg.PolicyRecommendationCertSecret.UseCertificateManagement() {
		initContainers = append(initContainers, pr.cfg.PolicyRecommendationCertSecret.InitContainer(PolicyRecommendationNamespace))
	}

	podTemplateSpec := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        PolicyRecommendationName,
			Namespace:   pr.cfg.Namespace,
			Annotations: pr.policyRecommendationAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:        pr.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:       pr.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: PolicyRecommendationName,
			ImagePullSecrets:   secret.GetReferenceList(pr.cfg.PullSecrets),
			Containers:         []corev1.Container{controllerContainer},
			InitContainers:     initContainers,
			Volumes:            volumes,
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyRecommendationName,
			Namespace: pr.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Template: *podTemplateSpec,
		},
	}

	if pr.cfg.PolicyRecommendation != nil {
		if overrides := pr.cfg.PolicyRecommendation.Spec.PolicyRecommendationDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (pr *policyRecommendationComponent) policyRecommendationAnnotations() map[string]string {
	return pr.cfg.TrustedBundle.HashAnnotations()
}

func (pr *policyRecommendationComponent) serviceAccount() client.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PolicyRecommendationName, Namespace: pr.cfg.Namespace},
	}
}

// allowTigeraPolicyForPolicyRecommendation defines an allow-tigera policy for policy recommendation.
func (pr *policyRecommendationComponent) allowTigeraPolicyForPolicyRecommendation() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.Helper(pr.cfg.Tenant.MultiTenant(), pr.cfg.Namespace).ManagerEntityRule(),
		},
	}

	if !pr.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.Helper(pr.cfg.Tenant.MultiTenant(), pr.cfg.Namespace).LinseedEntityRule(),
		})
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, pr.cfg.Openshift)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyRecommendationPolicyName,
			Namespace: pr.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(PolicyRecommendationName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{},
			Egress:   egressRules,
		},
	}
}
