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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the PolicyRecommendation APIs related rendered objects.
const (
	ElasticsearchPolicyRecommendationUserSecret = "tigera-ee-policy-recommendation-elasticsearch-access"

	PolicyRecommendationName       = "tigera-policy-recommendation"
	PolicyRecommendationNamespace  = PolicyRecommendationName
	PolicyRecommendationPolicyName = networkpolicy.TigeraComponentPolicyPrefix + PolicyRecommendationName

	PolicyRecommendationTLSSecretName = "policy-recommendation-tls"
)

var PolicyRecommendationEntityRule = networkpolicy.CreateSourceEntityRule(PolicyRecommendationNamespace, PolicyRecommendationName)

// PolicyRecommendationConfiguration contains all the config information needed to render the component.
type PolicyRecommendationConfiguration struct {
	ClusterDomain                  string
	ESClusterConfig                *relasticsearch.ClusterConfig
	ESSecrets                      []*corev1.Secret
	Installation                   *operatorv1.InstallationSpec
	ManagedCluster                 bool
	Openshift                      bool
	PullSecrets                    []*corev1.Secret
	TrustedBundle                  certificatemanagement.TrustedBundle
	PolicyRecommendationCertSecret certificatemanagement.KeyPairInterface

	// Whether the cluster supports pod security policies.
	UsePSP bool
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
	return rmeta.OSTypeAny
}

func (pr *policyRecommendationComponent) Objects() ([]client.Object, []client.Object) {
	// Management and managed clusters need API access to the resources defined in the policy
	// recommendation cluster role
	objs := []client.Object{
		CreateNamespace(PolicyRecommendationNamespace, pr.cfg.Installation.KubernetesProvider, PSSRestricted),
		pr.serviceAccount(),
		pr.clusterRole(),
		pr.clusterRoleBinding(),
		networkpolicy.AllowTigeraDefaultDeny(PolicyRecommendationNamespace),
	}

	if pr.cfg.ManagedCluster {
		// No further resources are needed for managed clusters
		return objs, nil
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(PolicyRecommendationNamespace, pr.cfg.PullSecrets...)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(PolicyRecommendationNamespace, pr.cfg.ESSecrets...)...)...)
	// The deployment is created on management/standalone clusters only
	objs = append(objs,
		pr.allowTigeraPolicyForPolicyRecommendation(),
		pr.deployment(),
	)

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
			Resources: []string{"licensekeys", "managedclusters"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
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

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PolicyRecommendationName,
		},
		Rules: rules,
	}
}

func (pr *policyRecommendationComponent) clusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: PolicyRecommendationName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     PolicyRecommendationName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      PolicyRecommendationName,
				Namespace: PolicyRecommendationNamespace,
			},
		},
	}
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
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(pr.SupportedOSType(), pr.cfg.ClusterDomain),
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

	container := relasticsearch.ContainerDecorateIndexCreator(
		relasticsearch.ContainerDecorate(
			controllerContainer,
			pr.cfg.ESClusterConfig.ClusterName(),
			ElasticsearchPolicyRecommendationUserSecret,
			pr.cfg.ClusterDomain,
			rmeta.OSTypeLinux,
		),
		pr.cfg.ESClusterConfig.Replicas(),
		pr.cfg.ESClusterConfig.Shards())

	podTemplateSpec := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        PolicyRecommendationName,
			Namespace:   PolicyRecommendationNamespace,
			Annotations: pr.policyRecommendationAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:        pr.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:       pr.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: PolicyRecommendationName,
			ImagePullSecrets:   secret.GetReferenceList(pr.cfg.PullSecrets),
			Containers: []corev1.Container{
				container,
			},
			InitContainers: initContainers,
			Volumes:        volumes,
		},
	}, pr.cfg.ESClusterConfig, pr.cfg.ESSecrets).(*corev1.PodTemplateSpec)

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyRecommendationName,
			Namespace: PolicyRecommendationNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Template: *podTemplateSpec,
		},
	}
}

func (pr *policyRecommendationComponent) policyRecommendationAnnotations() map[string]string {
	return pr.cfg.TrustedBundle.HashAnnotations()
}

func (pr *policyRecommendationComponent) serviceAccount() client.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PolicyRecommendationName, Namespace: PolicyRecommendationNamespace},
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
			Destination: ManagerEntityRule,
		},
	}

	if !pr.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.LinseedEntityRule,
		})
	}

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, pr.cfg.Openshift)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyRecommendationPolicyName,
			Namespace: PolicyRecommendationNamespace,
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
