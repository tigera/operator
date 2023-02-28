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
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/ptr"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the PolicyRecommendation APIs related rendered objects.
const (
	ElasticsearchPolicyRecommendationUserSecret = "tigera-ee-policy-recommendation-elasticsearch-access"

	PolicyRecommendationName = "tigera-policy-recommendation"

	PolicyRecommendationClusterRoleName        = PolicyRecommendationName
	PolicyRecommendationClusterRoleBindingName = PolicyRecommendationName
	PolicyRecommendationDeploymentName         = PolicyRecommendationName
	PolicyRecommendationNamespace              = PolicyRecommendationName
	PolicyRecommendationServiceAccountName     = PolicyRecommendationName
	PolicyRecommendationPolicyName             = networkpolicy.TigeraComponentPolicyPrefix + PolicyRecommendationName

	PolicyRecommendationControllerName = "policy-recommendation-controller"
	PolicyRecommendationInstallerName  = "policy-recommendation-es-installer"
)

// PolicyRecommendationConfiguration contains all the config information needed to render the component.
type PolicyRecommendationConfiguration struct {
	ClusterDomain                        string
	ESClusterConfig                      *relasticsearch.ClusterConfig
	ESSecrets                            []*corev1.Secret
	Installation                         *operatorv1.InstallationSpec
	ManagedCluster                       bool
	Openshift                            bool
	PolicyRecommendationServerCertSecret certificatemanagement.KeyPairInterface
	PullSecrets                          []*corev1.Secret
	TrustedBundle                        certificatemanagement.TrustedBundle

	// Whether or not the cluster supports pod security policies.
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
	objs := []client.Object{
		CreateNamespace(PolicyRecommendationNamespace, pr.cfg.Installation.KubernetesProvider, PSSBaseline),
		allowTigeraPolicyForPolicyRecommendation(pr.cfg),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(PolicyRecommendationNamespace, pr.cfg.PullSecrets...)...)...)

	objs = append(objs,
		pr.serviceAccount(),
		pr.clusterRole(),
		pr.clusterRoleBinding(),
		pr.deployment(),
	)

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(PolicyRecommendationNamespace, pr.cfg.ESSecrets...)...)...)

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
				"policyrecommendationscope",
				"policyrecommendationscope/status",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagednetworkpolicy",
				"tier.stagednetworkpolicy",
			},
			Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PolicyRecommendationClusterRoleName,
		},
		Rules: rules,
	}
}

func (pr *policyRecommendationComponent) clusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PolicyRecommendationClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     PolicyRecommendationClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      PolicyRecommendationServiceAccountName,
				Namespace: PolicyRecommendationNamespace,
			},
		},
	}
}

func (pr *policyRecommendationComponent) controllerContainer() corev1.Container {
	envs := []corev1.EnvVar{
		{
			Name:  "CLUSTER_NAME",
			Value: pr.cfg.ESClusterConfig.ClusterName(),
		},
		{
			Name:  "MULTI_CLUSTER_FORWARDING_CA",
			Value: pr.cfg.TrustedBundle.MountPath(),
		},
		{
			Name:  "FIPS_MODE_ENABLED",
			Value: operatorv1.IsFIPSModeEnabledString(pr.cfg.Installation.FIPSMode),
		},
	}

	sc := securitycontext.NewNonRootContext()

	volumeMounts := []corev1.VolumeMount{
		pr.cfg.TrustedBundle.VolumeMount(pr.SupportedOSType()),
		pr.cfg.PolicyRecommendationServerCertSecret.VolumeMount(pr.SupportedOSType()),
	}

	return corev1.Container{
		Name:            "policy-recommendation-controller",
		Image:           pr.image,
		Env:             envs,
		SecurityContext: sc,
		VolumeMounts:    volumeMounts,
	}
}

func (pr *policyRecommendationComponent) deployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyRecommendationName,
			Namespace: PolicyRecommendationNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Template: *pr.deploymentPodTemplate(),
		},
	}
}

func (pr *policyRecommendationComponent) deploymentPodTemplate() *corev1.PodTemplateSpec {
	var ps []corev1.LocalObjectReference
	for _, x := range pr.cfg.PullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}

	volumes := []corev1.Volume{
		pr.cfg.TrustedBundle.Volume(),
		pr.cfg.PolicyRecommendationServerCertSecret.Volume(),
	}

	container := relasticsearch.ContainerDecorateIndexCreator(
		relasticsearch.ContainerDecorate(pr.controllerContainer(), pr.cfg.ESClusterConfig.ClusterName(),
			ElasticsearchPolicyRecommendationUserSecret, pr.cfg.ClusterDomain, rmeta.OSTypeLinux),
		pr.cfg.ESClusterConfig.Replicas(), pr.cfg.ESClusterConfig.Shards())

	return relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        PolicyRecommendationName,
			Namespace:   PolicyRecommendationNamespace,
			Annotations: pr.policyRecommendationAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:        pr.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:       pr.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: PolicyRecommendationName,
			ImagePullSecrets:   ps,
			Containers: []corev1.Container{
				container,
			},
			Volumes: volumes,
		},
	}, pr.cfg.ESClusterConfig, pr.cfg.ESSecrets).(*corev1.PodTemplateSpec)
}

func (pr *policyRecommendationComponent) policyRecommendationAnnotations() map[string]string {
	annotations := pr.cfg.TrustedBundle.HashAnnotations()

	pr.cfg.TrustedBundle.HashAnnotations()
	if pr.cfg.PolicyRecommendationServerCertSecret != nil {
		annotations[pr.cfg.PolicyRecommendationServerCertSecret.HashAnnotationKey()] = pr.cfg.PolicyRecommendationServerCertSecret.HashAnnotationValue()
	}
	return annotations
}

func (pr *policyRecommendationComponent) serviceAccount() client.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: PolicyRecommendationServiceAccountName, Namespace: PolicyRecommendationNamespace},
	}
}

// allowTigeraPolicyForPolicyRecommendation defines an allow-tigera policy for policy recommendation.
func allowTigeraPolicyForPolicyRecommendation(cfg *PolicyRecommendationConfiguration) *v3.NetworkPolicy {
	apiserverEntityRule := v3.EntityRule{
		NamespaceSelector: "projectcalico.org/name == 'default'",
		Selector: "provider == 'kubernetes' && component == 'apiserver' && " +
			"endpoints.projectcalico.org/serviceName == 'kubernetes'",
		Ports: networkpolicy.Ports(443, 6443, 12388),
	}

	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: apiserverEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.ESGatewayEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: DexEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Openshift)

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
