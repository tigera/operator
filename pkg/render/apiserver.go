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
	"fmt"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

const (
	apiServerPort           = 5443
	queryServerPort         = 8080
	APIServerNamespace      = "tigera-system"
	APIServerTLSSecretName  = "tigera-apiserver-certs"
	APIServerSecretKeyName  = "apiserver.key"
	APIServerSecretCertName = "apiserver.crt"
	apiServiceName          = "tigera-api"
)

var apiServiceHostname = apiServiceName + "." + APIServerNamespace + ".svc"

func APIServer(installation *operator.Installation, tlsKeyPair *corev1.Secret, pullSecrets []*corev1.Secret, openshift bool) (Component, error) {
	tlsSecrets := []*corev1.Secret{}
	if tlsKeyPair == nil {
		var err error
		tlsKeyPair, err = createOperatorTLSSecret(nil,
			APIServerTLSSecretName,
			APIServerSecretKeyName,
			APIServerSecretCertName,
			DefaultCertificateDuration,
			nil,
			apiServiceHostname,
		)
		if err != nil {
			return nil, err
		}
		// We only need to add the tlsKeyPair if we created it, otherwise
		// it already exists.
		tlsSecrets = []*corev1.Secret{tlsKeyPair}
	}
	copy := tlsKeyPair.DeepCopy()
	copy.ObjectMeta = metav1.ObjectMeta{
		Name:      APIServerTLSSecretName,
		Namespace: APIServerNamespace,
	}
	tlsSecrets = append(tlsSecrets, copy)

	return &apiServerComponent{
		installation: installation,
		tlsSecrets:   tlsSecrets,
		pullSecrets:  pullSecrets,
		openshift:    openshift,
	}, nil
}

type apiServerComponent struct {
	installation *operator.Installation
	tlsSecrets   []*corev1.Secret
	pullSecrets  []*corev1.Secret
	openshift    bool
}

func (c *apiServerComponent) Objects() []runtime.Object {
	objs := []runtime.Object{
		createNamespace(APIServerNamespace, c.openshift),
	}
	secrets := copyImagePullSecrets(c.pullSecrets, APIServerNamespace)
	objs = append(objs, secrets...)
	objs = append(objs,
		c.auditPolicyConfigMap(),
		c.apiServerServiceAccount(),
		c.apiServiceAccountClusterRole(),
		c.apiServiceAccountClusterRoleBinding(),
		c.tieredPolicyPassthruClusterRole(),
		c.tieredPolicyPassthruClusterRolebinding(),
		c.authClusterRole(),
		c.authClusterRoleBinding(),
		c.delegateAuthClusterRoleBinding(),
		c.authReaderRoleBinding(),
	)

	objs = append(objs, c.getTLSObjects()...)
	objs = append(objs,
		c.apiServer(),
		c.apiServiceRegistration(c.tlsSecrets[0].Data[APIServerSecretCertName]),
		c.apiServerService(),
	)

	objs = append(objs,
		c.k8sKubeControllerClusterRole(),
		c.k8sRoleBinding(),
		c.tigeraUserClusterRole(),
		c.tigeraNetworkAdminClusterRole(),
	)

	objs = append(objs,
		c.webhookReaderClusterRole(),
		c.webhookReaderClusterRoleBinding(),
	)

	return objs
}

func (c *apiServerComponent) Ready() bool {
	return true
}

// apiServiceRegistration creates an API service that registers Tigera Secure APIs (and API server).
func (c *apiServerComponent) apiServiceRegistration(cert []byte) *v1beta1.APIService {
	s := &v1beta1.APIService{
		TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "v3.projectcalico.org",
		},
		Spec: v1beta1.APIServiceSpec{
			Group:                "projectcalico.org",
			VersionPriority:      200,
			GroupPriorityMinimum: 200,
			Service: &v1beta1.ServiceReference{
				Name:      apiServiceName,
				Namespace: APIServerNamespace,
			},
			Version:  "v3",
			CABundle: cert,
		},
	}
	return s
}

// tieredPolicyPassthruClusterRole creates a clusterrole that is used to control the RBAC
// mechanism for Tigera Secure tiered policy.
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
			{
				Kind:     "Group",
				Name:     "system:unauthenticated",
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

// delegateAuthClusterRoleBinding creates a clusterrolebinding that allows the API server to delegate
// authn/authz requests to main API server.
func (c *apiServerComponent) delegateAuthClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-delegate-auth",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-apiserver",
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
func (c *apiServerComponent) authReaderRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-auth-reader",
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
				Name:      "tigera-apiserver",
				Namespace: APIServerNamespace,
			},
		},
	}
}

// apiServerServiceAccount creates the service account used by the API server.
func (c *apiServerComponent) apiServerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-apiserver",
			Namespace: APIServerNamespace,
		},
	}
}

// apiServiceAccountClusterRole creates a clusterrole that gives permissions to access backing CRDs and
// k8s networkpolicies.
func (c *apiServerComponent) apiServiceAccountClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-crds",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"extensions",
					"networking.k8s.io",
					"",
				},
				Resources: []string{
					"networkpolicies",
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
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"globalnetworkpolicies",
					"networkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"stagedglobalnetworkpolicies",
					"tiers",
					"clusterinformations",
					"hostendpoints",
					"licensekeys",
					"globalnetworksets",
					"networksets",
					"globalalerts",
					"globalalerttemplates",
					"globalthreatfeeds",
					"globalreporttypes",
					"globalreports",
					"bgpconfigurations",
					"bgppeers",
					"felixconfigurations",
					"ippools",
					"ipamblocks",
					"blockaffinities",
					"remoteclusterconfigurations",
					"managedclusters",
				},
				Verbs: []string{"*"},
			},
		},
	}
}

// apiServiceAccountClusterRoleBinding creates a clusterrolebinding that applies apiServiceAccountClusterRole to
// the tigera-apiserver service account.
func (c *apiServerComponent) apiServiceAccountClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-access-crds",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-apiserver",
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-crds",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func (c *apiServerComponent) authClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-extension-apiserver-auth-access",
		},
		Rules: []rbacv1.PolicyRule{
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
		},
	}
}
func (c *apiServerComponent) authClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-extension-apiserver-auth-access",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-apiserver",
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-extension-apiserver-auth-access",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// webhookReaderClusterRole returns a ClusterRole to read MutatingWebhookConfigurations and ValidatingWebhookConfigurations
func (c *apiServerComponent) webhookReaderClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-webhook-reader",
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

// webhookReaderClusterRoleBinding binds the tigera-apiserver ServiceAccount to the tigera-webhook-reader
func (c *apiServerComponent) webhookReaderClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-webhook-reader",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-apiserver",
				Namespace: APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-webhook-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// apiServerService creates a service backed by the API server and query server.
func (c *apiServerComponent) apiServerService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-api",
			Namespace: APIServerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "apiserver",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(apiServerPort),
				},
				{
					Name:       "queryserver",
					Port:       queryServerPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(queryServerPort),
				},
			},
			Selector: map[string]string{
				"apiserver": "true",
			},
		},
	}
}

func (c *apiServerComponent) auditPolicyConfigMap() *corev1.ConfigMap {
	const defaultAuditPolicy = `apiVersion: audit.k8s.io/v1beta1
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
			Name:      "tigera-audit-policy",
			Namespace: APIServerNamespace,
		},
		Data: map[string]string{
			"config": defaultAuditPolicy,
		},
	}
}

// apiServer creates a deployment containing the API and query servers.
func (c *apiServerComponent) apiServer() *appsv1.Deployment {
	var replicas int32 = 1
	annotations := make(map[string]string)
	annotations[tlsSecretHashAnnotation] = AnnotationHash(c.tlsSecrets[0].Data)

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-apiserver",
			Namespace: APIServerNamespace,
			Labels: map[string]string{
				"apiserver": "true",
				"k8s-app":   "tigera-apiserver",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"apiserver": "true"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-apiserver",
					Namespace: APIServerNamespace,
					Labels: map[string]string{
						"apiserver": "true",
						"k8s-app":   "tigera-apiserver",
					},
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					ServiceAccountName: "tigera-apiserver",
					Tolerations:        c.tolerations(),
					ImagePullSecrets:   getImagePullSecretReferenceList(c.pullSecrets),
					Containers: []corev1.Container{
						c.apiServerContainer(),
						c.queryServerContainer(),
					},
					Volumes: c.apiServerVolumes(),
				},
			},
		},
	}
	return d
}

// apiServerContainer creates the API server container.
func (c *apiServerComponent) apiServerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		{Name: "tigera-audit-logs", MountPath: "/var/log/calico/audit"},
		{Name: "tigera-audit-policy", MountPath: "/etc/tigera/audit"},
		{Name: "tigera-apiserver-certs", MountPath: "/code/apiserver.local.config/certificates"},
	}

	isPrivileged := true

	apiServer := corev1.Container{
		Name:  "tigera-apiserver",
		Image: constructImage(APIServerImageName, c.installation.Spec.Registry, c.installation.Spec.ImagePath),
		Args: []string{
			fmt.Sprintf("--secure-port=%d", apiServerPort),
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		},
		Env: []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		},
		// Needed for permissions to write to the audit log
		SecurityContext: &corev1.SecurityContext{Privileged: &isPrivileged},
		VolumeMounts:    volumeMounts,
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt(apiServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
			PeriodSeconds:       10,
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"cat",
						"/tmp/ready",
					},
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
			FailureThreshold:    5,
		},
	}

	return apiServer
}

// queryServerContainer creates the query server container.
func (c *apiServerComponent) queryServerContainer() corev1.Container {
	image := constructImage(QueryServerImageName, c.installation.Spec.Registry, c.installation.Spec.ImagePath)
	container := corev1.Container{
		Name:  "tigera-queryserver",
		Image: image,
		Env: []corev1.EnvVar{
			// Set queryserver logging to "info"
			{Name: "LOGLEVEL", Value: "info"},
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt(queryServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
			PeriodSeconds:       10,
		},
		SecurityContext: securityContext(),
	}
	return container
}

// apiServerVolumes creates the volumes used by the API server deployment.
func (c *apiServerComponent) apiServerVolumes() []corev1.Volume {
	hostPathType := corev1.HostPathDirectoryOrCreate
	volumes := []corev1.Volume{
		{
			Name: "tigera-audit-logs",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/audit",
					Type: &hostPathType,
				},
			},
		},
		{
			Name: "tigera-audit-policy",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-audit-policy"},
					Items: []corev1.KeyToPath{
						{
							Key:  "config",
							Path: "policy.conf",
						},
					},
				},
			},
		},
		{
			Name: "tigera-apiserver-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: APIServerTLSSecretName,
				},
			},
		},
	}
	return volumes
}

// tolerations creates the tolerations used by the API server deployment.
func (c *apiServerComponent) tolerations() []corev1.Toleration {
	tolerations := []corev1.Toleration{
		{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
	}
	return tolerations
}

func (c *apiServerComponent) getTLSObjects() []runtime.Object {
	objs := []runtime.Object{}
	for _, s := range c.tlsSecrets {
		objs = append(objs, s)
	}

	return objs
}

// k8sKubeControllerClusterRole creates a clusterrole that gives permissions to get tiers.
func (c *apiServerComponent) k8sKubeControllerClusterRole() *rbacv1.ClusterRole {
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

// k8sRoleBinding creates a rolebinding that allows the k8s kube-controller to get tiers
// In k8s 1.15+, cascading resource deletions (for instance pods for a replicaset) failed
// due to k8s kube-controller not having permissions to get tiers.
func (c *apiServerComponent) k8sRoleBinding() *rbacv1.ClusterRoleBinding {
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

// tigeraUserClusterRole returns a cluster role for a default Tigera Secure user.
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
	if c.installation.Spec.ClusterManagementType != operator.ClusterManagementTypeManaged {
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
	if c.installation.Spec.ClusterManagementType != operator.ClusterManagementTypeManaged {
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
