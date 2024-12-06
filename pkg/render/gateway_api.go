// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did
)

var (
	//go:embed gateway_api_crds.yaml
	gatewayAPICRDsYAML string

	yamlDelimiter = "\n---\n"
	lock          sync.Mutex
	cachedObjects []client.Object
)

type yamlKind struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

func GatewayAPICRDs(log logr.Logger) []client.Object {
	lock.Lock()
	defer lock.Unlock()

	if len(cachedObjects) == 0 {
		for _, yml := range strings.Split(gatewayAPICRDsYAML, yamlDelimiter) {
			var yamlKind yamlKind
			if err := yaml.Unmarshal([]byte(yml), &yamlKind); err != nil {
				panic(fmt.Sprintf("unable to unmarshal YAML: %v:\n%v\n", err, yml))
			}
			kindStr := yamlKind.APIVersion + "/" + yamlKind.Kind
			if kindStr == "apiextensions.k8s.io/v1/CustomResourceDefinition" {
				obj := &apiextenv1.CustomResourceDefinition{}
				if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
					panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
				}
				cachedObjects = append(cachedObjects, obj)
			}
		}
	}

	gatewayAPICRDs := make([]client.Object, len(cachedObjects))
	for i := range cachedObjects {
		gatewayAPICRDs[i] = cachedObjects[i].DeepCopyObject().(client.Object)
	}

	return gatewayAPICRDs
}

type GatewayAPIImplementationConfig struct {
	ClusterDomain        string
	Installation         *operatorv1.InstallationSpec
	ManagedCluster       bool
	OpenShift            bool
	PullSecrets          []*corev1.Secret
	TrustedBundle        certificatemanagement.TrustedBundleRO
	GatewayAPICertSecret certificatemanagement.KeyPairInterface

	Namespace         string
	BindingNamespaces []string

	// Whether or not to run the rendered components in multi-tenant mode.
	Tenant          *operatorv1.Tenant
	ExternalElastic bool

	GatewayAPI *operatorv1.GatewayAPI
}

type gatewayAPIImplementationComponent struct {
	cfg   *GatewayAPIImplementationConfig
	image string
}

func GatewayAPIImplementationComponent(cfg *GatewayAPIImplementationConfig) Component {
	return &gatewayAPIImplementationComponent{
		cfg: cfg,
	}
}

const (
	GatewayAPIName         = "gateway-api"              // for resource within a Calico namespace
	GatewayAPIGlobalName   = "calico-" + GatewayAPIName // for non-namespaced resources
	EnvoyGatewayConfigName = GatewayAPIName + "-envoy-gateway-config"
	EnvoyGatewayConfigKey  = "envoy-gateway.yaml"
)

func (pr *gatewayAPIImplementationComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := pr.cfg.Installation.Registry
	path := pr.cfg.Installation.ImagePath
	prefix := pr.cfg.Installation.ImagePrefix

	var err error
	pr.image, err = components.GetReference(components.ComponentGatewayAPI, reg, path, prefix, is)
	if err != nil {
		return err
	}
	return nil
}

func (pr *gatewayAPIImplementationComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (pr *gatewayAPIImplementationComponent) Ready() bool {
	return true
}

func (pr *gatewayAPIImplementationComponent) Objects() ([]client.Object, []client.Object) {
	// Management and managed clusters need API access to the resources defined in the policy
	// recommendation cluster role
	objs := []client.Object{
		CreateNamespace(pr.cfg.Namespace, pr.cfg.Installation.KubernetesProvider, PSSRestricted, pr.cfg.Installation.Azure),
		pr.serviceAccount(),
		pr.envoyGatewayConfig(),
		pr.clusterRole(),
		pr.clusterRoleBinding(),
		pr.role(),
		pr.roleForLeaderElection(),
		pr.roleBinding(),
		pr.roleBindingForLeaderElection(),
		pr.controllerService(),
		pr.controllerDeployment(),
		networkpolicy.AllowTigeraDefaultDeny(pr.cfg.Namespace),
		pr.allowTigeraPolicyForGatewayAPI(),
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(pr.cfg.Namespace, pr.cfg.PullSecrets...)...)...)

	return objs, nil
}

func (pr *gatewayAPIImplementationComponent) serviceAccount() client.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GatewayAPIName, Namespace: pr.cfg.Namespace},
	}
}

func (pr *gatewayAPIImplementationComponent) envoyGatewayConfig() client.Object {
	config := `
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyGateway
gateway:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
logging:
  level:
    default: info
provider:
  kubernetes:
    rateLimitDeployment:
      container:
        image: docker.io/envoyproxy/ratelimit:26f28d78
      patch:
        type: StrategicMerge
        value:
          spec:
            template:
              spec:
                containers:
                - imagePullPolicy: IfNotPresent
                  name: envoy-ratelimit
    shutdownManager:
      image: docker.io/envoyproxy/gateway:v1.1.2
  type: Kubernetes
`
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: EnvoyGatewayConfigName, Namespace: pr.cfg.Namespace},
		Data: map[string]string{
			EnvoyGatewayConfigKey: config,
		},
	}
}

func (pr *gatewayAPIImplementationComponent) clusterRole() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"nodes", "namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gatewayclasses"},
			Verbs:     []string{"get", "list", "patch", "update", "watch"},
		},
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gatewayclasses/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"multicluster.x-k8s.io"},
			Resources: []string{"serviceimports"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps", "secrets", "services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"gateway.envoyproxy.io"},
			Resources: []string{
				"envoyproxies",
				"envoypatchpolicies",
				"clienttrafficpolicies",
				"backendtrafficpolicies",
				"securitypolicies",
				"envoyextensionpolicies",
				"backends",
			},
			Verbs: []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"gateway.envoyproxy.io"},
			Resources: []string{
				"envoypatchpolicies/status",
				"clienttrafficpolicies/status",
				"backendtrafficpolicies/status",
				"securitypolicies/status",
				"envoyextensionpolicies/status",
				"backends/status",
			},
			Verbs: []string{"update"},
		},
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{
				"gateways",
				"grpcroutes",
				"httproutes",
				"referencegrants",
				"tcproutes",
				"tlsroutes",
				"udproutes",
				"backendtlspolicies",
			},
			Verbs: []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{
				"gateways/status",
				"grpcroutes/status",
				"httproutes/status",
				"tcproutes/status",
				"tlsroutes/status",
				"udproutes/status",
				"backendtlspolicies/status",
			},
			Verbs: []string{"update"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GatewayAPIGlobalName,
		},
		Rules: rules,
	}
}

func (pr *gatewayAPIImplementationComponent) clusterRoleBinding() client.Object {
	return rcomponents.ClusterRoleBinding(
		GatewayAPIGlobalName,
		GatewayAPIGlobalName,
		GatewayAPIName,
		[]string{pr.cfg.Namespace},
	)
}

func (pr *gatewayAPIImplementationComponent) role() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts", "services"},
			Verbs:     []string{"create", "get", "delete", "patch"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments", "daemonsets"},
			Verbs:     []string{"create", "get", "delete", "patch"},
		},
		{
			APIGroups: []string{"autoscaling", "policy"},
			Resources: []string{"horizontalpodautoscalers", "poddisruptionbudgets"},
			Verbs:     []string{"create", "get", "delete", "patch"},
		},
	}

	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayAPIName,
			Namespace: pr.cfg.Namespace,
		},
		Rules: rules,
	}
}

func (pr *gatewayAPIImplementationComponent) roleBinding() client.Object {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayAPIName,
			Namespace: pr.cfg.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     GatewayAPIName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GatewayAPIName,
				Namespace: pr.cfg.Namespace,
			},
		},
	}
}

func (pr *gatewayAPIImplementationComponent) roleForLeaderElection() client.Object {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"coordination.k8s.io"},
			Resources: []string{"leases"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
	}

	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayAPIName + "-leader-election",
			Namespace: pr.cfg.Namespace,
		},
		Rules: rules,
	}
}

func (pr *gatewayAPIImplementationComponent) roleBindingForLeaderElection() client.Object {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayAPIName + "-leader-election",
			Namespace: pr.cfg.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     GatewayAPIName + "-leader-election",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GatewayAPIName,
				Namespace: pr.cfg.Namespace,
			},
		},
	}
}

func (pr *gatewayAPIImplementationComponent) controllerService() client.Object {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayAPIName,
			Namespace: pr.cfg.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				AppLabelName: GatewayAPIName,
			},
			Ports: []corev1.ServicePort{{
				Name:       "grpc",
				Port:       18000,
				TargetPort: intstr.FromInt(18000),
			}, {
				Name:       "ratelimit",
				Port:       18001,
				TargetPort: intstr.FromInt(18001),
			}, {
				Name:       "wasm",
				Port:       18002,
				TargetPort: intstr.FromInt(18002),
			}, {
				Name:       "metrics",
				Port:       19001,
				TargetPort: intstr.FromInt(19001),
			}},
		},
	}
}

func (pr *gatewayAPIImplementationComponent) controllerDeployment() *appsv1.Deployment {
	volumeMounts := pr.cfg.TrustedBundle.VolumeMounts(pr.SupportedOSType())
	volumeMounts = append(volumeMounts, pr.cfg.GatewayAPICertSecret.VolumeMount(pr.SupportedOSType()))

	controllerContainer := corev1.Container{
		Args: []string{"server", "--config-path=/config/envoy-gateway.yaml"},
		Env: []corev1.EnvVar{
			{
				Name: "ENVOY_GATEWAY_NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						APIVersion: "v1",
						FieldPath:  "metadata.namespace",
					},
				},
			},
			{
				Name:  "KUBERNETES_CLUSTER_DOMAIN",
				Value: "cluster.local",
			},
		},
		Image:           "docker.io/envoyproxy/gateway:v1.1.2",
		ImagePullPolicy: ImagePullPolicy(),
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/healthz",
					Port: intstr.FromInt(8081),
				},
			},
			InitialDelaySeconds: 15,
			PeriodSeconds:       20,
		},
		Name: "envoy-gateway",
		Ports: []corev1.ContainerPort{{
			ContainerPort: 18000,
			Name:          "grpc",
		}, {
			ContainerPort: 18001,
			Name:          "ratelimit",
		}, {
			ContainerPort: 18002,
			Name:          "wasm",
		}, {
			ContainerPort: 19001,
			Name:          "metrics",
		}},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/readyz",
					Port: intstr.FromInt(8081),
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
		},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("1024Mi"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}

	volumes := []corev1.Volume{
		pr.cfg.TrustedBundle.Volume(),
		pr.cfg.GatewayAPICertSecret.Volume(),
	}
	var initContainers []corev1.Container
	if pr.cfg.GatewayAPICertSecret != nil && pr.cfg.GatewayAPICertSecret.UseCertificateManagement() {
		initContainers = append(initContainers, pr.cfg.GatewayAPICertSecret.InitContainer(GatewayAPINamespace))
	}

	tolerations := pr.cfg.Installation.ControlPlaneTolerations
	if pr.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	podTemplateSpec := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        GatewayAPIName,
			Namespace:   pr.cfg.Namespace,
			Annotations: pr.policyRecommendationAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:        tolerations,
			NodeSelector:       pr.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: GatewayAPIName,
			ImagePullSecrets:   secret.GetReferenceList(pr.cfg.PullSecrets),
			Containers:         []corev1.Container{controllerContainer},
			InitContainers:     initContainers,
			Volumes:            volumes,
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayAPIName,
			Namespace: pr.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Template: *podTemplateSpec,
		},
	}

	if pr.cfg.GatewayAPI != nil {
		if overrides := pr.cfg.GatewayAPI.Spec.GatewayAPIDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}

	return d
}

func (pr *gatewayAPIImplementationComponent) policyRecommendationAnnotations() map[string]string {
	return pr.cfg.TrustedBundle.HashAnnotations()
}

// allowTigeraPolicyForGatewayAPI defines an allow-tigera policy for policy recommendation.
func (pr *gatewayAPIImplementationComponent) allowTigeraPolicyForGatewayAPI() *v3.NetworkPolicy {
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

	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, pr.cfg.OpenShift)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayAPIPolicyName,
			Namespace: pr.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(GatewayAPIName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{},
			Egress:   egressRules,
		},
	}
}
