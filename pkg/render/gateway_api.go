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
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did
)

var (
	//go:embed gateway_api_resources.yaml
	gatewayAPIResourcesYAML string
)

type yamlKind struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

// This struct defines all of the resources that we expect to read from the rendered Envoy Gateway
// helm chart (as of v1.1.2).
type gatewayAPIResources struct {
	namespace                 *corev1.Namespace
	k8sCRDs                   []*apiextenv1.CustomResourceDefinition
	envoyCRDs                 []*apiextenv1.CustomResourceDefinition
	controllerServiceAccount  *corev1.ServiceAccount
	envoyGatewayConfig        *corev1.ConfigMap
	clusterRole               *rbacv1.ClusterRole
	clusterRoleBinding        *rbacv1.ClusterRoleBinding
	role                      *rbacv1.Role
	roleBinding               *rbacv1.RoleBinding
	leaderElectionRole        *rbacv1.Role
	leaderElectionRoleBinding *rbacv1.RoleBinding
	controllerService         *corev1.Service
	controllerDeployment      *appsv1.Deployment
	certgenServiceAccount     *corev1.ServiceAccount
	certgenRole               *rbacv1.Role
	certgenRoleBinding        *rbacv1.RoleBinding
	certgenJob                *batchv1.Job
}

const (
	GatewayAPIName                      = "gateway-api"
	GatewayControllerLabel              = GatewayAPIName + "-controller"
	EnvoyGatewayConfigName              = "envoy-gateway-config"
	EnvoyGatewayConfigKey               = "envoy-gateway.yaml"
	EnvoyGatewayDeploymentContainerName = "envoy-gateway"
	EnvoyGatewayJobContainerName        = "envoy-gateway-certgen"
)

func GatewayAPIResourcesGetter() func() *gatewayAPIResources {
	var lock sync.Mutex
	var resources = &gatewayAPIResources{}
	const yamlDelimiter = "\n---\n"
	return func() *gatewayAPIResources {
		lock.Lock()
		defer lock.Unlock()

		if len(resources.k8sCRDs) == 0 {
			for _, yml := range strings.Split(gatewayAPIResourcesYAML, yamlDelimiter) {
				var yamlKind yamlKind
				if err := yaml.Unmarshal([]byte(yml), &yamlKind); err != nil {
					panic(fmt.Sprintf("unable to unmarshal YAML: %v:\n%v\n", err, yml))
				}
				kindStr := yamlKind.APIVersion + "/" + yamlKind.Kind
				switch kindStr {
				case "v1/Namespace":
					if resources.namespace != nil {
						panic("already read a namespace from gateway API YAML")
					}
					resources.namespace = &corev1.Namespace{}
					if err := yaml.Unmarshal([]byte(yml), resources.namespace); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
				case "apiextensions.k8s.io/v1/CustomResourceDefinition":
					obj := &apiextenv1.CustomResourceDefinition{}
					if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
					if strings.HasSuffix(obj.Name, ".gateway.networking.k8s.io") {
						resources.k8sCRDs = append(resources.k8sCRDs, obj)
					} else if strings.HasSuffix(obj.Name, ".gateway.envoyproxy.io") {
						resources.envoyCRDs = append(resources.envoyCRDs, obj)
					} else {
						panic(fmt.Sprintf("unhandled CRD name %v from gateway API YAML", obj.Name))
					}
				case "v1/ServiceAccount":
					obj := &corev1.ServiceAccount{}
					if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
					if strings.HasSuffix(obj.Name, "certgen") {
						if resources.certgenServiceAccount != nil {
							panic("already read a certgen ServiceAccount from gateway API YAML")
						}
						resources.certgenServiceAccount = obj
					} else {
						if resources.controllerServiceAccount != nil {
							panic("already read a controller ServiceAccount from gateway API YAML")
						}
						resources.controllerServiceAccount = obj
					}
				case "v1/ConfigMap":
					obj := &corev1.ConfigMap{}
					if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
					if obj.Name != EnvoyGatewayConfigName {
						panic(fmt.Sprintf("unhandled ConfigMap name %v from gateway API YAML", obj.Name))
					}
					if resources.envoyGatewayConfig != nil {
						panic("already read envoy-gateway-config ConfigMap from gateway API YAML")
					}
					resources.envoyGatewayConfig = obj
				case "rbac.authorization.k8s.io/v1/ClusterRole":
					if resources.clusterRole != nil {
						panic("already read a ClusterRole from gateway API YAML")
					}
					resources.clusterRole = &rbacv1.ClusterRole{}
					if err := yaml.Unmarshal([]byte(yml), resources.clusterRole); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
				case "rbac.authorization.k8s.io/v1/ClusterRoleBinding":
					if resources.clusterRoleBinding != nil {
						panic("already read a ClusterRoleBinding from gateway API YAML")
					}
					resources.clusterRoleBinding = &rbacv1.ClusterRoleBinding{}
					if err := yaml.Unmarshal([]byte(yml), resources.clusterRoleBinding); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
				case "rbac.authorization.k8s.io/v1/Role":
					obj := &rbacv1.Role{}
					if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
					if strings.HasSuffix(obj.Name, "leader-election-role") {
						if resources.leaderElectionRole != nil {
							panic("already read leader-election Role from gateway API YAML")
						}
						resources.leaderElectionRole = obj
					} else if strings.HasSuffix(obj.Name, "certgen") {
						if resources.certgenRole != nil {
							panic("already read certgen Role from gateway API YAML")
						}
						resources.certgenRole = obj
					} else {
						if resources.role != nil {
							panic("already read general Role from gateway API YAML")
						}
						resources.role = obj
					}
				case "rbac.authorization.k8s.io/v1/RoleBinding":
					obj := &rbacv1.RoleBinding{}
					if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
					if strings.HasSuffix(obj.Name, "leader-election-rolebinding") {
						if resources.leaderElectionRoleBinding != nil {
							panic("already read leader-election RoleBinding from gateway API YAML")
						}
						resources.leaderElectionRoleBinding = obj
					} else if strings.HasSuffix(obj.Name, "certgen") {
						if resources.certgenRoleBinding != nil {
							panic("already read certgen RoleBinding from gateway API YAML")
						}
						resources.certgenRoleBinding = obj
					} else {
						if resources.roleBinding != nil {
							panic("already read general RoleBinding from gateway API YAML")
						}
						resources.roleBinding = obj
					}
				case "v1/Service":
					if resources.controllerService != nil {
						panic("already read controller Service from gateway API YAML")
					}
					resources.controllerService = &corev1.Service{}
					if err := yaml.Unmarshal([]byte(yml), resources.controllerService); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
				case "apps/v1/Deployment":
					if resources.controllerDeployment != nil {
						panic("already read controller Deployment from gateway API YAML")
					}
					resources.controllerDeployment = &appsv1.Deployment{}
					if err := yaml.Unmarshal([]byte(yml), resources.controllerDeployment); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
				case "batch/v1/Job":
					if resources.certgenJob != nil {
						panic("already read certgen Job from gateway API YAML")
					}
					resources.certgenJob = &batchv1.Job{}
					if err := yaml.Unmarshal([]byte(yml), resources.certgenJob); err != nil {
						panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
					}
				case "/":
					// No-op.  We see this when there is only a comment between
					// two "---" delimiters.
				default:
					panic(fmt.Sprintf("unhandled type %v", kindStr))
				}
			}

			// Check we now have all the resources that we expect.
			if resources.namespace == nil {
				panic("missing Namespace from gateway API YAML")
			}
			if len(resources.k8sCRDs) != 10 {
				panic(fmt.Sprintf("missing/extra k8s CRDs from gateway API YAML (%v != 10)", len(resources.k8sCRDs)))
			}
			if len(resources.envoyCRDs) != 7 {
				panic(fmt.Sprintf("missing/extra envoy CRDs from gateway API YAML (%v != 7)", len(resources.envoyCRDs)))
			}
			if resources.controllerServiceAccount == nil {
				panic("missing controller ServiceAccount from gateway API YAML")
			}
			if resources.envoyGatewayConfig == nil {
				panic("missing envoy-gateway-config from gateway API YAML")
			}
			if resources.clusterRole == nil {
				panic("missing ClusterRole from gateway API YAML")
			}
			if resources.clusterRoleBinding == nil {
				panic("missing ClusterRoleBinding from gateway API YAML")
			}
			if resources.role == nil {
				panic("missing general Role from gateway API YAML")
			}
			if resources.roleBinding == nil {
				panic("missing general RoleBinding from gateway API YAML")
			}
			if resources.leaderElectionRole == nil {
				panic("missing leader election Role from gateway API YAML")
			}
			if resources.leaderElectionRoleBinding == nil {
				panic("missing leader election RoleBinding from gateway API YAML")
			}
			if resources.controllerService == nil {
				panic("missing controller Service from gateway API YAML")
			}
			if resources.controllerDeployment == nil {
				panic("missing controller Deployment from gateway API YAML")
			}
			if resources.certgenServiceAccount == nil {
				panic("missing certgen ServiceAccount from gateway API YAML")
			}
			if resources.certgenRole == nil {
				panic("missing certgen Role from gateway API YAML")
			}
			if resources.certgenRoleBinding == nil {
				panic("missing certgen RoleBinding from gateway API YAML")
			}
			if resources.certgenJob == nil {
				panic("missing certgen Job from gateway API YAML")
			}

			// Further assumptions that we rely on below in `Objects()`.  We put these
			// here, instead of later, so that they are verified in UT.
			defaultGatewayImage, _ := components.GetReference(components.ComponentGatewayAPIEnvoyGateway, "", "", "", nil)
			defaultRatelimitImage, _ := components.GetReference(components.ComponentGatewayAPIEnvoyRatelimit, "", "", "", nil)
			if len(resources.controllerDeployment.Spec.Template.Spec.Containers) != 1 {
				panic("expected 1 container in deployment from gateway API YAML")
			}
			if resources.controllerDeployment.Spec.Template.Spec.Containers[0].Name != EnvoyGatewayDeploymentContainerName {
				panic("expected container name 'envoy-gateway' in deployment from gateway API YAML")
			}
			if resources.controllerDeployment.Spec.Template.Spec.Containers[0].Image != defaultGatewayImage {
				panic(fmt.Sprintf("unexpected image in deployment from gateway API YAML (%v != %v)",
					resources.controllerDeployment.Spec.Template.Spec.Containers[0].Image,
					defaultGatewayImage))
			}
			if len(resources.certgenJob.Spec.Template.Spec.Containers) != 1 {
				panic("expected 1 container in certgen job from gateway API YAML")
			}
			if resources.certgenJob.Spec.Template.Spec.Containers[0].Name != EnvoyGatewayJobContainerName {
				panic("expected container name 'envoy-gateway' in certgen job from gateway API YAML")
			}
			if resources.certgenJob.Spec.Template.Spec.Containers[0].Image != defaultGatewayImage {
				panic("unexpected image in certgen job from gateway API YAML")
			}
			if !strings.Contains(
				resources.envoyGatewayConfig.Data[EnvoyGatewayConfigKey],
				"image: "+defaultGatewayImage,
			) {
				panic("missing gateway image in envoy-gateway-config from gateway API YAML")
			}
			if !strings.Contains(
				resources.envoyGatewayConfig.Data[EnvoyGatewayConfigKey],
				"image: "+defaultRatelimitImage,
			) {
				panic("missing ratelimit image in envoy-gateway-config from gateway API YAML")
			}
		}
		return resources
	}
}

var GatewayAPIResources = GatewayAPIResourcesGetter()

func GatewayAPICRDs(log logr.Logger) []client.Object {
	resources := GatewayAPIResources()
	gatewayAPICRDs := make([]client.Object, 0, len(resources.k8sCRDs)+len(resources.envoyCRDs))
	for _, crd := range resources.k8sCRDs {
		gatewayAPICRDs = append(gatewayAPICRDs, crd.DeepCopyObject().(client.Object))
	}
	for _, crd := range resources.envoyCRDs {
		gatewayAPICRDs = append(gatewayAPICRDs, crd.DeepCopyObject().(client.Object))
	}

	return gatewayAPICRDs
}

type GatewayAPIImplementationConfig struct {
	Installation *operatorv1.InstallationSpec
	GatewayAPI   *operatorv1.GatewayAPI
	PullSecrets  []*corev1.Secret
}

type gatewayAPIImplementationComponent struct {
	cfg                 *GatewayAPIImplementationConfig
	envoyGatewayImage   string
	envoyRatelimitImage string
}

func GatewayAPIImplementationComponent(cfg *GatewayAPIImplementationConfig) Component {
	return &gatewayAPIImplementationComponent{
		cfg: cfg,
	}
}

func (pr *gatewayAPIImplementationComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := pr.cfg.Installation.Registry
	path := pr.cfg.Installation.ImagePath
	prefix := pr.cfg.Installation.ImagePrefix

	var err error
	pr.envoyGatewayImage, err = components.GetReference(components.ComponentGatewayAPIEnvoyGateway, reg, path, prefix, is)
	if err != nil {
		return err
	}
	pr.envoyRatelimitImage, err = components.GetReference(components.ComponentGatewayAPIEnvoyRatelimit, reg, path, prefix, is)
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
	resources := GatewayAPIResources()

	// List all the non-CRD resources, read from YAML, that we can apply without any tweaking.
	objs := []client.Object{
		resources.namespace,
		resources.controllerServiceAccount,
		resources.clusterRole,
		resources.clusterRoleBinding,
		resources.role,
		resources.roleBinding,
		resources.leaderElectionRole,
		resources.leaderElectionRoleBinding,
		resources.controllerService,
		resources.certgenRole,
		resources.certgenRoleBinding,
	}

	// Deep-copy all of those, so as not to inadvertently modify the cache inside
	// `GatewayAPIResourcesGetter`.
	for i := range objs {
		objs[i] = objs[i].DeepCopyObject().(client.Object)
	}

	// Substitute possibly modified image names into the envoy-gateway-config.
	envoyGatewayConfig := resources.envoyGatewayConfig.DeepCopyObject().(*corev1.ConfigMap)
	data := envoyGatewayConfig.Data[EnvoyGatewayConfigKey]
	defaultRatelimitImage, _ := components.GetReference(components.ComponentGatewayAPIEnvoyRatelimit, "", "", "", nil)
	data = strings.ReplaceAll(data, defaultRatelimitImage, pr.envoyRatelimitImage)
	defaultGatewayImage, _ := components.GetReference(components.ComponentGatewayAPIEnvoyGateway, "", "", "", nil)
	data = strings.ReplaceAll(data, defaultGatewayImage, pr.envoyGatewayImage)
	envoyGatewayConfig.Data[EnvoyGatewayConfigKey] = data

	// TODO: I guess we might need to add in pull secrets here, which is more hacky when dealing
	// only with the text representation.

	objs = append(objs, envoyGatewayConfig)

	// Deep copy the controller deployment,
	controllerDeployment := resources.controllerDeployment.DeepCopyObject().(*appsv1.Deployment)

	// Substitute possibly modified gateway image name.
	controllerDeployment.Spec.Template.Spec.Containers[0].Image = pr.envoyGatewayImage

	// Reference additional pull secrets.
	controllerDeployment.Spec.Template.Spec.ImagePullSecrets = append(
		controllerDeployment.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(pr.cfg.PullSecrets)...)

	// Add a k8s-app label that we can use to provide API access for the controller.
	controllerDeployment.Spec.Template.Labels["k8s-app"] = GatewayControllerLabel

	// Apply customizations from the GatewayControllerDeployment field of the GatewayAPI CR.
	rcomp.ApplyDeploymentOverrides(controllerDeployment, pr.cfg.GatewayAPI.Spec.GatewayControllerDeployment)

	objs = append(objs, controllerDeployment)

	// Deep copy the certgen job,
	certgenJob := resources.certgenJob.DeepCopyObject().(*batchv1.Job)

	// Substitute possibly modified gateway image name.
	certgenJob.Spec.Template.Spec.Containers[0].Image = pr.envoyGatewayImage

	// Reference additional pull secrets.
	certgenJob.Spec.Template.Spec.ImagePullSecrets = append(
		certgenJob.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(pr.cfg.PullSecrets)...)

	// Apply customizations from the GatewayCertgenJob field of the GatewayAPI CR.
	rcomp.ApplyJobOverrides(certgenJob, pr.cfg.GatewayAPI.Spec.GatewayCertgenJob)

	objs = append(objs, certgenJob)

	// Network policy to allow the gateway controller to access the Kubernetes API server.
	objs = append(objs, pr.allowGatewayControllerToKubeAPI(resources.namespace.Name))

	// Network policy for traffic through deployed gateways.  Our GatewayAPI support provisions
	// gateway deployments in the calico-system namespace, which an application-specific
	// customer team would not normally have any access to.  Therefore we have to program
	// network policy to allow traffic through gateways ourselves.
	objs = append(objs, pr.allowGatewayTraffic(resources.namespace.Name))

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(resources.namespace.Name, pr.cfg.PullSecrets...)...)...)

	return objs, nil
}

func (pr *gatewayAPIImplementationComponent) allowGatewayControllerToKubeAPI(namespace string) *v3.NetworkPolicy {
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkpolicy.TigeraComponentPolicyPrefix + "gateway-controller-api-access",
			Namespace: namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(GatewayControllerLabel),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:      v3.Allow,
					Protocol:    &networkpolicy.TCPProtocol,
					Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
				},
			},
		},
	}
}

func (pr *gatewayAPIImplementationComponent) allowGatewayTraffic(namespace string) *v3.NetworkPolicy {
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkpolicy.TigeraComponentPolicyPrefix + "gateway-traffic",
			Namespace: namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order: &networkpolicy.HighPrecedenceOrder,
			Tier:  networkpolicy.TigeraComponentTierName,
			Selector: strings.Join(
				[]string{
					// These are the labels that the Envoy gateway controller
					// puts on a gateway pod.
					"app.kubernetes.io/component == 'proxy'",
					"app.kubernetes.io/managed-by == 'envoy-gateway'",
					"app.kubernetes.io/name == 'envoy'",
				},
				" && ",
			),
			Types: []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{{
				Action: v3.Allow,
			}},
			Egress: []v3.Rule{{
				Action: v3.Allow,
			}},
		},
	}
}
