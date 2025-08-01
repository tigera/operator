// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/set"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
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
// helm chart (as of the version indicated by `ENVOY_GATEWAY_VERSION` in `Makefile`).
type gatewayAPIResources struct {
	namespace                 *corev1.Namespace
	k8sCRDs                   []*apiextenv1.CustomResourceDefinition
	envoyCRDs                 []*apiextenv1.CustomResourceDefinition
	controllerServiceAccount  *corev1.ServiceAccount
	envoyGatewayConfigMap     *corev1.ConfigMap
	envoyGatewayConfig        *envoyapi.EnvoyGateway
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

var (
	// logger gateway name and namespace are set from the k8s downward api pod metadata.
	GatewayNameEnvVar = corev1.EnvVar{
		Name: "LOGGER_GATEWAY_NAME",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.name",
			},
		},
	}
	GatewayNamespaceEnvVar = corev1.EnvVar{
		Name: "LOGGER_GATEWAY_NAMESPACE",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.namespace",
			},
		},
	}
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
					if resources.envoyGatewayConfigMap != nil {
						panic("already read envoy-gateway-config ConfigMap from gateway API YAML")
					}
					resources.envoyGatewayConfigMap = obj
					resources.envoyGatewayConfig = &envoyapi.EnvoyGateway{}
					if err := yaml.Unmarshal([]byte(obj.Data[EnvoyGatewayConfigKey]), resources.envoyGatewayConfig); err != nil {
						panic("can't unmarshal EnvoyGateway from envoy-gateway-config ConfigMap from gateway API YAML")
					}
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
			if len(resources.envoyCRDs) != 8 {
				panic(fmt.Sprintf("missing/extra envoy CRDs from gateway API YAML (%v != 8)", len(resources.envoyCRDs)))
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
			if len(resources.controllerDeployment.Spec.Template.Spec.Containers) != 1 {
				panic("expected 1 container in deployment from gateway API YAML")
			}
			if resources.controllerDeployment.Spec.Template.Spec.Containers[0].Name != EnvoyGatewayDeploymentContainerName {
				panic("expected container name 'envoy-gateway' in deployment from gateway API YAML")
			}
			if len(resources.certgenJob.Spec.Template.Spec.Containers) != 1 {
				panic("expected 1 container in certgen job from gateway API YAML")
			}
			if resources.certgenJob.Spec.Template.Spec.Containers[0].Name != EnvoyGatewayJobContainerName {
				panic("expected container name 'envoy-gateway' in certgen job from gateway API YAML")
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
	Installation          *operatorv1.InstallationSpec
	GatewayAPI            *operatorv1.GatewayAPI
	PullSecrets           []*corev1.Secret
	CustomEnvoyGateway    *envoyapi.EnvoyGateway
	CustomEnvoyProxies    map[string]*envoyapi.EnvoyProxy
	CurrentGatewayClasses set.Set[string]
}

type gatewayAPIImplementationComponent struct {
	cfg                 *GatewayAPIImplementationConfig
	envoyGatewayImage   string
	envoyProxyImage     string
	envoyRatelimitImage string
	wafHTTPFilterImage  string
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
	if pr.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		pr.envoyGatewayImage, err = components.GetReference(components.ComponentGatewayAPIEnvoyGateway, reg, path, prefix, is)
		if err != nil {
			return err
		}
		pr.envoyProxyImage, err = components.GetReference(components.ComponentGatewayAPIEnvoyProxy, reg, path, prefix, is)
		if err != nil {
			return err
		}
		pr.envoyRatelimitImage, err = components.GetReference(components.ComponentGatewayAPIEnvoyRatelimit, reg, path, prefix, is)
		if err != nil {
			return err
		}
		pr.wafHTTPFilterImage, err = components.GetReference(components.ComponentWAFHTTPFilter, reg, path, prefix, is)
		if err != nil {
			return err
		}
	} else {
		pr.envoyGatewayImage, err = components.GetReference(components.ComponentCalicoEnvoyGateway, reg, path, prefix, is)
		if err != nil {
			return err
		}
		pr.envoyProxyImage, err = components.GetReference(components.ComponentCalicoEnvoyProxy, reg, path, prefix, is)
		if err != nil {
			return err
		}
		pr.envoyRatelimitImage, err = components.GetReference(components.ComponentCalicoEnvoyRatelimit, reg, path, prefix, is)
		if err != nil {
			return err
		}
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

	// First create the namespace.  We take the name from the read resources, but otherwise
	// follow our own pattern for namespace creation.
	objs := []client.Object{
		CreateNamespace(
			resources.namespace.Name,
			pr.cfg.Installation.KubernetesProvider,
			PSSPrivileged, // Needed for HostPath volume to write logs to
			pr.cfg.Installation.Azure,
		),
	}

	// Create role binding to allow creating secrets in our namespace.
	objs = append(objs, CreateOperatorSecretsRoleBinding(resources.namespace.Name))

	// Add pull secrets (inferred from the Installation resource).
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(resources.namespace.Name, pr.cfg.PullSecrets...)...)...)

	// Add all the non-CRD resources, read from YAML, that we can apply without any tweaking.
	for _, resource := range []client.Object{
		resources.controllerServiceAccount,
		resources.clusterRole,
		resources.clusterRoleBinding,
		resources.role,
		resources.roleBinding,
		resources.leaderElectionRole,
		resources.leaderElectionRoleBinding,
		resources.controllerService,
		resources.certgenServiceAccount,
		resources.certgenRole,
		resources.certgenRoleBinding,
	} {
		// But deep-copy each one so as not to inadvertently modify the cache inside
		// `GatewayAPIResourcesGetter`.
		objs = append(objs, resource.DeepCopyObject().(client.Object))
	}

	// Prepare EnvoyGateway config, either from upstream or from a custom EnvoyGatewayConfigRef
	// provided by the user.
	envoyGatewayConfig := pr.cfg.CustomEnvoyGateway
	if envoyGatewayConfig == nil {
		// In the upstream case, take a deepcopy of the default to make sure we don't
		// accidentally modify the config loaded at start of day.  (In the custom case we
		// don't need to do this because the next Reconcile will read the custom resource
		// again from scratch.)
		envoyGatewayConfig = resources.envoyGatewayConfig.DeepCopyObject().(*envoyapi.EnvoyGateway)
	}

	// Ensure the minimal structure that we require for the following customizations.
	if envoyGatewayConfig.Provider == nil {
		envoyGatewayConfig.Provider = &envoyapi.EnvoyGatewayProvider{}
	}
	envoyGatewayConfig.Provider.Type = envoyapi.ProviderTypeKubernetes
	if envoyGatewayConfig.Provider.Kubernetes == nil {
		envoyGatewayConfig.Provider.Kubernetes = &envoyapi.EnvoyGatewayKubernetesProvider{}
	}
	if envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment == nil {
		envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment = &envoyapi.KubernetesDeploymentSpec{}
	}
	if envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod == nil {
		envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod = &envoyapi.KubernetesPodSpec{}
	}
	if envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container == nil {
		envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container = &envoyapi.KubernetesContainerSpec{}
	}
	if envoyGatewayConfig.Provider.Kubernetes.ShutdownManager == nil {
		envoyGatewayConfig.Provider.Kubernetes.ShutdownManager = &envoyapi.ShutdownManager{}
	}
	if envoyGatewayConfig.ExtensionAPIs == nil {
		envoyGatewayConfig.ExtensionAPIs = &envoyapi.ExtensionAPISettings{}
	}
	if envoyGatewayConfig.Gateway == nil {
		envoyGatewayConfig.Gateway = &envoyapi.Gateway{}
	}
	if envoyGatewayConfig.Gateway.ControllerName == "" {
		envoyGatewayConfig.Gateway.ControllerName = resources.envoyGatewayConfig.Gateway.ControllerName
	}

	// Substitute possibly modified image names.
	envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container.Image = &pr.envoyRatelimitImage
	envoyGatewayConfig.Provider.Kubernetes.ShutdownManager.Image = &pr.envoyGatewayImage

	// Add in pull secrets.  (Note that these are at the pod level and cover both the
	// "ShutdownManager" and "RateLimit" images.)
	envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod.ImagePullSecrets = secret.GetReferenceList(pr.cfg.PullSecrets)

	// Enable extension APIs.
	envoyGatewayConfig.ExtensionAPIs.EnableBackend = true
	envoyGatewayConfig.ExtensionAPIs.EnableEnvoyPatchPolicy = true

	// Rebuild the ConfigMap with those changes.
	envoyGatewayConfigMap := resources.envoyGatewayConfigMap.DeepCopyObject().(*corev1.ConfigMap)
	if bytes, err := yaml.Marshal(*envoyGatewayConfig); err == nil {
		envoyGatewayConfigMap.Data[EnvoyGatewayConfigKey] = string(bytes)
	} else {
		panic(fmt.Sprintf("couldn't marshal EnvoyGateway to YAML: %v", err))
	}

	objs = append(objs, envoyGatewayConfigMap)

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

	// Provision GatewayClasses.
	for i := range pr.cfg.GatewayAPI.Spec.GatewayClasses {
		className := pr.cfg.GatewayAPI.Spec.GatewayClasses[i].Name

		// The EnvoyProxy config.
		proxyConfig := pr.envoyProxyConfig(className, pr.cfg.CustomEnvoyProxies[className], &(pr.cfg.GatewayAPI.Spec.GatewayClasses[i]))
		objs = append(objs, proxyConfig)

		// The GatewayClass using that EnvoyProxy config.
		objs = append(objs, pr.gatewayClass(className, envoyGatewayConfig.Gateway.ControllerName, proxyConfig))

		if pr.cfg.CurrentGatewayClasses.Has(className) {
			pr.cfg.CurrentGatewayClasses.Delete(className)
		}
	}

	objsToDelete := []client.Object(nil)
	for _, gcName := range pr.cfg.CurrentGatewayClasses.UnsortedList() {
		log.V(1).Info("Will delete GatewayClass and EnvoyProxy", "name", gcName)
		objsToDelete = append(objsToDelete,
			&gapi.GatewayClass{
				TypeMeta: metav1.TypeMeta{
					Kind:       "GatewayClass",
					APIVersion: "gateway.networking.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: gcName,
				},
			},
			&envoyapi.EnvoyProxy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "EnvoyProxy",
					APIVersion: "gateway.envoyproxy.io/v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      gcName,
					Namespace: "tigera-gateway",
				},
			},
		)
	}

	log.V(1).Info("GatewayAPI rendering", "num_current", len(objs), "num_delete", len(objsToDelete))
	return objs, objsToDelete
}

func (pr *gatewayAPIImplementationComponent) envoyProxyConfig(className string, envoyProxy *envoyapi.EnvoyProxy, classSpec *operatorv1.GatewayClassSpec) *envoyapi.EnvoyProxy {
	// Ensure the minimal structure that we need for basic correctness and for the following
	// customizations.  Note, we always create the running EnvoyProxy in our own namespace, even
	// if it's based on a custom resource from another namespace.
	if envoyProxy == nil {
		envoyProxy = &envoyapi.EnvoyProxy{}
	} else {
		// Copy over the important fields from the custom supplied, specifically avoiding
		// the fields that must NOT be set when first creating an object.
		envoyProxy = &envoyapi.EnvoyProxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:        envoyProxy.Name,
				Labels:      envoyProxy.Labels,
				Annotations: envoyProxy.Annotations,
			},
			Spec: envoyProxy.Spec,
		}
	}
	if envoyProxy.Kind == "" {
		envoyProxy.Kind = "EnvoyProxy"
	}
	if envoyProxy.APIVersion == "" {
		envoyProxy.APIVersion = "gateway.envoyproxy.io/v1alpha1"
	}
	envoyProxy.ObjectMeta.Name = className
	envoyProxy.ObjectMeta.Namespace = "tigera-gateway"
	if envoyProxy.Spec.Provider == nil {
		envoyProxy.Spec.Provider = &envoyapi.EnvoyProxyProvider{}
	}
	envoyProxy.Spec.Provider.Type = envoyapi.ProviderTypeKubernetes
	if envoyProxy.Spec.Provider.Kubernetes == nil {
		envoyProxy.Spec.Provider.Kubernetes = &envoyapi.EnvoyProxyKubernetesProvider{}
	}

	// If the EnvoyProxy itself doesn't already indicate DaemonSet or Deployment, and our
	// customization structs indicate deploying as a DaemonSet, set that up.
	if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet == nil && envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment == nil {
		if classSpec.GatewayKind != nil {
			if *classSpec.GatewayKind == operatorv1.GatewayKindDaemonSet {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet = &envoyapi.KubernetesDaemonSetSpec{}
			}
		}
	}

	// Add EnvoyProxy config that will apply our image configuration, pull secrets and overrides
	// to gateway deployments.
	if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet != nil {
		// Custom EnvoyProxy indicates deployment as a DaemonSet.
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod = &envoyapi.KubernetesPodSpec{}
		}
		envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.ImagePullSecrets = secret.GetReferenceList(pr.cfg.PullSecrets)
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container = &envoyapi.KubernetesContainerSpec{}
		}
		envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container.Image = &pr.envoyProxyImage
	} else {
		// Deployment as a Deployment.
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment = &envoyapi.KubernetesDeploymentSpec{}
		}
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod = &envoyapi.KubernetesPodSpec{}
		}
		envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.ImagePullSecrets = secret.GetReferenceList(pr.cfg.PullSecrets)
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container == nil {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container = &envoyapi.KubernetesContainerSpec{}
		}
		envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Image = &pr.envoyProxyImage
	}

	// Apply overrides.
	if envoyProxy.Spec.Provider.Kubernetes.EnvoyDaemonSet != nil {
		rcomp.ApplyEnvoyProxyOverrides(envoyProxy, classSpec.GatewayDaemonSet)
	} else {
		rcomp.ApplyEnvoyProxyOverrides(envoyProxy, classSpec.GatewayDeployment)
	}
	applyEnvoyProxyServiceOverrides(envoyProxy, classSpec.GatewayService)

	// Setup WAF HTTP Filter on Enterprise.
	if pr.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// The WAF HTTP filter is not supported when the envoy proxy is deployed as a DaemonSet
		// as there is no support for init containers in a DaemonSet.
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment != nil {
			// Add or update the Init Container to the deployment
			wafHTTPFilter := corev1.Container{
				Name:  "waf-http-filter",
				Image: pr.wafHTTPFilterImage,
				Args: []string{
					"-logFileDirectory",
					"/var/log/calico/waf",
					"-logFileName",
					"waf.log",
					"-socketPath",
					"/var/run/waf-http-filter/extproc.sock",
				},
				RestartPolicy: ptr.ToPtr[corev1.ContainerRestartPolicy](corev1.ContainerRestartPolicyAlways),
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "waf-http-filter",
						MountPath: "/var/run/waf-http-filter",
					},
					{
						Name:      "var-log-calico",
						MountPath: "/var/log/calico",
					},
				},
				Env: []corev1.EnvVar{
					GatewayNameEnvVar,
					GatewayNamespaceEnvVar,
				},
				SecurityContext: securitycontext.NewRootContext(true),
			}
			hasWAFHTTPFilter := false
			for i, initContainer := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers {
				if initContainer.Name == wafHTTPFilter.Name {
					hasWAFHTTPFilter = true
					// Handle update
					if initContainer.Image != wafHTTPFilter.Image {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i] = wafHTTPFilter
					}
				}
			}
			if !hasWAFHTTPFilter {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers, wafHTTPFilter)
			}

			// Add or update Container volume mount
			socketVolumeMount := corev1.VolumeMount{
				Name:      "waf-http-filter",
				MountPath: "/var/run/waf-http-filter",
			}
			hasSocketVolumeMount := false
			for i, volumeMount := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts {
				if volumeMount.Name == socketVolumeMount.Name {
					hasSocketVolumeMount = true
					if volumeMount.MountPath != socketVolumeMount.MountPath {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts[i] = socketVolumeMount
					}
				}
			}
			if !hasSocketVolumeMount {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts, socketVolumeMount)
			}

			// Add or update Pod volumes
			logsVolume := corev1.Volume{
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/log/calico",
						Type: ptr.ToPtr(corev1.HostPathDirectoryOrCreate),
					},
				},
				Name: "var-log-calico",
			}
			socketVolume := corev1.Volume{
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
				Name: "waf-http-filter",
			}
			hasLogsVolume := false
			hasSocketVolume := false
			for i, volume := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes {
				if volume.Name == logsVolume.Name {
					hasLogsVolume = true
					// Handle update
					if volume.VolumeSource.HostPath.Path != logsVolume.VolumeSource.HostPath.Path || volume.VolumeSource.HostPath.Type != logsVolume.VolumeSource.HostPath.Type {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes[i] = logsVolume
					}
				}
				if volume.Name == socketVolume.Name {
					hasSocketVolume = true
					if volume.VolumeSource.EmptyDir != socketVolume.VolumeSource.EmptyDir {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes[i] = socketVolume
					}
				}
			}
			if !hasLogsVolume {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes, logsVolume)
			}
			if !hasSocketVolume {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes, socketVolume)
			}
		}
	}

	return envoyProxy
}

func (pr *gatewayAPIImplementationComponent) gatewayClass(className, controllerName string, proxyConfig *envoyapi.EnvoyProxy) *gapi.GatewayClass {
	// Provision a GatewayClass that references the EnvoyProxy config and the controllerName
	// that the gateway controller expects.
	return &gapi.GatewayClass{
		TypeMeta: metav1.TypeMeta{Kind: "GatewayClass", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      className,
			Namespace: "tigera-gateway",
		},
		Spec: gapi.GatewayClassSpec{
			ControllerName: gapi.GatewayController(controllerName),
			ParametersRef: &gapi.ParametersReference{
				Group:     gapi.Group(proxyConfig.GroupVersionKind().Group),
				Kind:      gapi.Kind(proxyConfig.Kind),
				Name:      proxyConfig.Name,
				Namespace: (*gapi.Namespace)(&proxyConfig.Namespace),
			},
		},
	}
}

type GatewayAPIImplementationConfigInterface interface {
	GetConfig() *GatewayAPIImplementationConfig
}

func (pr *gatewayAPIImplementationComponent) GetConfig() *GatewayAPIImplementationConfig {
	return pr.cfg
}

// applyEnvoyProxyServiceOverrides applies the overrides to the given EnvoyProxy.
// Note: overrides must not be nil pointer.
func applyEnvoyProxyServiceOverrides(ep *envoyapi.EnvoyProxy, overrides *operatorv1.GatewayService) {
	if overrides != nil {
		if ep.Spec.Provider.Kubernetes.EnvoyService == nil {
			ep.Spec.Provider.Kubernetes.EnvoyService = &envoyapi.KubernetesServiceSpec{}
		}
		if overrides.Metadata != nil {
			if len(overrides.Metadata.Labels) > 0 {
				ep.Spec.Provider.Kubernetes.EnvoyService.Labels = common.MapExistsOrInitialize(ep.Spec.Provider.Kubernetes.EnvoyService.Labels)
				common.MergeMaps(overrides.Metadata.Labels, ep.Spec.Provider.Kubernetes.EnvoyService.Labels)
			}
			if len(overrides.Metadata.Annotations) > 0 {
				ep.Spec.Provider.Kubernetes.EnvoyService.Annotations = common.MapExistsOrInitialize(ep.Spec.Provider.Kubernetes.EnvoyService.Annotations)
				common.MergeMaps(overrides.Metadata.Annotations, ep.Spec.Provider.Kubernetes.EnvoyService.Annotations)
			}
		}
		if overrides.Spec != nil {
			if overrides.Spec.LoadBalancerClass != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerClass = overrides.Spec.LoadBalancerClass
			}
			if overrides.Spec.AllocateLoadBalancerNodePorts != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.AllocateLoadBalancerNodePorts = overrides.Spec.AllocateLoadBalancerNodePorts
			}
			if overrides.Spec.LoadBalancerSourceRanges != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerSourceRanges = overrides.Spec.LoadBalancerSourceRanges
			}
			if overrides.Spec.LoadBalancerIP != nil {
				ep.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerIP = overrides.Spec.LoadBalancerIP
			}
		}
	}
}
