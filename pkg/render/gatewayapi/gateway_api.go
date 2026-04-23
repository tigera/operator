// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package gatewayapi

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/utils/ptr"
	"k8s.io/utils/set"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

var (
	//go:embed gateway-helm.tgz
	gatewayHelmChart []byte

	AccessLogType envoyapi.ProxyAccessLogType = "Route"

	log = logf.Log.WithName("gateway_api")
)

// Legacy* name the tigera-gateway install. Slated for deprecation; to retire
// it, drop these constants with legacyObjects and its callers.
const (
	LegacyControllerNamespace = "tigera-gateway"
	LegacyReleaseName         = "tigera-gateway-api"
	LegacyControllerName      = "gateway.envoyproxy.io/gatewayclass-controller"
	LegacyGatewayClassName    = "tigera-gateway-class"

	// Namespaced* name the calico-system install: controller there,
	// deploy.type=GatewayNamespace, proxies in each Gateway's own namespace.
	NamespacedReleaseName      = "tigera-gateway-api-ns"
	NamespacedControllerName   = "gateway.envoyproxy.io/gatewayclass-controller-ns"
	NamespacedGatewayClassName = "tigera-gateway-class-ns"

	ControllerPolicyName       = networkpolicy.CalicoComponentPolicyPrefix + "envoy-gateway"
	EnvoyGatewayPolicySelector = "app.kubernetes.io/name == 'gateway-helm' || app == 'certgen'"
)

// gatewayAPIResources defines all of the resources that we expect to read from the rendered Envoy Gateway
// helm chart (as of the version indicated by `ENVOY_GATEWAY_VERSION` in `Makefile`).
type gatewayAPIResources struct {
	k8sCRDs                       []*apiextenv1.CustomResourceDefinition
	envoyCRDs                     []*apiextenv1.CustomResourceDefinition
	controllerServiceAccount      *corev1.ServiceAccount
	envoyGatewayConfigMap         *corev1.ConfigMap
	envoyGatewayConfig            *envoyapi.EnvoyGateway
	clusterRoles                  []*rbacv1.ClusterRole
	clusterRoleBindings           []*rbacv1.ClusterRoleBinding
	role                          *rbacv1.Role
	roleBinding                   *rbacv1.RoleBinding
	leaderElectionRole            *rbacv1.Role
	leaderElectionRoleBinding     *rbacv1.RoleBinding
	controllerService             *corev1.Service
	controllerDeployment          *appsv1.Deployment
	certgenServiceAccount         *corev1.ServiceAccount
	certgenRole                   *rbacv1.Role
	certgenRoleBinding            *rbacv1.RoleBinding
	certgenJob                    *batchv1.Job
	mutatingWebhookConfigurations []*admissionregv1.MutatingWebhookConfiguration
}

const (
	GatewayAPIName                      = "gateway-api"
	GatewayControllerLabel              = GatewayAPIName + "-controller"
	EnvoyGatewayConfigName              = "envoy-gateway-config"
	EnvoyGatewayConfigKey               = "envoy-gateway.yaml"
	EnvoyGatewayDeploymentContainerName = "envoy-gateway"
	EnvoyGatewayJobContainerName        = "envoy-gateway-certgen"
	wafFilterName                       = "waf-http-filter"
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

	// Owning Gateway name and namespace are exposed via pod labels set by EnvoyProxy.
	// These allow the l7-log-collector to know which Gateway it is collecting logs for
	// without needing to query the Kubernetes API.
	OwningGatewayNameEnvVar = corev1.EnvVar{
		Name: "OWNING_GATEWAY_NAME",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.labels['gateway.envoyproxy.io/owning-gateway-name']",
			},
		},
	}
	OwningGatewayNamespaceEnvVar = corev1.EnvVar{
		Name: "OWNING_GATEWAY_NAMESPACE",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.labels['gateway.envoyproxy.io/owning-gateway-namespace']",
			},
		},
	}
)

// helmOpts represents the helm values passed when rendering the Envoy Gateway chart.
type helmOpts struct {
	Config *helmConfig `json:"config,omitempty"`
}

type helmConfig struct {
	EnvoyGateway *helmEnvoyGateway `json:"envoyGateway,omitempty"`
}

type helmEnvoyGateway struct {
	Gateway  *helmGateway  `json:"gateway,omitempty"`
	Provider *helmProvider `json:"provider,omitempty"`
}

type helmGateway struct {
	ControllerName string `json:"controllerName,omitempty"`
}

type helmProvider struct {
	Kubernetes *helmKubernetes `json:"kubernetes,omitempty"`
}

type helmKubernetes struct {
	Deploy *helmDeploy `json:"deploy,omitempty"`
}

type helmDeploy struct {
	Type string `json:"type,omitempty"`
}

func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// isReservedOperatorNamespace reports whether core Installation already owns
// tigera-operator-secrets / tigera-pull-secret in ns (deleting ours would wipe them).
func isReservedOperatorNamespace(ns string) bool {
	return ns == common.CalicoNamespace || ns == common.OperatorNamespace()
}

// The operator only ever does two chart renders. The chart output is
// deterministic, so each is cached by its own sync.Once on first use.
// Callers must deep-copy any object they intend to mutate.
var (
	legacyChartOnce    sync.Once
	legacyChartResults *gatewayAPIResources
	legacyChartErr     error

	namespacedChartOnce    sync.Once
	namespacedChartResults *gatewayAPIResources
	namespacedChartErr     error
)

func legacyChart(scheme *runtime.Scheme) (*gatewayAPIResources, error) {
	legacyChartOnce.Do(func() {
		legacyChartResults, legacyChartErr = renderChart(scheme, LegacyReleaseName, LegacyControllerNamespace, "", "")
	})
	return legacyChartResults, legacyChartErr
}

func namespacedChart(scheme *runtime.Scheme) (*gatewayAPIResources, error) {
	namespacedChartOnce.Do(func() {
		namespacedChartResults, namespacedChartErr = renderChart(scheme, NamespacedReleaseName, common.CalicoNamespace, NamespacedControllerName, "GatewayNamespace")
	})
	return namespacedChartResults, namespacedChartErr
}

// renderChart renders the embedded Envoy Gateway helm chart using the Helm SDK.
// releaseName + namespace go to Helm as Release.Name / Release.Namespace. controllerName
// overrides config.envoyGateway.gateway.controllerName when non-empty. deployType
// overrides config.envoyGateway.provider.kubernetes.deploy.type when non-empty.
func renderChart(scheme *runtime.Scheme, releaseName, namespace, controllerName, deployType string) (*gatewayAPIResources, error) {
	chart, err := loader.LoadArchive(bytes.NewReader(gatewayHelmChart))
	if err != nil {
		return nil, fmt.Errorf("failed to load gateway-helm chart: %w", err)
	}

	actionConfig := new(action.Configuration)
	helmClient := action.NewInstall(actionConfig)
	helmClient.DryRun = true
	helmClient.ClientOnly = true
	helmClient.IncludeCRDs = true
	helmClient.Namespace = namespace
	helmClient.ReleaseName = releaseName

	opts := &helmOpts{}
	if controllerName != "" || deployType != "" {
		eg := &helmEnvoyGateway{}
		if controllerName != "" {
			eg.Gateway = &helmGateway{ControllerName: controllerName}
		}
		if deployType != "" {
			eg.Provider = &helmProvider{
				Kubernetes: &helmKubernetes{
					Deploy: &helmDeploy{Type: deployType},
				},
			}
		}
		opts.Config = &helmConfig{EnvoyGateway: eg}
	}

	values, err := toMap(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to convert helm values: %w", err)
	}

	rel, err := helmClient.Run(chart, values)
	if err != nil {
		return nil, fmt.Errorf("failed to render gateway-helm chart: %w", err)
	}

	// Combine the main manifest with hook manifests (certgen, webhooks, etc.).
	var allManifests strings.Builder
	allManifests.WriteString(rel.Manifest)
	for _, hook := range rel.Hooks {
		allManifests.WriteString("\n---\n")
		allManifests.WriteString(hook.Manifest)
	}

	resources, err := parseManifest(scheme, allManifests.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse rendered manifest: %w", err)
	}
	return resources, nil
}

// parseManifest parses the rendered helm manifest into typed gatewayAPIResources.
func parseManifest(scheme *runtime.Scheme, manifest string) (*gatewayAPIResources, error) {
	codecs := serializer.NewCodecFactory(scheme)
	universalDeserializer := codecs.UniversalDeserializer()

	resources := &gatewayAPIResources{}
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(manifest)), 4096)

	for {
		var rawObj runtime.RawExtension
		if err := decoder.Decode(&rawObj); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error decoding manifest document: %w", err)
		}
		if len(rawObj.Raw) == 0 {
			continue
		}

		obj, _, err := universalDeserializer.Decode(rawObj.Raw, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("error deserializing object: %w", err)
		}

		clientObj, ok := obj.(client.Object)
		if !ok {
			return nil, fmt.Errorf("object does not implement client.Object: %T", obj)
		}

		switch typedObj := clientObj.(type) {
		case *apiextenv1.CustomResourceDefinition:
			if strings.HasSuffix(typedObj.Name, ".gateway.networking.k8s.io") || strings.HasSuffix(typedObj.Name, ".gateway.networking.x-k8s.io") {
				resources.k8sCRDs = append(resources.k8sCRDs, typedObj)
			} else if strings.HasSuffix(typedObj.Name, ".gateway.envoyproxy.io") {
				resources.envoyCRDs = append(resources.envoyCRDs, typedObj)
			}
		case *corev1.ServiceAccount:
			if strings.HasSuffix(typedObj.Name, "certgen") {
				resources.certgenServiceAccount = typedObj
			} else {
				resources.controllerServiceAccount = typedObj
			}
		case *corev1.ConfigMap:
			if typedObj.Name == EnvoyGatewayConfigName {
				resources.envoyGatewayConfigMap = typedObj
				resources.envoyGatewayConfig = &envoyapi.EnvoyGateway{}
				if err := yaml.Unmarshal([]byte(typedObj.Data[EnvoyGatewayConfigKey]), resources.envoyGatewayConfig); err != nil {
					return nil, fmt.Errorf("can't unmarshal EnvoyGateway from ConfigMap: %w", err)
				}
			}
		case *rbacv1.ClusterRole:
			resources.clusterRoles = append(resources.clusterRoles, typedObj)
		case *rbacv1.ClusterRoleBinding:
			resources.clusterRoleBindings = append(resources.clusterRoleBindings, typedObj)
		case *rbacv1.Role:
			if strings.HasSuffix(typedObj.Name, "leader-election-role") {
				resources.leaderElectionRole = typedObj
			} else if strings.HasSuffix(typedObj.Name, "certgen") {
				resources.certgenRole = typedObj
			} else {
				resources.role = typedObj
			}
		case *rbacv1.RoleBinding:
			if strings.HasSuffix(typedObj.Name, "leader-election-rolebinding") {
				resources.leaderElectionRoleBinding = typedObj
			} else if strings.HasSuffix(typedObj.Name, "certgen") {
				resources.certgenRoleBinding = typedObj
			} else {
				resources.roleBinding = typedObj
			}
		case *corev1.Service:
			resources.controllerService = typedObj
		case *appsv1.Deployment:
			resources.controllerDeployment = typedObj
		case *batchv1.Job:
			resources.certgenJob = typedObj
		case *admissionregv1.MutatingWebhookConfiguration:
			resources.mutatingWebhookConfigurations = append(resources.mutatingWebhookConfigurations, typedObj)
		case *corev1.Namespace:
			// The chart may render a namespace; we create our own in Objects(), so skip it.
		default:
			// Skip unknown types.
		}
	}

	return resources, nil
}

func K8SGatewayAPICRDs(provider operatorv1.Provider, scheme *runtime.Scheme) (essentialCRDs, optionalCRDs []client.Object, err error) {
	resources, err := legacyChart(scheme)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to render chart for CRDs: %w", err)
	}
	for _, crd := range resources.k8sCRDs {
		if provider.IsOpenShift() {
			// OpenShift 4.19+ restricts the Gateway CRDs that we can install, so report
			// that only some of them are essential.
			switch strings.TrimSuffix(crd.Name, ".gateway.networking.k8s.io") {
			case "gatewayclasses", "gateways", "httproutes", "referencegrants":
				essentialCRDs = append(essentialCRDs, crd.DeepCopyObject().(client.Object))
			default:
				optionalCRDs = append(optionalCRDs, crd.DeepCopyObject().(client.Object))
			}
		} else {
			// Other platforms do not restrict Gateway CRDs, so report them all as
			// essential.
			essentialCRDs = append(essentialCRDs, crd.DeepCopyObject().(client.Object))
		}
	}
	return
}

// GatewayAPICRDs returns the k8s GatewayAPI CRDs and the Envoy CRDs together,
// necessary for the deployment of Calico Gateway API.
func GatewayAPICRDs(provider operatorv1.Provider, scheme *runtime.Scheme) (essentialCRDs, optionalCRDs []client.Object, err error) {
	resources, err := legacyChart(scheme)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to render chart for CRDs: %w", err)
	}
	essentialCRDs, optionalCRDs, err = K8SGatewayAPICRDs(provider, scheme)
	if err != nil {
		return nil, nil, err
	}
	for _, crd := range resources.envoyCRDs {
		essentialCRDs = append(essentialCRDs, crd.DeepCopyObject().(client.Object))
	}

	return essentialCRDs, optionalCRDs, nil
}

type GatewayAPIImplementationConfig struct {
	Scheme                 *runtime.Scheme
	Installation           *operatorv1.InstallationSpec
	GatewayAPI             *operatorv1.GatewayAPI
	PullSecrets            []*corev1.Secret
	CustomEnvoyGateway     *envoyapi.EnvoyGateway
	CustomEnvoyProxies     map[string]*envoyapi.EnvoyProxy
	CurrentGatewayClasses  set.Set[string]
	IncludeV3NetworkPolicy bool

	// GatewayNamespaces is the list of namespaces containing a Gateway that targets
	// the calico-system controller (Enterprise only).
	GatewayNamespaces []string
	// CurrentGatewayNamespaces tracks previously provisioned namespaces for cleanup
	// when Gateways are removed.
	CurrentGatewayNamespaces set.Set[string]

	// HasLegacyGateways is true when at least one Gateway resolves to the
	// tigera-gateway controllerName. False → the install is torn down.
	HasLegacyGateways bool
}

type gatewayAPIImplementationComponent struct {
	cfg                 *GatewayAPIImplementationConfig
	envoyGatewayImage   string
	envoyProxyImage     string
	envoyRatelimitImage string
	wafHTTPFilterImage  string
	L7LogCollectorImage string

	// Pre-rendered helm chart results for the two installs.
	legacy     *gatewayAPIResources
	namespaced *gatewayAPIResources
}

func GatewayAPIImplementationComponent(cfg *GatewayAPIImplementationConfig) (render.Component, error) {
	legacy, err := legacyChart(cfg.Scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to render gateway-helm chart (legacy tigera-gateway): %w", err)
	}
	namespaced, err := namespacedChart(cfg.Scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to render gateway-helm chart (namespaced calico-system): %w", err)
	}
	return &gatewayAPIImplementationComponent{
		cfg:        cfg,
		legacy:     legacy,
		namespaced: namespaced,
	}, nil
}

func (pr *gatewayAPIImplementationComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := pr.cfg.Installation.Registry
	path := pr.cfg.Installation.ImagePath
	prefix := pr.cfg.Installation.ImagePrefix

	var err error
	if pr.cfg.Installation.Variant.IsEnterprise() {
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
		pr.L7LogCollectorImage, err = components.GetReference(components.ComponentGatewayL7Collector, reg, path, prefix, is)
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
	var objs, objsToDelete []client.Object
	openShift := pr.cfg.Installation.KubernetesProvider.IsOpenShift()

	// DEPRECATION: kept only while legacy Gateways exist; retire by deleting
	// this block along with legacyObjects and the Legacy* constants.
	if pr.cfg.HasLegacyGateways {
		objs = append(objs, pr.legacyObjects()...)
		// User-declared GatewayClasses target the tigera-gateway controller. Skip the
		// namespaced class if the user also declared it; the caller auto-provisions it.
		for i := range pr.cfg.GatewayAPI.Spec.GatewayClasses {
			className := pr.cfg.GatewayAPI.Spec.GatewayClasses[i].Name
			if className == NamespacedGatewayClassName {
				continue
			}
			proxy := pr.envoyProxyConfig(className, LegacyControllerNamespace, pr.cfg.CustomEnvoyProxies[className], &(pr.cfg.GatewayAPI.Spec.GatewayClasses[i]))
			objs = append(objs, proxy, pr.gatewayClass(className, LegacyControllerName, proxy))
			pr.cfg.CurrentGatewayClasses.Delete(className)
		}
	} else {
		objsToDelete = append(objsToDelete, pr.legacyTeardownObjects()...)
	}

	// Allow policy for the calico-system controller to punch through the core
	// Installation's default-deny.
	if pr.cfg.IncludeV3NetworkPolicy {
		objs = append(objs, gatewayAPIControllerPolicy(common.CalicoNamespace, openShift))
	}

	// Helm-rendered resources for the calico-system controller.
	objs = append(objs, pr.controllerObjects(pr.namespaced, false)...)

	// Auto-provision the calico-system class so users can create Gateways in their own
	// namespaces without declaring a GatewayClass in the GatewayAPI CR.
	nsClassSpec := &operatorv1.GatewayClassSpec{Name: NamespacedGatewayClassName}
	nsProxy := pr.envoyProxyConfig(NamespacedGatewayClassName, common.CalicoNamespace, nil, nsClassSpec)
	objs = append(objs, nsProxy, pr.gatewayClass(NamespacedGatewayClassName, NamespacedControllerName, nsProxy))
	pr.cfg.CurrentGatewayClasses.Delete(NamespacedGatewayClassName)

	// Clean up the deprecated combined waf-http-filter ClusterRole/ClusterRoleBinding
	// that pre-dated the cluster-scoped vs gateway-resources split. Unconditional so
	// upgrades from older Enterprise installs always converge, and harmless on OSS.
	objsToDelete = append(objsToDelete,
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: wafFilterName},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: wafFilterName},
		},
	)

	for _, gcName := range pr.cfg.CurrentGatewayClasses.UnsortedList() {
		log.V(1).Info("Will delete GatewayClass and EnvoyProxy", "name", gcName)
		objsToDelete = append(objsToDelete,
			&gapi.GatewayClass{
				TypeMeta:   metav1.TypeMeta{Kind: "GatewayClass", APIVersion: "gateway.networking.k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: gcName},
			},
			&envoyapi.EnvoyProxy{
				TypeMeta:   metav1.TypeMeta{Kind: "EnvoyProxy", APIVersion: "gateway.envoyproxy.io/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: gcName, Namespace: LegacyControllerNamespace},
			},
		)
	}

	// Shared WAF ClusterRoles (Enterprise). Kept across tigera-gateway teardown
	// because the per-namespace SAs still bind to them.
	if pr.cfg.Installation.Variant.IsEnterprise() {
		objs = append(objs,
			pr.wafHttpFilterClusterScopedRole(),
			pr.wafHttpFilterGatewayResourcesRole(),
		)
	}

	// Per-namespace Enterprise resources for namespaces containing a Gateway that
	// targets the namespaced controller (populated by the GatewayAPI controller).
	if pr.cfg.Installation.Variant.IsEnterprise() {
		for _, ns := range pr.cfg.GatewayNamespaces {
			objs = append(objs,
				pr.gatewayNamespaceSA(ns),
				pr.gatewayNamespaceRoleBinding(ns),
			)
			// Skip shared resources in reserved namespaces — core Installation owns them.
			if !isReservedOperatorNamespace(ns) {
				objs = append(objs, render.CreateOperatorSecretsRoleBinding(ns))
				objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ns, pr.cfg.PullSecrets...)...)...)
			}
		}
		if len(pr.cfg.GatewayNamespaces) > 0 {
			objs = append(objs, pr.gatewayNamespacesCRB(pr.cfg.GatewayNamespaces))
		}

		// Clean up resources for namespaces that no longer have a namespaced-class Gateway.
		if pr.cfg.CurrentGatewayNamespaces != nil {
			currentNS := set.New(pr.cfg.GatewayNamespaces...)
			for _, ns := range pr.cfg.CurrentGatewayNamespaces.UnsortedList() {
				if !currentNS.Has(ns) {
					// Secret must go before the RoleBinding that grants us delete perms; skip shared
					// resources in reserved namespaces (core-owned).
					if !isReservedOperatorNamespace(ns) {
						objsToDelete = append(objsToDelete, secret.ToRuntimeObjects(secret.CopyToNamespace(ns, pr.cfg.PullSecrets...)...)...)
					}
					objsToDelete = append(objsToDelete,
						pr.gatewayNamespaceSA(ns),
						pr.gatewayNamespaceRoleBinding(ns),
					)
					if !isReservedOperatorNamespace(ns) {
						objsToDelete = append(objsToDelete, render.CreateOperatorSecretsRoleBinding(ns))
					}
				}
			}
			if len(pr.cfg.GatewayNamespaces) == 0 {
				objsToDelete = append(objsToDelete, pr.gatewayNamespacesCRB(nil))
			}
		}
	}

	log.V(1).Info("GatewayAPI rendering", "num_current", len(objs), "num_delete", len(objsToDelete))
	return objs, objsToDelete
}

// legacyObjects returns every resource tied to the tigera-gateway install.
// Grouped together so the install can be retired in a single delete pass.
// User-declared GatewayClasses are rendered by Objects, not here.
func (pr *gatewayAPIImplementationComponent) legacyObjects() []client.Object {
	var objs []client.Object

	// Bootstrap the tigera-gateway namespace; we own it.
	objs = append(objs,
		render.CreateNamespace(
			LegacyControllerNamespace,
			pr.cfg.Installation.KubernetesProvider,
			render.PSSPrivileged, // HostPath volume for l7-collector logs
			pr.cfg.Installation.Azure,
		),
		render.CreateOperatorSecretsRoleBinding(LegacyControllerNamespace),
	)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(LegacyControllerNamespace, pr.cfg.PullSecrets...)...)...)

	// Helm-rendered envoy-gateway controller in tigera-gateway.
	objs = append(objs, pr.controllerObjects(pr.legacy, true)...)

	// Legacy-only WAF bits: SA in tigera-gateway + the CRBs that bind it. The
	// shared ClusterRoles are rendered outside (Enterprise, unconditional).
	if pr.cfg.Installation.Variant.IsEnterprise() {
		objs = append(objs,
			pr.wafHttpFilterServiceAccount(),
			pr.wafHttpFilterClusterScopedCRB(),
			pr.wafHttpFilterGatewayResourcesCRB(),
		)
	}

	return objs
}

// legacyTeardownObjects returns the retirement delete list: Namespace +
// cluster-scoped objects (the cascade handles the rest), plus the Deployment
// so the component handler calls status.RemoveDeployments on it. Queuing
// Secrets/RoleBindings explicitly would 403 once the tigera-operator-secrets
// RoleBinding is cascaded; Deployment delete goes via cluster-wide perms.
func (pr *gatewayAPIImplementationComponent) legacyTeardownObjects() []client.Object {
	var objs []client.Object
	for _, obj := range pr.legacyObjects() {
		if _, isNamespace := obj.(*corev1.Namespace); isNamespace || obj.GetNamespace() == "" {
			objs = append(objs, obj)
			continue
		}
		if _, isDeployment := obj.(*appsv1.Deployment); isDeployment {
			objs = append(objs, obj)
		}
	}
	return objs
}

// controllerObjects returns the helm-rendered resources for one envoy-gateway
// install. applyCustomEG=true applies user CustomEnvoyGateway + image/pull-secret
// overrides to the EnvoyGateway ConfigMap (tigera-gateway controller only).
func (pr *gatewayAPIImplementationComponent) controllerObjects(resources *gatewayAPIResources, applyCustomEG bool) []client.Object {
	var objs []client.Object

	// SA + cluster-scoped RBAC + webhooks + namespaced RBAC.
	objs = append(objs, resources.controllerServiceAccount.DeepCopyObject().(client.Object))
	for _, cr := range resources.clusterRoles {
		objs = append(objs, cr.DeepCopyObject().(client.Object))
	}
	for _, crb := range resources.clusterRoleBindings {
		objs = append(objs, crb.DeepCopyObject().(client.Object))
	}
	for _, mwc := range resources.mutatingWebhookConfigurations {
		objs = append(objs, mwc.DeepCopyObject().(client.Object))
	}
	for _, resource := range []client.Object{
		resources.role,
		resources.roleBinding,
		resources.leaderElectionRole,
		resources.leaderElectionRoleBinding,
		resources.controllerService,
		resources.certgenServiceAccount,
		resources.certgenRole,
		resources.certgenRoleBinding,
	} {
		objs = append(objs, resource.DeepCopyObject().(client.Object))
	}

	// EnvoyGateway ConfigMap.
	var envoyGatewayConfig *envoyapi.EnvoyGateway
	if applyCustomEG && pr.cfg.CustomEnvoyGateway != nil {
		envoyGatewayConfig = pr.cfg.CustomEnvoyGateway
	} else {
		envoyGatewayConfig = resources.envoyGatewayConfig.DeepCopyObject().(*envoyapi.EnvoyGateway)
	}
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
	envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container.Image = &pr.envoyRatelimitImage
	envoyGatewayConfig.Provider.Kubernetes.ShutdownManager.Image = &pr.envoyGatewayImage
	envoyGatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod.ImagePullSecrets = secret.GetReferenceList(pr.cfg.PullSecrets)
	envoyGatewayConfig.ExtensionAPIs.EnableBackend = true
	envoyGatewayConfig.ExtensionAPIs.EnableEnvoyPatchPolicy = true

	envoyGatewayConfigMap := resources.envoyGatewayConfigMap.DeepCopyObject().(*corev1.ConfigMap)
	if bytes, err := yaml.Marshal(*envoyGatewayConfig); err == nil {
		envoyGatewayConfigMap.Data[EnvoyGatewayConfigKey] = string(bytes)
	} else {
		panic(fmt.Sprintf("couldn't marshal EnvoyGateway to YAML: %v", err))
	}
	objs = append(objs, envoyGatewayConfigMap)

	// Controller Deployment.
	controllerDeployment := resources.controllerDeployment.DeepCopyObject().(*appsv1.Deployment)
	controllerDeployment.Spec.Template.Spec.Containers[0].Image = pr.envoyGatewayImage
	controllerDeployment.Spec.Template.Spec.ImagePullSecrets = append(
		controllerDeployment.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(pr.cfg.PullSecrets)...)
	controllerDeployment.Spec.Template.Labels["k8s-app"] = GatewayControllerLabel
	rcomp.ApplyDeploymentOverrides(controllerDeployment, pr.cfg.GatewayAPI.Spec.GatewayControllerDeployment)
	objs = append(objs, controllerDeployment)

	// Certgen Job.
	certgenJob := resources.certgenJob.DeepCopyObject().(*batchv1.Job)
	certgenJob.Spec.Template.Spec.Containers[0].Image = pr.envoyGatewayImage
	certgenJob.Spec.Template.Spec.ImagePullSecrets = append(
		certgenJob.Spec.Template.Spec.ImagePullSecrets,
		secret.GetReferenceList(pr.cfg.PullSecrets)...)
	rcomp.ApplyJobOverrides(certgenJob, pr.cfg.GatewayAPI.Spec.GatewayCertgenJob)
	objs = append(objs, certgenJob)

	return objs
}

func (pr *gatewayAPIImplementationComponent) envoyProxyConfig(className, ns string, envoyProxy *envoyapi.EnvoyProxy, classSpec *operatorv1.GatewayClassSpec) *envoyapi.EnvoyProxy {
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
	envoyProxy.Name = className
	envoyProxy.Namespace = ns
	if envoyProxy.Spec.Provider == nil {
		envoyProxy.Spec.Provider = &envoyapi.EnvoyProxyProvider{}
	}
	envoyProxy.Spec.Provider.Type = envoyapi.EnvoyProxyProviderTypeKubernetes
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

	// Setup WAF HTTP Filter and l7 Log collector on Enterprise.
	if pr.cfg.Installation.Variant.IsEnterprise() {
		// The WAF HTTP filter is not supported when the envoy proxy is deployed as a DaemonSet
		// as there is no support for init containers in a DaemonSet.
		if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment != nil {
			// Add or update the Init Container to the deployment
			wafHTTPFilter := corev1.Container{
				Name:  wafFilterName,
				Image: pr.wafHTTPFilterImage,
				Args: []string{
					"-logFileDirectory",
					"/var/log/calico/waf",
					"-logFileName",
					"waf.log",
					"-socketPath",
					"/var/run/waf-http-filter/extproc.sock",
				},
				RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      wafFilterName,
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
			// need to make changes to the envoy container to mount the socket
			l7LogCollector := corev1.Container{
				Name:  "l7-log-collector",
				Image: pr.L7LogCollectorImage,
				Env: []corev1.EnvVar{
					{
						Name:  "LOG_LEVEL",
						Value: "info",
					},
					{
						Name:  "FELIX_DIAL_TARGET",
						Value: "/var/run/felix/nodeagent/socket",
					},
					{
						Name:  "ENVOY_ACCESS_LOG_PATH",
						Value: "/access_logs/access.log",
					},
					// Owning Gateway info from pod labels (set by EnvoyProxy)
					OwningGatewayNameEnvVar,
					OwningGatewayNamespaceEnvVar,
				},
				RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "access-logs",
						MountPath: "/access_logs",
					},
					{
						Name:      "felix-sync",
						MountPath: "/var/run/felix",
					},
				},
				SecurityContext: securitycontext.NewRootContext(true),
			}

			hasWAFHTTPFilter := false
			hasL7LogCollector := false
			for i, initContainer := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers {
				if initContainer.Name == wafHTTPFilter.Name {
					hasWAFHTTPFilter = true
					// Handle update
					if initContainer.Image != wafHTTPFilter.Image {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i] = wafHTTPFilter
					}
				}
				if initContainer.Name == l7LogCollector.Name {
					hasL7LogCollector = true
					// Handle update
					if initContainer.Image != l7LogCollector.Image {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].Image = l7LogCollector.Image
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].Env = l7LogCollector.Env
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].VolumeMounts = l7LogCollector.VolumeMounts
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].RestartPolicy = l7LogCollector.RestartPolicy
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].SecurityContext = l7LogCollector.SecurityContext
					}
				}
			}
			if !hasWAFHTTPFilter {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers, wafHTTPFilter)
			}

			if !hasL7LogCollector {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers, l7LogCollector)
			}

			accessLogsName := "access-logs"
			// Add or update Container volume mount
			wafSocketVolumeMount := corev1.VolumeMount{
				Name:      wafFilterName,
				MountPath: "/var/run/waf-http-filter",
			}

			l7SocketVolumeMount := corev1.VolumeMount{
				Name:      accessLogsName,
				MountPath: "/access_logs",
			}

			hasWAFFilterSocketVolumeMount := false
			hasAccessLogsVolumeMount := false

			for i, volumeMount := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts {
				switch volumeMount.Name {
				case wafSocketVolumeMount.Name:
					hasWAFFilterSocketVolumeMount = true
					if volumeMount.MountPath != wafSocketVolumeMount.MountPath {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts[i] = wafSocketVolumeMount
					}
				case l7SocketVolumeMount.Name:
					hasAccessLogsVolumeMount = true
					if volumeMount.MountPath != l7SocketVolumeMount.MountPath {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts[i] = l7SocketVolumeMount
					}

				}
			}
			if !hasWAFFilterSocketVolumeMount {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts, wafSocketVolumeMount)
			}

			if !hasAccessLogsVolumeMount {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts, l7SocketVolumeMount)
			}

			// Add or update Pod volumes
			logsVolume := corev1.Volume{
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/log/calico",
						Type: ptr.To(corev1.HostPathDirectoryOrCreate),
					},
				},
				Name: "var-log-calico",
			}
			WAFHttpFilterSocketVolume := corev1.Volume{
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
				Name: wafFilterName,
			}
			AccessLogsVolume := []corev1.Volume{
				{
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
					Name: accessLogsName,
				},
				{
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver: "csi.tigera.io",
						},
					},
					Name: "felix-sync",
				},
			}
			hasLogsVolume := false
			hasSocketVolume := false
			hasAccessLogsVolume := false
			for i, volume := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes {
				if volume.Name == logsVolume.Name {
					hasLogsVolume = true
					// Handle update
					if volume.HostPath.Path != logsVolume.HostPath.Path || volume.HostPath.Type != logsVolume.HostPath.Type {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes[i] = logsVolume
					}
				}
				if volume.Name == WAFHttpFilterSocketVolume.Name {
					hasSocketVolume = true
					if volume.EmptyDir != WAFHttpFilterSocketVolume.EmptyDir {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes[i] = WAFHttpFilterSocketVolume
					}
				}
				for _, acVolume := range AccessLogsVolume {
					if volume.Name == acVolume.Name {
						hasAccessLogsVolume = true
						if acVolume.VolumeSource != volume.VolumeSource {
							envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes[i] = acVolume
						}
					}
				}

			}
			if !hasLogsVolume {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes, logsVolume)
			}
			if !hasSocketVolume {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes, WAFHttpFilterSocketVolume)
			}
			if !hasAccessLogsVolume {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes, AccessLogsVolume...)
			}

			// Configure service account for WAF HTTP Filter license client
			// Use EnvoyProxy patch mechanism to set serviceAccountName and automountServiceAccountToken
			serviceAccountPatch := map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"serviceAccountName":           wafFilterName,
							"automountServiceAccountToken": true,
						},
					},
				},
			}

			// Convert patch to JSON
			patchBytes, err := json.Marshal(serviceAccountPatch)
			if err == nil {
				if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Patch == nil {
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Patch = &envoyapi.KubernetesPatchSpec{}
				}
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Patch.Value = apiextenv1.JSON{Raw: patchBytes}
			}

			if envoyProxy.Spec.Telemetry != nil {
				if envoyProxy.Spec.Telemetry.AccessLog == nil {
					envoyProxy.Spec.Telemetry.AccessLog = &envoyapi.ProxyAccessLog{
						Settings: []envoyapi.ProxyAccessLogSetting{},
					}
				}
			} else {
				envoyProxy.Spec.Telemetry = &envoyapi.ProxyTelemetry{
					AccessLog: &envoyapi.ProxyAccessLog{
						Settings: []envoyapi.ProxyAccessLogSetting{},
					},
				}
			}

			envoyProxy.Spec.Telemetry.AccessLog.Settings = []envoyapi.ProxyAccessLogSetting{
				{
					Sinks: []envoyapi.ProxyAccessLogSink{
						{
							Type: envoyapi.ProxyAccessLogSinkTypeFile,
							File: &envoyapi.FileEnvoyProxyAccessLog{
								Path: "/access_logs/access.log",
							},
						},
					},
					Format: &envoyapi.ProxyAccessLogFormat{
						Type: ptr.To(envoyapi.ProxyAccessLogFormatTypeJSON),
						JSON: map[string]string{
							"reporter":                         "gateway",
							"start_time":                       "%START_TIME%",
							"duration":                         "%DURATION%",
							"response_code":                    "%RESPONSE_CODE%",
							"bytes_sent":                       "%BYTES_SENT%",
							"bytes_received":                   "%BYTES_RECEIVED%",
							"user_agent":                       "%REQ(USER-AGENT)%",
							"request_path":                     "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
							"request_method":                   "%REQ(:METHOD)%",
							"request_id":                       "%REQ(X-REQUEST-ID)%",
							"type":                             "{{.}}",
							"downstream_remote_address":        "%DOWNSTREAM_REMOTE_ADDRESS%",
							"downstream_local_address":         "%DOWNSTREAM_LOCAL_ADDRESS%",
							"downstream_direct_remote_address": "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%",
							"domain":                           "%REQ(HOST?:AUTHORITY)%",
							"upstream_host":                    "%UPSTREAM_HOST%",
							"upstream_local_address":           "%UPSTREAM_LOCAL_ADDRESS%",
							"upstream_service_time":            "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
							"route_name":                       "%ROUTE_NAME%",
						},
					},
					Type: &AccessLogType,
				},
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
			Namespace: LegacyControllerNamespace,
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

// wafHttpFilterServiceAccount creates the ServiceAccount for WAF HTTP Filter
func (pr *gatewayAPIImplementationComponent) wafHttpFilterServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      wafFilterName,
			Namespace: LegacyControllerNamespace,
		},
	}
}

const (
	wafFilterClusterScopedRoleName    = wafFilterName + "-cluster-scoped"
	wafFilterGatewayResourcesRoleName = wafFilterName + "-gateway-resources"
)

// wafHttpFilterClusterScopedRole creates the ClusterRole granting access to cluster-scoped
// resources (license keys, token reviews) needed by every WAF HTTP Filter / L7 Log Collector.
func (pr *gatewayAPIImplementationComponent) wafHttpFilterClusterScopedRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: wafFilterClusterScopedRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "watch"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

// wafHttpFilterGatewayResourcesRole grants read access to namespaced Gateway
// API resources (used by the L7 Log Collector). Bound cluster-wide in
// tigera-gateway; per-namespace for proxies in Gateway namespaces.
func (pr *gatewayAPIImplementationComponent) wafHttpFilterGatewayResourcesRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: wafFilterGatewayResourcesRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"gateway.networking.k8s.io"},
				Resources: []string{"gateways", "httproutes", "grpcroutes"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
}

// wafHttpFilterClusterScopedCRB binds the cluster-scoped ClusterRole to the WAF HTTP
// Filter ServiceAccount in tigera-gateway.
func (pr *gatewayAPIImplementationComponent) wafHttpFilterClusterScopedCRB() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: wafFilterClusterScopedRoleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     wafFilterClusterScopedRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      wafFilterName,
				Namespace: LegacyControllerNamespace,
			},
		},
	}
}

// wafHttpFilterGatewayResourcesCRB binds the gateway-resources ClusterRole
// cluster-wide to the SA in tigera-gateway (proxies there serve all namespaces).
func (pr *gatewayAPIImplementationComponent) wafHttpFilterGatewayResourcesCRB() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: wafFilterGatewayResourcesRoleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     wafFilterGatewayResourcesRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      wafFilterName,
				Namespace: LegacyControllerNamespace,
			},
		},
	}
}

// gatewayNamespaceSA creates a waf-http-filter ServiceAccount in a Gateway namespace,
// used by proxies that the calico-system controller deploys there.
func (pr *gatewayAPIImplementationComponent) gatewayNamespaceSA(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      wafFilterName,
			Namespace: namespace,
		},
	}
}

// GatewayNamespacesCRBName is the name of the shared ClusterRoleBinding that binds the
// waf-http-filter ClusterRole to ServiceAccounts in all Gateway namespaces.
const GatewayNamespacesCRBName = wafFilterName + "-gateway-namespaces"

// gatewayNamespacesCRB binds the cluster-scoped WAF ClusterRole to the
// waf-http-filter SA in each Gateway namespace via a single shared CRB.
// Gateway API resource access is scoped per namespace via gatewayNamespaceRoleBinding.
func (pr *gatewayAPIImplementationComponent) gatewayNamespacesCRB(namespaces []string) *rbacv1.ClusterRoleBinding {
	subjects := make([]rbacv1.Subject, 0, len(namespaces))
	for _, ns := range namespaces {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      wafFilterName,
			Namespace: ns,
		})
	}
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GatewayNamespacesCRBName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     wafFilterClusterScopedRoleName,
		},
		Subjects: subjects,
	}
}

// gatewayNamespaceRoleBinding scopes the WAF SA's Gateway API read access
// to its own namespace (least privilege for proxies in user namespaces).
func (pr *gatewayAPIImplementationComponent) gatewayNamespaceRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      wafFilterGatewayResourcesRoleName,
			Namespace: namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     wafFilterGatewayResourcesRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      wafFilterName,
				Namespace: namespace,
			},
		},
	}
}

// gatewayAPIControllerPolicy allows the controller + certgen to reach kube-apiserver and DNS.
func gatewayAPIControllerPolicy(namespace string, openShift bool) *v3.NetworkPolicy {
	egress := networkpolicy.AppendDNSEgressRules(nil, openShift)
	egress = append(egress,
		v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		v3.Rule{Action: v3.Pass},
	)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ControllerPolicyName,
			Namespace: namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: EnvoyGatewayPolicySelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			// 9443: webhook. 18000-18002: xDS. 19001: metrics.
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   v3.EntityRule{Nets: []string{"0.0.0.0/0"}},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(9443, 18000, 18001, 18002, 19001),
					},
				},
			},
			Egress: egress,
		},
	}
}
