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

package kubecontrollers

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	KubeController                  = "calico-kube-controllers"
	KubeControllerServiceAccount    = "calico-kube-controllers"
	KubeControllerRole              = "calico-kube-controllers"
	KubeControllerRoleBinding       = "calico-kube-controllers"
	KubeControllerMetrics           = "calico-kube-controllers-metrics"
	KubeControllerNetworkPolicyName = networkpolicy.CalicoComponentPolicyPrefix + "kube-controller-access"

	// WASMPullSecretName is the dedicated image-pull Secret (a renamed copy of
	// the install pull secret) that the WAF reconciler replicates into tenant
	// namespaces for the Coraza wasm OCI pull. A dedicated name avoids clashing
	// with the operator-managed tigera-pull-secret the GatewayAPI render also
	// copies into those namespaces (EV-6386).
	WASMPullSecretName = "tigera-waf-pull-secret"

	// WASMCACertName is the dedicated CA-bundle ConfigMap (in the controller
	// namespace) the WAF reconciler replicates into tenant namespaces for the
	// Coraza wasm OCI registry TLS check — a dedicated name avoids clashing with
	// the operator-managed tigera-ca-bundle ConfigMap the GatewayAPI render also
	// copies there (EV-6386). The source copy is a renamed copy of the trusted
	// bundle, provisioned by the core controller and passed in as WASMCACert.
	WASMCACertName = "tigera-waf-ca-bundle"

	// ManagedClustersWatchRoleBindingName binds kube-controllers to the managed-cluster
	// watch ClusterRole. Used by both calico-kube-controllers (in a management cluster)
	// and the enterprise es-calico-kube-controllers, so the binding stays generic here.
	ManagedClustersWatchRoleBindingName = "es-calico-kube-controllers-managed-cluster-watch"

	KubeControllerPrometheusTLSSecret = "calico-kube-controllers-metrics-tls"

	// KubeControllersHealthPort is the port the kube-controllers HealthAggregator listens on when run from the
	// combined calico binary. The legacy per-component image uses file-based health checks instead.
	KubeControllersHealthPort = 9440
)

type KubeControllersConfiguration struct {
	K8sServiceEp           k8sapi.ServiceEndpoint
	K8sServiceEpPodNetwork k8sapi.ServiceEndpoint

	Installation                *operatorv1.InstallationSpec
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	Authentication              *operatorv1.Authentication

	ClusterDomain string
	MetricsPort   int

	// For details on why this is needed see 'Node and Installation finalizer' in the core_controller.
	Terminating bool

	// Secrets - provided by the caller. Used to generate secrets in the destination
	// namespace to be returned by the rendered. Expected that the calling code
	// take care to pass the same secret on each reconcile where possible.
	KubeControllersGatewaySecret *corev1.Secret
	WASMPullSecret               *corev1.Secret
	WASMCACert                   *corev1.ConfigMap
	TrustedBundle                certificatemanagement.TrustedBundleRO

	// Namespace to be installed into.
	Namespace string

	// List of namespaces that are running a kube-controllers instance that need a cluster role binding.
	BindingNamespaces []string

	// Tenant object provides tenant configuration for both single and multi-tenant modes.
	// If this is nil, then we should run in zero-tenant mode.
	Tenant *operatorv1.Tenant

	// WAFGatewayExtensionEnabled gates the WAF v3 (Gateway API add-on) surface
	// on calico-kube-controllers: the applicationlayer controller enablement,
	// the WAF / Gateway-API / EnvoyExtensionPolicy / event / secret-replication
	// RBAC, the WASM_IMAGE / WASM_PULL_SECRET / WASM_CA_CERT env vars, and the
	// gateway envoy-proxy wasm image resolution.  Sourced from
	// `GatewayAPI.spec.extensions.waf.state == Enabled` (default off).
	// See design `tigera/designs#25` (PMREQ-384).
	WAFGatewayExtensionEnabled bool

	// WAFWebhookServerTLS is the serving certificate for the in-process WAF
	// SecLang validating admission webhook hosted by calico-kube-controllers.
	// When set (WAF enabled), it is mounted into the Pod and the webhook server
	// reads it from WAF_WEBHOOK_CERT_DIR. Issued for the tigera-waf-webhook
	// Service DNS name. Nil leaves the Deployment untouched (and the in-process
	// server self-disables when the cert is absent).
	WAFWebhookServerTLS certificatemanagement.KeyPairInterface

	// WAFWebhookCABundle is the PEM of the CA that issued WAFWebhookServerTLS
	// (the operator CA), stamped into the ValidatingWebhookConfiguration's
	// caBundle so the apiserver can verify the in-process webhook endpoint.
	// Only consulted when WAFGatewayExtensionEnabled is true.
	WAFWebhookCABundle []byte

	// The fields below parameterize the generic kube-controllers component. The
	// variant assemblers (NewCalicoKubeControllers, the enterprise es builder)
	// fill them; the component renders them without any variant or component-name
	// branching.

	// Name is the deployment / pod / container name (and the value the metrics
	// Service selects on).
	Name string
	// ConfigName is the KUBE_CONTROLLERS_CONFIG_NAME the binary reconciles.
	ConfigName string
	// RoleName / RoleBindingName / MetricsName name the ClusterRole, its binding,
	// and the Prometheus metrics Service.
	RoleName        string
	RoleBindingName string
	MetricsName     string
	// EnabledControllers is the ENABLED_CONTROLLERS list. The deployment is only
	// rendered when it is non-empty.
	EnabledControllers []string
	// Rules are the ClusterRole policy rules.
	Rules []rbacv1.PolicyRule
	// NetworkPolicy, when set, is rendered into the install namespace (and the
	// deprecated allow-tigera policy named DeprecatedNetworkPolicyName is deleted).
	NetworkPolicy               *v3.NetworkPolicy
	DeprecatedNetworkPolicyName string
	// ExtraEnv is appended to the deployment's container env.
	ExtraEnv []corev1.EnvVar
	// DisableConfigAPI sets DISABLE_KUBE_CONTROLLERS_CONFIG_API.
	DisableConfigAPI bool
	// ManageWAFWebhook makes this component own the in-process WAF admission
	// webhook surface lifecycle (rendered when WAFGatewayExtensionEnabled, deleted
	// otherwise). Only the calico-kube-controllers component sets this.
	ManageWAFWebhook bool

	// ModifierKey is the extension modifier key the component reports through
	// render.Extensible. calico-kube-controllers sets it so the enterprise modifier
	// can layer on its metrics TLS; es-calico-kube-controllers leaves it empty so it
	// is never decorated.
	ModifierKey string
}

func NewCalicoKubeControllersPolicy(cfg *KubeControllersConfiguration, defaultDeny *v3.NetworkPolicy) render.Component {
	toCreate := []client.Object{kubeControllersCalicoSystemPolicy(cfg)}

	if defaultDeny != nil {
		toCreate = append(toCreate, defaultDeny)
	}

	return render.NewPassthrough(
		toCreate,
		[]client.Object{
			// allow-tigera Tier was renamed to calico-system
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("kube-controller-access", cfg.Namespace),
			networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject("default-deny", common.CalicoNamespace),
		},
	)
}

// NewKubeControllers builds a kube-controllers component from a fully-populated
// configuration. Callers (NewCalicoKubeControllers, the enterprise es-kube-controllers
// builder) fill the generic Name/Rules/EnabledControllers/ExtraEnv/NetworkPolicy fields;
// the component renders them with no variant branching.
func NewKubeControllers(cfg *KubeControllersConfiguration) render.Component {
	return &kubeControllersComponent{cfg: cfg}
}

func NewCalicoKubeControllers(cfg *KubeControllersConfiguration) render.Component {
	cfg.Name = KubeController
	cfg.ConfigName = "default"
	cfg.RoleName = KubeControllerRole
	cfg.RoleBindingName = KubeControllerRoleBinding
	cfg.MetricsName = KubeControllerMetrics
	cfg.ManageWAFWebhook = true
	cfg.ModifierKey = render.ComponentNameKubeControllers

	cfg.Rules = KubeControllersRoleCommonRules(cfg)
	cfg.EnabledControllers = []string{"node", "loadbalancer"}
	if cfg.Installation.Variant.IsEnterprise() {
		cfg.Rules = append(cfg.Rules, KubeControllersRoleEnterpriseCommonRules(cfg)...)
		cfg.Rules = append(cfg.Rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"remoteclusterconfigurations"},
				Verbs:     []string{"watch", "list", "get"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"endpoints"},
				Verbs:     []string{"create", "update", "delete"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"usage.tigera.io"},
				Resources: []string{"licenseusagereports"},
				Verbs:     []string{"create", "update", "delete", "watch", "list", "get"},
			},
		)
		cfg.EnabledControllers = append(cfg.EnabledControllers, "service", "federatedservices", "usage")
		if cfg.WAFGatewayExtensionEnabled {
			cfg.EnabledControllers = append(cfg.EnabledControllers, "applicationlayer")
		}
		cfg.ExtraEnv = calicoEnterpriseEnv(cfg)
	}

	return NewKubeControllers(cfg)
}

// calicoEnterpriseEnv builds the enterprise-only static env vars for
// calico-kube-controllers. The dynamic WASM_* vars depend on resolved images and
// are added at deployment-render time.
func calicoEnterpriseEnv(cfg *KubeControllersConfiguration) []corev1.EnvVar {
	var env []corev1.EnvVar
	if cfg.Tenant != nil {
		env = append(env, corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID})
	}
	if cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: cfg.TrustedBundle.MountPath()})
	}
	if cfg.Installation.CalicoNetwork != nil && cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}
	return env
}

type kubeControllersComponent struct {
	// cfg is caller-supplied configuration for building kube-controllers Kubernetes resources.
	cfg *KubeControllersConfiguration

	// Internal state generated by the given configuration.
	calicoImage string

	// wasmImage is the fully-resolved OCI reference for the Coraza WAF wasm
	// binary (Enterprise only). Surfaced to the kube-controllers binary via
	// the WASM_IMAGE env var; consumed by the applicationlayer reconcilers
	// in tigera/calico-private to program WAF policy attachments.
	wasmImage string
}

func (c *kubeControllersComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.calicoImage, err = components.GetReference(components.CombinedCalicoImage(c.cfg.Installation), reg, path, prefix, is)
	if err != nil {
		return err
	}
	if c.cfg.WAFGatewayExtensionEnabled {
		// The Coraza WAF wasm is baked into the gateway envoy-proxy image as its
		// final layer; Envoy Gateway extracts it from there. Point WASM_IMAGE at
		// that same image (no standalone coraza-wasm image needed).
		c.wasmImage, err = components.GetReference(components.ComponentGatewayAPIEnvoyProxy, reg, path, prefix, is)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *kubeControllersComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *kubeControllersComponent) Objects() ([]client.Object, []client.Object) {
	objectsToCreate := []client.Object{}
	objectsToDelete := []client.Object{}

	if c.cfg.NetworkPolicy != nil {
		objectsToCreate = append(objectsToCreate, c.cfg.NetworkPolicy)
		if c.cfg.DeprecatedNetworkPolicyName != "" {
			// allow-tigera Tier was renamed to calico-system
			objectsToDelete = append(objectsToDelete,
				networkpolicy.DeprecatedAllowTigeraNetworkPolicyObject(c.cfg.DeprecatedNetworkPolicyName, c.cfg.Namespace),
			)
		}
	}

	objectsToCreate = append(objectsToCreate,
		c.controllersServiceAccount(),
		c.controllersClusterRole(),
		c.controllersClusterRoleBinding(),
	)
	objectsToCreate = append(objectsToCreate, c.managedClusterRoleBindings()...)

	if len(c.cfg.EnabledControllers) > 0 {
		// There's something to run, so create the deployment.
		objectsToCreate = append(objectsToCreate, c.controllersDeployment())
	} else {
		// No controllers are enabled, so delete the deployment.
		objectsToDelete = append(objectsToDelete, c.controllersDeployment())
	}

	if c.cfg.Installation.KubernetesProvider.IsOpenShift() {
		objectsToCreate = append(objectsToCreate, c.controllersOCPFederationRoleBinding())
	}
	if c.cfg.KubeControllersGatewaySecret != nil {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(
			secret.CopyToNamespace(c.cfg.Namespace, c.cfg.KubeControllersGatewaySecret)...)...)
	}
	if c.cfg.WASMPullSecret != nil {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(
			secret.CopyToNamespace(c.cfg.Namespace, c.cfg.WASMPullSecret)...)...)
	}
	if c.cfg.WASMCACert != nil {
		objectsToCreate = append(objectsToCreate, c.cfg.WASMCACert)
	}

	// The in-process WAF admission webhook surface (Service fronting this Pod +
	// ValidatingWebhookConfiguration). Rendered here, rather than as a
	// passthrough in the core controller, so the objects are cleaned up when the
	// WAF extension is disabled or the GatewayAPI CR is removed.
	if c.cfg.ManageWAFWebhook {
		webhookObjs := applicationlayer.WAFAdmissionWebhookComponents(c.cfg.WAFWebhookCABundle)
		if c.cfg.WAFGatewayExtensionEnabled {
			objectsToCreate = append(objectsToCreate, webhookObjs...)
		} else {
			objectsToDelete = append(objectsToDelete, webhookObjs...)
		}
	}

	if c.cfg.MetricsPort != 0 {
		objectsToCreate = append(objectsToCreate, c.prometheusService())
	} else {
		objectsToDelete = append(objectsToDelete, c.prometheusService())
	}

	if c.cfg.Terminating {
		objectsToDelete = append(objectsToDelete, objectsToCreate...)
		objectsToCreate = nil
	}

	return objectsToCreate, objectsToDelete
}

func (c *kubeControllersComponent) Ready() bool {
	return true
}

// ModifierKey implements render.Extensible. It is empty for es-calico-kube-controllers
// (never decorated) and set for calico-kube-controllers.
func (c *kubeControllersComponent) ModifierKey() string {
	return c.cfg.ModifierKey
}

func KubeControllersRoleCommonRules(cfg *KubeControllersConfiguration) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			// Nodes are watched to monitor for deletions.
			APIGroups: []string{""},
			Resources: []string{"nodes", "endpoints", "services"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			// Pods are watched to check for existence as part of IPAM GC.
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services", "services/status"},
			Verbs:     []string{"get", "list", "update", "watch"},
		},
		{
			// IPAM resources are manipulated in response to node and block updates, as well as periodic triggers.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"ipreservations"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"blockaffinities", "ipamblocks", "ipamhandles", "networksets", "ipamconfigurations", "ipamconfigs"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				// Pools are watched by various controllers.
				// - IPAM garbage collection watches pools to know which blocks to GC.
				// - The pool controller adds / manages finalizers on IP pools.
				// - The pool controller updates status conditions on IP pools.
				"ippools",
				"ippools/status",
			},
			Verbs: []string{"list", "watch", "update"},
		},
		{
			// Needs access to update clusterinformations.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "create", "update", "list", "watch"},
		},
		{
			// Needs to manage hostendpoints.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		{
			// Needs to manipulate kubecontrollersconfiguration, which contains
			// its config.  It creates a default if none exists, and updates status
			// as well.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"kubecontrollersconfigurations", "kubecontrollersconfigurations/status"},
			Verbs:     []string{"get", "create", "list", "update", "watch"},
		},
		{
			// calico-kube-controllers requires tiers create to create the default tiers,
			// and get permissions to access network policies in those tiers.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create", "update", "get", "list", "watch"},
		},
		{
			// Namespaces are watched for LoadBalancer IP allocation with namespace selector support
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// The policy name migrator needs to check calico/node daemonset rollout status.
			APIGroups:     []string{"apps"},
			Resources:     []string{"daemonsets"},
			Verbs:         []string{"get"},
			ResourceNames: []string{"calico-node"},
		},
		{
			// The policy name migrator needs to be able to CRUD Calico NetworkPolicies.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"networkpolicies",
				"globalnetworkpolicies",
				"stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
			},
			Verbs: []string{"get", "list", "watch", "create", "update", "delete"},
		},
		{
			// The IPAM GC controller uses informers to list/watch KubeVirt VMs/VMIs for IP garbage collection.
			APIGroups: []string{"kubevirt.io"},
			Resources: []string{"virtualmachineinstances", "virtualmachines"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			// The datastore migration controller watches DatastoreMigration CRs and updates their status.
			APIGroups: []string{"migration.projectcalico.org"},
			Resources: []string{"datastoremigrations", "datastoremigrations/status"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
		},
		{
			// The datastore migration controller needs to list/watch CRDs to determine
			// which API group is active.
			APIGroups: []string{"apiextensions.k8s.io"},
			Resources: []string{"customresourcedefinitions"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}

	if cfg.Installation.KubernetesProvider.IsOpenShift() {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	return rules
}

func KubeControllersRoleEnterpriseCommonRules(cfg *KubeControllersConfiguration) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"watch", "list", "get", "update", "create", "delete"},
		},
		{
			// The Federated Services Controller needs access to the remote kubeconfig secret
			// in order to create a remote syncer.
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			// Needed to validate the license
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			// Needed to update the status of the LicenseKey with the result of license validation.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"licensekeys/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "update"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"packetcaptures/status"},
			Verbs:     []string{"update"},
		},
	}

	if cfg.WAFGatewayExtensionEnabled {
		// WAF v3 (Gateway API add-on) RBAC. Gated by
		// GatewayAPI.spec.extensions.waf.state == Enabled.
		rules = append(rules,
			// Application-layer (gateway-addons) reconcilers reconcile WAF resources
			// against Gateway API targetRefs and emit events on the policy objects.
			rbacv1.PolicyRule{
				APIGroups: []string{"applicationlayer.projectcalico.org"},
				Resources: []string{
					"wafpolicies", "globalwafpolicies",
					"wafplugins", "globalwafplugins",
					"wafvalidationpolicies", "globalwafvalidationpolicies",
				},
				Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"applicationlayer.projectcalico.org"},
				Resources: []string{
					"wafpolicies/status", "globalwafpolicies/status",
					"wafplugins/status", "globalwafplugins/status",
					"wafvalidationpolicies/status", "globalwafvalidationpolicies/status",
				},
				Verbs: []string{"get", "update", "patch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"applicationlayer.projectcalico.org"},
				Resources: []string{
					"wafpolicies/finalizers", "globalwafpolicies/finalizers",
					"wafplugins/finalizers", "globalwafplugins/finalizers",
					"wafvalidationpolicies/finalizers", "globalwafvalidationpolicies/finalizers",
				},
				Verbs: []string{"update"},
			},
			rbacv1.PolicyRule{
				// Validate Gateway API targetRefs and surface attachment status.
				APIGroups: []string{"gateway.networking.k8s.io"},
				Resources: []string{"gateways", "httproutes", "tcproutes", "tlsroutes", "grpcroutes"},
				Verbs:     []string{"get", "list", "watch", "update", "patch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"gateway.networking.k8s.io"},
				Resources: []string{"gateways/status", "httproutes/status", "tcproutes/status", "tlsroutes/status", "grpcroutes/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
			// controller-runtime Reconcilers (e.g. the applicationlayer manager) record
			// events on watched objects via Recorder.Eventf; both core and events.k8s.io
			// API groups are emitted depending on the kubernetes version.
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"events.k8s.io"},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
			// Application-layer reconciler replicates the WAF wasm pull Secret from
			// the controller namespace (calico-system) into each WAFPolicy's
			// namespace so the rendered EnvoyExtensionPolicy can reference it. Also
			// replicates CA-cert ConfigMaps when WASM_CA_CERT is set.
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets", "configmaps"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			// Application-layer reconciler emits one EnvoyExtensionPolicy per WAF
			// targetRef to bind the Coraza wasm filter at the gateway / route.
			rbacv1.PolicyRule{
				APIGroups: []string{"gateway.envoyproxy.io"},
				Resources: []string{"envoyextensionpolicies"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			// Application-layer reconciler stamps each namespace with its
			// allocated WAF rule-id range (applicationlayer.projectcalico.org/waf-id-range
			// annotation) so application operators can author in-range rules. The
			// base role already grants namespaces get/list/watch; the annotation
			// write needs patch/update, gated to the WAF path.
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "patch", "update"},
			},
		)
	}

	if cfg.ManagementClusterConnection != nil {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "create", "update", "list", "watch"},
			},
		)
	}

	return rules
}

func (c *kubeControllersComponent) controllersServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeControllerServiceAccount,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{},
		},
	}
}

func (c *kubeControllersComponent) controllersClusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.cfg.RoleName,
		},
		Rules: c.cfg.Rules,
	}

	return role
}

// controllersOCPFederationRoleBinding on Openshift, an admission controller will block requests unless this permission
// is active.
func (c *kubeControllersComponent) controllersOCPFederationRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-kube-controllers-endpoint-controller",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:controller:endpoint-controller",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      KubeControllerServiceAccount,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *kubeControllersComponent) controllersDeployment() *appsv1.Deployment {
	env := []corev1.EnvVar{
		{Name: "KUBE_CONTROLLERS_CONFIG_NAME", Value: c.cfg.ConfigName},
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "ENABLED_CONTROLLERS", Value: strings.Join(c.cfg.EnabledControllers, ",")},
		{Name: "DISABLE_KUBE_CONTROLLERS_CONFIG_API", Value: strconv.FormatBool(c.cfg.DisableConfigAPI)},
	}

	env = append(env, c.cfg.K8sServiceEpPodNetwork.EnvVars()...)
	env = append(env, c.cfg.ExtraEnv...)

	// Application-layer (gateway-addons / WAF v3) env vars, gated by
	// GatewayAPI.spec.extensions.waf.state == Enabled. When the gate is off
	// (default), none of the WASM_* env vars are rendered and the kube-controllers
	// binary skips the WAF reconcilers entirely (see the applicationlayer entry in
	// EnabledControllers). The WASM_IMAGE value depends on resolved images, so this
	// is rendered here rather than in the static ExtraEnv.
	if c.cfg.WAFGatewayExtensionEnabled {
		// Application-layer (gateway-addons) reconcilers consume the Coraza WAF
		// wasm OCI reference from this env var to program WAF policy attachments.
		// Empty when ResolveImages was not called for the Calico variant; the
		// reconciler stamps Programmed=False/WASMUnavailable in that case.
		if c.wasmImage != "" {
			env = append(env, corev1.EnvVar{Name: "WASM_IMAGE", Value: c.wasmImage})
		}

		// WASM_PULL_SECRET names the imagePullSecret the reconciler replicates
		// from the kube-controllers namespace into a WAFPolicy's namespace so
		// the rendered EnvoyExtensionPolicy can pull the wasm OCI artifact from
		// a private Tigera registry. Source the name from the first
		// Installation.ImagePullSecrets entry so multi-tenant / BYO-registry
		// installs reuse whatever pull secret operator already attaches here.
		if c.cfg.WASMPullSecret != nil {
			env = append(env, corev1.EnvVar{Name: "WASM_PULL_SECRET", Value: c.cfg.WASMPullSecret.Name})
		}

		// WASM_CA_CERT names the dedicated CA bundle ConfigMap (provisioned as
		// WASMCACert) that the reconciler replicates alongside WASM_PULL_SECRET
		// so the EnvoyExtensionPolicy wasm fetcher trusts the registry's TLS
		// chain. Only set when the source ConfigMap is actually rendered.
		if c.cfg.WASMCACert != nil {
			env = append(env, corev1.EnvVar{Name: "WASM_CA_CERT", Value: c.cfg.WASMCACert.Name})
		}
	}

	if c.cfg.TrustedBundle != nil {
		env = append(env,
			corev1.EnvVar{Name: "CA_CRT_PATH", Value: c.cfg.TrustedBundle.MountPath()},
		)
	}
	if c.cfg.WAFWebhookServerTLS != nil {
		// The in-process WAF admission webhook server (calico-private
		// applicationlayer manager) reads its serving cert (tls.crt/tls.key)
		// from this directory; the controller-runtime webhook server only
		// registers when the cert is present.
		env = append(env,
			corev1.EnvVar{Name: "WAF_WEBHOOK_CERT_DIR", Value: filepath.Dir(c.cfg.WAFWebhookServerTLS.VolumeMountCertificateFilePath())},
		)
	}

	// UID 999 is used in kube-controller Dockerfile.
	sc := securitycontext.NewNonRootContext()
	sc.RunAsUser = ptr.To(int64(999))
	sc.RunAsGroup = ptr.To(int64(0))

	readinessProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{components.CalicoBinaryPath, "health", fmt.Sprintf("--port=%d", KubeControllersHealthPort), "--type=readiness"},
			},
		},
		TimeoutSeconds: 10,
	}
	livenessProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{components.CalicoBinaryPath, "health", fmt.Sprintf("--port=%d", KubeControllersHealthPort), "--type=liveness"},
			},
		},
		FailureThreshold:    6,
		InitialDelaySeconds: 10,
		TimeoutSeconds:      10,
	}
	containerCommand := []string{
		components.CalicoBinaryPath,
		"component",
		"kube-controllers",
		fmt.Sprintf("--health-port=%d", KubeControllersHealthPort),
	}

	container := corev1.Container{
		Name:            c.cfg.Name,
		Image:           c.calicoImage,
		Command:         containerCommand,
		Env:             env,
		Resources:       c.kubeControllersResources(),
		ReadinessProbe:  readinessProbe,
		LivenessProbe:   livenessProbe,
		SecurityContext: sc,
		VolumeMounts:    c.kubeControllersVolumeMounts(),
	}

	if c.cfg.WAFWebhookServerTLS != nil {
		// Expose the in-process WAF admission-webhook port that the
		// tigera-waf-webhook Service forwards to.
		container.Ports = append(container.Ports, corev1.ContainerPort{
			Name:          "waf-webhook",
			ContainerPort: applicationlayer.WAFWebhookContainerPort,
			Protocol:      corev1.ProtocolTCP,
		})
	}

	var initContainers []corev1.Container
	if c.cfg.WAFWebhookServerTLS != nil && c.cfg.WAFWebhookServerTLS.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.WAFWebhookServerTLS.InitContainer(c.cfg.Namespace, sc))
	}
	tolerations := appendUniqueTolerations(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = appendUniqueTolerations(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	podSpec := corev1.PodSpec{
		NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
		Tolerations:        tolerations,
		ImagePullSecrets:   c.cfg.Installation.ImagePullSecrets,
		ServiceAccountName: KubeControllerServiceAccount,
		InitContainers:     initContainers,
		Containers:         []corev1.Container{container},
		Volumes:            c.kubeControllersVolumes(),
	}

	var replicas int32 = 1

	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.Name,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        c.cfg.Name,
					Namespace:   c.cfg.Namespace,
					Annotations: c.annotations(),
				},
				Spec: podSpec,
			},
		},
	}

	render.SetClusterCriticalPod(&d.Spec.Template)

	if overrides := c.cfg.Installation.CalicoKubeControllersDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(&d, overrides)
	}
	return &d
}

func appendUniqueTolerations(tolerations []corev1.Toleration, toAppend ...corev1.Toleration) []corev1.Toleration {
	for _, toleration := range toAppend {
		if slices.Contains(tolerations, toleration) {
			continue
		}
		tolerations = append(tolerations, toleration)
	}
	return tolerations
}

func (c *kubeControllersComponent) controllersClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	subjects := []rbacv1.Subject{}
	for _, ns := range c.cfg.BindingNamespaces {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      KubeControllerServiceAccount,
			Namespace: ns,
		})
	}
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   c.cfg.RoleBindingName,
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     c.cfg.RoleName,
		},
		Subjects: subjects,
	}
}

func (c *kubeControllersComponent) managedClusterRoleBindings() []client.Object {
	if c.cfg.ManagementCluster != nil {
		return []client.Object{
			rcomp.ClusterRoleBinding(ManagedClustersWatchRoleBindingName, render.ManagedClustersWatchClusterRoleName, KubeControllerServiceAccount, []string{c.cfg.Namespace}),
		}
	}
	return []client.Object{}
}

// prometheusService creates a Service which exposes an endpoint on kube-controllers for
// reporting Prometheus metrics.
func (c *kubeControllersComponent) prometheusService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.MetricsName,
			Namespace: c.cfg.Namespace,
			Annotations: map[string]string{
				"prometheus.io/scrape": "true",
				"prometheus.io/port":   fmt.Sprintf("%d", c.cfg.MetricsPort),
			},
			Labels: map[string]string{"k8s-app": c.cfg.Name},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.cfg.Name},
			// "Headless" service; prevent kube-proxy from rendering any rules for this service
			// (which is only intended for Prometheus to scrape).
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics-port",
					Port:       int32(c.cfg.MetricsPort),
					TargetPort: intstr.FromInt(int(c.cfg.MetricsPort)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// kubeControllerResources creates the kube-controller's resource requirements.
func (c *kubeControllersComponent) kubeControllersResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameKubeControllers)
}

func (c *kubeControllersComponent) annotations() map[string]string {
	var am map[string]string
	if c.cfg.TrustedBundle != nil {
		am = c.cfg.TrustedBundle.HashAnnotations()
	} else {
		am = make(map[string]string)
	}

	if c.cfg.KubeControllersGatewaySecret != nil {
		am[render.ElasticsearchUserHashAnnotation] = rmeta.AnnotationHash(c.cfg.KubeControllersGatewaySecret.Data)
	}
	return am
}

func (c *kubeControllersComponent) kubeControllersVolumeMounts() []corev1.VolumeMount {
	var mounts []corev1.VolumeMount
	if c.cfg.TrustedBundle != nil {
		mounts = append(mounts, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)
	}
	if c.cfg.WAFWebhookServerTLS != nil {
		mounts = append(mounts, c.cfg.WAFWebhookServerTLS.VolumeMount(c.SupportedOSType()))
	}
	return mounts
}

func (c *kubeControllersComponent) kubeControllersVolumes() []corev1.Volume {
	var volumes []corev1.Volume
	if c.cfg.TrustedBundle != nil {
		volumes = append(volumes, c.cfg.TrustedBundle.Volume())
	}
	if c.cfg.WAFWebhookServerTLS != nil {
		volumes = append(volumes, c.cfg.WAFWebhookServerTLS.Volume())
	}
	return volumes
}

func kubeControllersCalicoSystemPolicy(cfg *KubeControllersConfiguration) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(443, 6443, 12388),
			},
		},
	}...)

	if cfg.ManagementClusterConnection != nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.GuardianEntityRule,
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().ManagerEntityRule(),
		})
	}

	ingressRules := []v3.Rule{}
	if cfg.MetricsPort != 0 {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source:   networkpolicy.PrometheusSourceEntityRule,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(cfg.MetricsPort)),
			},
		})
	}

	// Allow the kube-apiserver to reach the in-process WAF admission webhook on
	// :9443 (EV-6386). render-v3 wires the webhook Service/config/cert + the
	// server, but without this ingress rule the calico-system default-deny drops
	// the apiserver→:9443 call and every WAFPolicy/WAFPlugin admission times out.
	if cfg.WAFGatewayExtensionEnabled {
		ingressRules = append(ingressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(applicationlayer.WAFWebhookContainerPort)),
			},
		})
	}

	if r, err := cfg.K8sServiceEp.DestinationEntityRule(); r != nil && err == nil {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: *r,
		})
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeControllerNetworkPolicyName,
			Namespace: cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: networkpolicy.KubernetesAppSelector(KubeController),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			Egress:   egressRules,
			Ingress:  ingressRules,
		},
	}
}
