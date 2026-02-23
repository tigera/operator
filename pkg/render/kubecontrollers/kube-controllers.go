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
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

const (
	KubeController                  = "calico-kube-controllers"
	KubeControllerServiceAccount    = "calico-kube-controllers"
	KubeControllerRole              = "calico-kube-controllers"
	KubeControllerRoleBinding       = "calico-kube-controllers"
	KubeControllerMetrics           = "calico-kube-controllers-metrics"
	KubeControllerNetworkPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "kube-controller-access"

	EsKubeController                    = "es-calico-kube-controllers"
	EsKubeControllerRole                = "es-calico-kube-controllers"
	EsKubeControllerRoleBinding         = "es-calico-kube-controllers"
	EsKubeControllerMetrics             = "es-calico-kube-controllers-metrics"
	EsKubeControllerNetworkPolicyName   = networkpolicy.TigeraComponentPolicyPrefix + "es-kube-controller-access"
	ManagedClustersWatchRoleBindingName = "es-calico-kube-controllers-managed-cluster-watch"

	ElasticsearchKubeControllersUserSecret             = "tigera-ee-kube-controllers-elasticsearch-access"
	ElasticsearchKubeControllersUserName               = "tigera-ee-kube-controllers"
	ElasticsearchKubeControllersSecureUserSecret       = "tigera-ee-kube-controllers-elasticsearch-access-gateway"
	ElasticsearchKubeControllersVerificationUserSecret = "tigera-ee-kube-controllers-gateway-verification-credentials"
	KubeControllerPrometheusTLSSecret                  = "calico-kube-controllers-metrics-tls"
)

type KubeControllersConfiguration struct {
	K8sServiceEp k8sapi.ServiceEndpoint

	Installation                *operatorv1.InstallationSpec
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	Authentication              *operatorv1.Authentication

	// Whether or not the LogStorage CRD is present in the cluster.
	LogStorageExists bool

	ClusterDomain string
	MetricsPort   int

	// For details on why this is needed see 'Node and Installation finalizer' in the core_controller.
	Terminating bool

	// Secrets - provided by the caller. Used to generate secrets in the destination
	// namespace to be returned by the rendered. Expected that the calling code
	// take care to pass the same secret on each reconcile where possible.
	KubeControllersGatewaySecret *corev1.Secret
	TrustedBundle                certificatemanagement.TrustedBundleRO

	MetricsServerTLS certificatemanagement.KeyPairInterface

	// Namespace to be installed into.
	Namespace string

	// List of namespaces that are running a kube-controllers instance that need a cluster role binding.
	BindingNamespaces []string

	// Tenant object provides tenant configuration for both single and multi-tenant modes.
	// If this is nil, then we should run in zero-tenant mode.
	Tenant *operatorv1.Tenant
}

func NewCalicoKubeControllers(cfg *KubeControllersConfiguration) *kubeControllersComponent {
	kubeControllerRolePolicyRules := kubeControllersRoleCommonRules(cfg)
	enabledControllers := []string{"node", "loadbalancer"}
	if cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		kubeControllerRolePolicyRules = append(kubeControllerRolePolicyRules, kubeControllersRoleEnterpriseCommonRules(cfg)...)
		kubeControllerRolePolicyRules = append(kubeControllerRolePolicyRules,
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
		enabledControllers = append(enabledControllers, "service", "federatedservices", "usage")
	}

	return &kubeControllersComponent{
		cfg:                              cfg,
		kubeControllerServiceAccountName: KubeControllerServiceAccount,
		kubeControllerRoleName:           KubeControllerRole,
		kubeControllerRoleBindingName:    KubeControllerRoleBinding,
		kubeControllerName:               KubeController,
		kubeControllerConfigName:         "default",
		kubeControllerMetricsName:        KubeControllerMetrics,
		kubeControllersRules:             kubeControllerRolePolicyRules,
		enabledControllers:               enabledControllers,
	}
}

func NewCalicoKubeControllersPolicy(cfg *KubeControllersConfiguration) render.Component {
	return render.NewPassthrough(kubeControllersAllowTigeraPolicy(cfg))
}

func NewElasticsearchKubeControllers(cfg *KubeControllersConfiguration) *kubeControllersComponent {
	var kubeControllerAllowTigeraPolicy *v3.NetworkPolicy
	kubeControllerRolePolicyRules := kubeControllersRoleCommonRules(cfg)

	if cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		kubeControllerRolePolicyRules = append(kubeControllerRolePolicyRules, kubeControllersRoleEnterpriseCommonRules(cfg)...)
		kubeControllerRolePolicyRules = append(kubeControllerRolePolicyRules,
			rbacv1.PolicyRule{
				APIGroups: []string{"elasticsearch.k8s.elastic.co"},
				Resources: []string{"elasticsearches"},
				Verbs:     []string{"watch", "get", "list"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "clusterrolebindings"},
				Verbs:     []string{"watch", "list", "get"},
			},
		)

		kubeControllerAllowTigeraPolicy = esKubeControllersAllowTigeraPolicy(cfg)
	}

	var enabledControllers []string
	if !cfg.Tenant.MultiTenant() {
		// Zero and single tenant cluster needs elasticsearch configuration
		enabledControllers = append(enabledControllers, "authorization", "elasticsearchconfiguration")
		if cfg.ManagementCluster != nil && cfg.Tenant == nil {
			// Enterprise will require the managedcluster controller to push licenses
			enabledControllers = append(enabledControllers, "managedcluster")
		}
	}

	return &kubeControllersComponent{
		cfg:                              cfg,
		kubeControllerServiceAccountName: KubeControllerServiceAccount,
		kubeControllerRoleName:           EsKubeControllerRole,
		kubeControllerRoleBindingName:    EsKubeControllerRoleBinding,
		kubeControllerName:               EsKubeController,
		kubeControllerConfigName:         "elasticsearch",
		kubeControllerMetricsName:        EsKubeControllerMetrics,
		kubeControllersRules:             kubeControllerRolePolicyRules,
		kubeControllerAllowTigeraPolicy:  kubeControllerAllowTigeraPolicy,
		enabledControllers:               enabledControllers,
	}
}

type kubeControllersComponent struct {
	// cfg is caller-supplied configuration for building kube-controllers Kubernetes resources.
	cfg *KubeControllersConfiguration

	// Internal state generated by the given configuration.
	image string

	kubeControllerServiceAccountName string
	kubeControllerRoleName           string
	kubeControllerRoleBindingName    string
	kubeControllerName               string
	kubeControllerConfigName         string
	kubeControllerMetricsName        string

	kubeControllersRules            []rbacv1.PolicyRule
	kubeControllerAllowTigeraPolicy *v3.NetworkPolicy

	enabledControllers []string
}

func (c *kubeControllersComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.image, err = components.GetReference(components.ComponentTigeraKubeControllers, reg, path, prefix, is)
	} else {
		if operatorv1.IsFIPSModeEnabled(c.cfg.Installation.FIPSMode) {
			c.image, err = components.GetReference(components.ComponentCalicoKubeControllersFIPS, reg, path, prefix, is)
		} else {
			c.image, err = components.GetReference(components.ComponentCalicoKubeControllers, reg, path, prefix, is)
		}
	}
	return err
}

func (c *kubeControllersComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *kubeControllersComponent) Objects() ([]client.Object, []client.Object) {
	objectsToCreate := []client.Object{}
	objectsToDelete := []client.Object{}

	if c.kubeControllerAllowTigeraPolicy != nil {
		objectsToCreate = append(objectsToCreate, c.kubeControllerAllowTigeraPolicy)
	}

	objectsToCreate = append(objectsToCreate,
		c.controllersServiceAccount(),
		c.controllersClusterRole(),
		c.controllersClusterRoleBinding(),
	)
	objectsToCreate = append(objectsToCreate, c.managedClusterRoleBindings()...)

	if len(c.enabledControllers) > 0 {
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

func kubeControllersRoleCommonRules(cfg *KubeControllersConfiguration) []rbacv1.PolicyRule {
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
			Resources: []string{"blockaffinities", "ipamblocks", "ipamhandles", "networksets", "ipamconfigurations"},
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

func kubeControllersRoleEnterpriseCommonRules(cfg *KubeControllersConfiguration) []rbacv1.PolicyRule {
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
			Name:      c.kubeControllerServiceAccountName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{},
		},
	}
}

func (c *kubeControllersComponent) controllersClusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.kubeControllerRoleName,
		},
		Rules: c.kubeControllersRules,
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
				Name:      KubeController,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *kubeControllersComponent) controllersDeployment() *appsv1.Deployment {
	env := []corev1.EnvVar{
		{Name: "KUBE_CONTROLLERS_CONFIG_NAME", Value: c.kubeControllerConfigName},
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "ENABLED_CONTROLLERS", Value: strings.Join(c.enabledControllers, ",")},
		{Name: "DISABLE_KUBE_CONTROLLERS_CONFIG_API", Value: strconv.FormatBool(c.cfg.Tenant.MultiTenant() && c.kubeControllerConfigName == "elasticsearch")},
	}

	env = append(env, c.cfg.K8sServiceEp.EnvVars(false, c.cfg.Installation.KubernetesProvider)...)

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		if c.cfg.Tenant != nil {
			env = append(env, corev1.EnvVar{Name: "TENANT_ID", Value: c.cfg.Tenant.Spec.ID})
		}

		if c.kubeControllerName == EsKubeController {
			// What started as a workaround is now the default behaviour. This feature uses our backend in order to
			// log into Kibana for users from external identity providers, rather than configuring an authn realm
			// in the Elastic stack.
			env = append(env, corev1.EnvVar{Name: "ENABLE_ELASTICSEARCH_OIDC_WORKAROUND", Value: "true"})

			if c.cfg.Authentication != nil {
				env = append(env,
					corev1.EnvVar{Name: "OIDC_AUTH_USERNAME_PREFIX", Value: c.cfg.Authentication.Spec.UsernamePrefix},
					corev1.EnvVar{Name: "OIDC_AUTH_GROUP_PREFIX", Value: c.cfg.Authentication.Spec.GroupsPrefix},
				)
			}
		}
		if c.cfg.TrustedBundle != nil {
			env = append(env, corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: c.cfg.TrustedBundle.MountPath()})
		}

		if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
			env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	if c.cfg.MetricsServerTLS != nil {
		env = append(env,
			corev1.EnvVar{Name: "TLS_KEY_PATH", Value: c.cfg.MetricsServerTLS.VolumeMountKeyFilePath()},
			corev1.EnvVar{Name: "TLS_CRT_PATH", Value: c.cfg.MetricsServerTLS.VolumeMountCertificateFilePath()},
			corev1.EnvVar{Name: "CLIENT_COMMON_NAME", Value: monitor.PrometheusClientTLSSecretName},
		)
	}
	if c.cfg.TrustedBundle != nil {
		env = append(env,
			corev1.EnvVar{Name: "CA_CRT_PATH", Value: c.cfg.TrustedBundle.MountPath()},
		)
	}

	// UID 999 is used in kube-controller Dockerfile.
	sc := securitycontext.NewNonRootContext()
	sc.RunAsUser = ptr.Int64ToPtr(999)
	sc.RunAsGroup = ptr.Int64ToPtr(0)

	container := corev1.Container{
		Name:            c.kubeControllerName,
		Image:           c.image,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env:             env,
		Resources:       c.kubeControllersResources(),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/usr/bin/check-status",
						"-r",
					},
				},
			},
			TimeoutSeconds: 10,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/usr/bin/check-status",
						"-l",
					},
				},
			},
			FailureThreshold:    6,
			InitialDelaySeconds: 10,
			TimeoutSeconds:      10,
		},
		SecurityContext: sc,
		VolumeMounts:    c.kubeControllersVolumeMounts(),
	}

	if c.kubeControllerName == EsKubeController && !c.cfg.Tenant.MultiTenant() {
		_, esHost, esPort, _ := url.ParseEndpoint(relasticsearch.GatewayEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, render.ElasticsearchNamespace))
		container.Env = append(container.Env, []corev1.EnvVar{
			relasticsearch.ElasticHostEnvVar(esHost),
			relasticsearch.ElasticPortEnvVar(esPort),
			relasticsearch.ElasticUsernameEnvVar(ElasticsearchKubeControllersUserSecret),
			relasticsearch.ElasticPasswordEnvVar(ElasticsearchKubeControllersUserSecret),
			relasticsearch.ElasticCAEnvVar(c.SupportedOSType()),
		}...)
	}

	var initContainers []corev1.Container
	if c.cfg.MetricsServerTLS != nil && c.cfg.MetricsServerTLS.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.MetricsServerTLS.InitContainer(c.cfg.Namespace, sc))
	}
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}
	podSpec := corev1.PodSpec{
		NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
		Tolerations:        tolerations,
		ImagePullSecrets:   c.cfg.Installation.ImagePullSecrets,
		ServiceAccountName: c.kubeControllerServiceAccountName,
		InitContainers:     initContainers,
		Containers:         []corev1.Container{container},
		Volumes:            c.kubeControllersVolumes(),
	}

	var replicas int32 = 1

	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.kubeControllerName,
			Namespace: c.cfg.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        c.kubeControllerName,
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

func (c *kubeControllersComponent) controllersClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	subjects := []rbacv1.Subject{}
	for _, ns := range c.cfg.BindingNamespaces {
		subjects = append(subjects, rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      c.kubeControllerServiceAccountName,
			Namespace: ns,
		})
	}
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   c.kubeControllerRoleBindingName,
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     c.kubeControllerRoleName,
		},
		Subjects: subjects,
	}
}

func (c *kubeControllersComponent) managedClusterRoleBindings() []client.Object {
	if c.cfg.ManagementCluster != nil {
		return []client.Object{
			rcomp.ClusterRoleBinding(ManagedClustersWatchRoleBindingName, render.ManagedClustersWatchClusterRoleName, c.kubeControllerServiceAccountName, []string{c.cfg.Namespace}),
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
			Name:      c.kubeControllerMetricsName,
			Namespace: c.cfg.Namespace,
			Annotations: map[string]string{
				"prometheus.io/scrape": "true",
				"prometheus.io/port":   fmt.Sprintf("%d", c.cfg.MetricsPort),
			},
			Labels: map[string]string{"k8s-app": c.kubeControllerName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.kubeControllerName},
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

	if c.cfg.MetricsServerTLS != nil {
		am[c.cfg.MetricsServerTLS.HashAnnotationKey()] = c.cfg.MetricsServerTLS.HashAnnotationValue()
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
	if c.cfg.MetricsServerTLS != nil {
		mounts = append(mounts, c.cfg.MetricsServerTLS.VolumeMount(c.SupportedOSType()))
	}
	return mounts
}

func (c *kubeControllersComponent) kubeControllersVolumes() []corev1.Volume {
	var volumes []corev1.Volume
	if c.cfg.TrustedBundle != nil {
		volumes = append(volumes, c.cfg.TrustedBundle.Volume())
	}
	if c.cfg.MetricsServerTLS != nil {
		volumes = append(volumes, c.cfg.MetricsServerTLS.Volume())
	}
	return volumes
}

func kubeControllersAllowTigeraPolicy(cfg *KubeControllersConfiguration) *v3.NetworkPolicy {
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
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(KubeController),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			Egress:   egressRules,
			Ingress:  ingressRules,
		},
	}
}

func esKubeControllersAllowTigeraPolicy(cfg *KubeControllersConfiguration) *v3.NetworkPolicy {
	if cfg.ManagementClusterConnection != nil {
		return nil
	}

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

	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.DefaultHelper().ESGatewayEntityRule(),
		},
	}...)

	networkpolicyHelper := networkpolicy.Helper(cfg.Tenant.MultiTenant(), cfg.Namespace)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicyHelper.ManagerEntityRule(),
		},
	}...)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsKubeControllerNetworkPolicyName,
			Namespace: cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(EsKubeController),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}
