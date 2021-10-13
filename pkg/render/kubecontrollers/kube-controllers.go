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

package kubecontrollers

import (
	"strings"

	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	KubeController                  = "calico-kube-controllers"
	KubeControllerServiceAccount    = "calico-kube-controllers"
	KubeControllerRole              = "calico-kube-controllers"
	KubeControllerRoleBinding       = "calico-kube-controllers"
	KubeControllerPodSecurityPolicy = "calico-kube-controllers"
	KubeControllerMetrics           = "calico-kube-controllers-metrics"

	EsKubeController                  = "es-calico-kube-controllers"
	EsKubeControllerServiceAccount    = "calico-kube-controllers"
	EsKubeControllerRole              = "es-calico-kube-controllers"
	EsKubeControllerRoleBinding       = "es-calico-kube-controllers"
	EsKubeControllerPodSecurityPolicy = "es-calico-kube-controllers"
	EsKubeControllerMetrics           = "es-calico-kube-controllers-metrics"

	ElasticsearchKubeControllersUserSecret             = "tigera-ee-kube-controllers-elasticsearch-access"
	ElasticsearchKubeControllersUserName               = "tigera-ee-kube-controllers"
	ElasticsearchKubeControllersSecureUserSecret       = "tigera-ee-kube-controllers-elasticsearch-access-gateway"
	ElasticsearchKubeControllersVerificationUserSecret = "tigera-ee-kube-controllers-gateway-verification-credentials"
)

type KubeControllersConfiguration struct {
	K8sServiceEp k8sapi.ServiceEndpoint

	Installation                *operatorv1.InstallationSpec
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	Authentication              *operatorv1.Authentication

	// Whether or not the LogStorage CRD is present in the cluster.
	LogStorageExists bool

	EnabledESOIDCWorkaround bool
	ClusterDomain           string
	MetricsPort             int

	// Secrets - provided by the caller. Used to generate secrets in the destination
	// namespace to be returned by the rendered. Expected that the calling code
	// take care to pass the same secret on each reconcile where possible.
	ManagerInternalSecret        *corev1.Secret
	ElasticsearchSecret          *corev1.Secret
	KubeControllersGatewaySecret *corev1.Secret
	KibanaSecret                 *corev1.Secret
}

func NewCalicoKubeControllers(cfg *KubeControllersConfiguration) *kubeControllersComponent {
	kubeControllerRolePolicyRules := kubeControllersRoleCommonRules(cfg, KubeController)
	enabledControllers := []string{"node"}
	if cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		kubeControllerRolePolicyRules = append(kubeControllerRolePolicyRules, kubeControllersRoleEnterpriseCommonRules(cfg)...)
		kubeControllerRolePolicyRules = append(kubeControllerRolePolicyRules,
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"deletecollection"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"remoteclusterconfigurations"},
				Verbs:     []string{"watch", "list", "get"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"endpoints"},
				Verbs:     []string{"create", "update", "delete"},
			},
		)
		enabledControllers = append(enabledControllers, "service", "federatedservices")
	}

	return &kubeControllersComponent{
		cfg:                              cfg,
		kubeControllerServiceAccountName: KubeControllerServiceAccount,
		kubeControllerRoleName:           KubeControllerRole,
		kubeControllerRoleBindingName:    KubeControllerRoleBinding,
		kubeControllerName:               KubeController,
		kubeControllerConfigName:         "default",
		kubeControllerMetricsName:        KubeControllerMetrics,
		renderManagerInternalSecret:      cfg.ManagerInternalSecret != nil,
		kubeControllersRules:             kubeControllerRolePolicyRules,
		enabledControllers:               enabledControllers,
	}
}

func NewElasticsearchKubeControllers(cfg *KubeControllersConfiguration) *kubeControllersComponent {
	kubeControllerRolePolicyRules := kubeControllersRoleCommonRules(cfg, EsKubeController)
	if cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		kubeControllerRolePolicyRules = append(kubeControllerRolePolicyRules, kubeControllersRoleEnterpriseCommonRules(cfg)...)
		kubeControllerRolePolicyRules = append(kubeControllerRolePolicyRules,
			rbacv1.PolicyRule{
				APIGroups: []string{"elasticsearch.k8s.elastic.co"},
				Resources: []string{"elasticsearches"},
				Verbs:     []string{"watch", "get", "list"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"watch", "list", "get", "update", "create"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"watch", "list", "get"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "clusterrolebindings"},
				Verbs:     []string{"watch", "list", "get"},
			},
		)
	}

	enabledControllers := []string{"authorization", "elasticsearchconfiguration"}
	if cfg.ManagementCluster != nil {
		enabledControllers = append(enabledControllers, "managedcluster")
	}

	return &kubeControllersComponent{
		cfg:                                cfg,
		kubeControllerServiceAccountName:   EsKubeControllerServiceAccount,
		kubeControllerRoleName:             EsKubeControllerRole,
		kubeControllerRoleBindingName:      EsKubeControllerRoleBinding,
		kubeControllerName:                 EsKubeController,
		kubeControllerConfigName:           "elasticsearch",
		kubeControllerMetricsName:          EsKubeControllerMetrics,
		renderElasticsearchSecret:          cfg.ElasticsearchSecret != nil,
		renderKubeControllersGatewaySecret: cfg.KubeControllersGatewaySecret != nil,
		kubeControllersRules:               kubeControllerRolePolicyRules,
		enabledControllers:                 enabledControllers,
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

	renderElasticsearchSecret          bool
	renderManagerInternalSecret        bool
	renderKubeControllersGatewaySecret bool

	kubeControllersRules []rbacv1.PolicyRule

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
		c.image, err = components.GetReference(components.ComponentCalicoKubeControllers, reg, path, prefix, is)
	}
	return err
}

func (c *kubeControllersComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *kubeControllersComponent) Objects() ([]client.Object, []client.Object) {
	objectsToCreate := []client.Object{
		c.controllersServiceAccount(),
		c.controllersRole(),
		c.controllersRoleBinding(),
		c.controllersDeployment(),
	}
	objectsToDelete := []client.Object{}
	if c.renderManagerInternalSecret {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(
			secret.CopyToNamespace(common.CalicoNamespace, c.cfg.ManagerInternalSecret)...)...)
	}

	if c.renderElasticsearchSecret {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(
			secret.CopyToNamespace(common.CalicoNamespace, c.cfg.ElasticsearchSecret)...)...)
	}

	if c.renderKubeControllersGatewaySecret {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(
			secret.CopyToNamespace(common.CalicoNamespace, c.cfg.KubeControllersGatewaySecret)...)...)
	}

	if c.cfg.Installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		objectsToCreate = append(objectsToCreate, c.controllersPodSecurityPolicy())
	}

	if c.cfg.MetricsPort != 0 {
		objectsToCreate = append(objectsToCreate, c.prometheusService())
	} else {
		objectsToDelete = append(objectsToDelete, c.prometheusService())
	}

	return objectsToCreate, objectsToDelete
}

func (c *kubeControllersComponent) Ready() bool {
	return true
}

func kubeControllersRoleCommonRules(cfg *KubeControllersConfiguration, kubeControllerName string) []rbacv1.PolicyRule {
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
			// IPAM resources are manipulated when nodes are deleted.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"ippools", "ipreservations"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"blockaffinities", "ipamblocks", "ipamhandles", "networksets"},
			Verbs:     []string{"get", "list", "create", "update", "delete", "watch"},
		},
		{
			// Needs access to update clusterinformations.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "create", "update"},
		},
		{
			// Needs to manage hostendpoints.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list", "create", "update", "delete"},
		},
		{
			// Needs to manipulate kubecontrollersconfiguration, which contains
			// its config.  It creates a default if none exists, and updates status
			// as well.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"kubecontrollersconfigurations"},
			Verbs:     []string{"get", "create", "update", "watch"},
		},
	}

	if cfg.Installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{kubeControllerName},
		})
	}

	return rules
}

func kubeControllersRoleEnterpriseCommonRules(cfg *KubeControllersConfiguration) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"watch", "list", "get", "update", "create"},
		},
		{
			// Needed to validate the license
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			// calico-kube-controllers requires tiers create
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"create"},
		},
		{
			// Needed to validate the license
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get"},
		},
	}

	if cfg.ManagementCluster != nil {
		// For cross-cluster requests an authentication review will be done for authenticating the kube-controllers.
		// Requests on behalf of the kube-controllers will be sent to Voltron, where an authentication review will
		// take place with its bearer token.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authenticationreviews"},
			Verbs:     []string{"create"},
		})
	}

	if cfg.ManagementClusterConnection != nil {
		rules = append(rules,
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"get", "create", "update", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "create", "update", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
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
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
	}
}

func (c *kubeControllersComponent) controllersRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: c.kubeControllerRoleName,
		},
		Rules: c.kubeControllersRules,
	}

	return role
}

func (c *kubeControllersComponent) controllersDeployment() *appsv1.Deployment {
	env := []corev1.EnvVar{
		{Name: "KUBE_CONTROLLERS_CONFIG_NAME", Value: c.kubeControllerConfigName},
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "ENABLED_CONTROLLERS", Value: strings.Join(c.enabledControllers, ",")},
	}

	env = append(env, c.cfg.K8sServiceEp.EnvVars(false, c.cfg.Installation.KubernetesProvider)...)

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		if c.kubeControllerName == EsKubeController {
			if c.cfg.EnabledESOIDCWorkaround {
				env = append(env, corev1.EnvVar{Name: "ENABLE_ELASTICSEARCH_OIDC_WORKAROUND", Value: "true"})
			}

			if c.cfg.Authentication != nil {
				env = append(env,
					corev1.EnvVar{Name: "OIDC_AUTH_USERNAME_PREFIX", Value: c.cfg.Authentication.Spec.UsernamePrefix},
					corev1.EnvVar{Name: "OIDC_AUTH_GROUP_PREFIX", Value: c.cfg.Authentication.Spec.GroupsPrefix},
				)
			}
		}

		if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
			env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	defaultMode := int32(420)

	container := corev1.Container{
		Name:      c.kubeControllerName,
		Image:     c.image,
		Env:       env,
		Resources: c.kubeControllersResources(),
		ReadinessProbe: &corev1.Probe{
			PeriodSeconds: int32(10),
			Handler: corev1.Handler{
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
			PeriodSeconds:       int32(10),
			InitialDelaySeconds: int32(10),
			FailureThreshold:    int32(6),
			Handler: corev1.Handler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/usr/bin/check-status",
						"-l",
					},
				},
			},
			TimeoutSeconds: 10,
		},
		VolumeMounts: kubeControllersVolumeMounts(c.cfg.ManagerInternalSecret),
	}

	if c.kubeControllerName == EsKubeController {
		container = relasticsearch.ContainerDecorate(container, render.DefaultElasticsearchClusterName,
			ElasticsearchKubeControllersUserSecret, c.cfg.ClusterDomain, rmeta.OSTypeLinux)
	}

	podSpec := corev1.PodSpec{
		NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
		Tolerations:        append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly),
		ImagePullSecrets:   c.cfg.Installation.ImagePullSecrets,
		ServiceAccountName: c.kubeControllerServiceAccountName,
		Containers:         []corev1.Container{container},
		Volumes:            kubeControllersVolumes(defaultMode, c.cfg.ManagerInternalSecret),
	}

	if c.kubeControllerName == EsKubeController {
		podSpec = relasticsearch.PodSpecDecorate(podSpec)
	}

	var replicas int32 = 1

	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.kubeControllerName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				"k8s-app": c.kubeControllerName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": c.kubeControllerName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      c.kubeControllerName,
					Namespace: common.CalicoNamespace,
					Labels: map[string]string{
						"k8s-app": c.kubeControllerName,
					},
					Annotations: c.annotations(),
				},
				Spec: podSpec,
			},
		},
	}
	render.SetClusterCriticalPod(&(d.Spec.Template))

	return &d
}

func (c *kubeControllersComponent) controllersRoleBinding() *rbacv1.ClusterRoleBinding {
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
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      c.kubeControllerServiceAccountName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

// prometheusService creates a Service which exposes and endpoint on kube-controllers for
// reporting Prometheus metrics.
func (c *kubeControllersComponent) prometheusService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.kubeControllerMetricsName,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": c.kubeControllerName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": c.kubeControllerName},
			Type:     corev1.ServiceTypeClusterIP,
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
	am := map[string]string{}
	if c.cfg.ManagerInternalSecret != nil {
		am[render.ManagerInternalTLSHashAnnotation] = rmeta.AnnotationHash(c.cfg.ManagerInternalSecret.Data)
	}
	if c.cfg.ElasticsearchSecret != nil {
		am[render.TlsSecretHashAnnotation] = rmeta.AnnotationHash(c.cfg.ElasticsearchSecret.Data)
	}
	if c.cfg.KubeControllersGatewaySecret != nil {
		am[render.ElasticsearchUserHashAnnotation] = rmeta.AnnotationHash(c.cfg.KubeControllersGatewaySecret.Data)
	}
	if c.cfg.KibanaSecret != nil {
		am[render.KibanaTLSHashAnnotation] = rmeta.AnnotationHash(c.cfg.KibanaSecret.Data)
	}
	return am
}

func (c *kubeControllersComponent) controllersPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(c.kubeControllerName)
	return psp
}

func kubeControllersVolumeMounts(managerSecret *corev1.Secret) []corev1.VolumeMount {
	if managerSecret != nil {
		return []corev1.VolumeMount{{
			Name:      render.ManagerInternalTLSSecretName,
			MountPath: "/manager-tls",
			ReadOnly:  true,
		}}
	}

	return []corev1.VolumeMount{}
}

func kubeControllersVolumes(defaultMode int32, managerSecret *corev1.Secret) []corev1.Volume {
	if managerSecret != nil {

		return []corev1.Volume{
			{
				Name: render.ManagerInternalTLSSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						DefaultMode: &defaultMode,
						SecretName:  render.ManagerInternalTLSSecretName,
						Items: []corev1.KeyToPath{
							{
								Key:  "cert",
								Path: "cert",
							},
						},
					},
				},
			},
		}
	}

	return []corev1.Volume{}
}
