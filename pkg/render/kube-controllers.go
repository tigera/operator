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
	"strings"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
)

var replicas int32 = 1

const (
	ElasticsearchKubeControllersUserName               = "tigera-ee-kube-controllers"
	ElasticsearchKubeControllersUserSecret             = "tigera-ee-kube-controllers-elasticsearch-access"
	ElasticsearchKubeControllersSecureUserSecret       = "tigera-ee-kube-controllers-elasticsearch-access-gateway"
	ElasticsearchKubeControllersVerificationUserSecret = "tigera-ee-kube-controllers-gateway-verification-credentials"
)

func KubeControllers(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operator.InstallationSpec,
	logStorageExists bool,
	managementCluster *operator.ManagementCluster,
	managementClusterConnection *operator.ManagementClusterConnection,
	managerInternalSecret *v1.Secret,
	elasticsearchSecret *v1.Secret,
	kibanaSecret *v1.Secret,
	authentication *operator.Authentication,
	enabledESOIDCWorkaround bool,
	clusterDomain string,
	kubeControllersGatewaySecret *v1.Secret,
	metricsPort int,
) *kubeControllersComponent {
	if kubeControllersGatewaySecret != nil {
		kubeControllersGatewaySecret = secret.CopyToNamespace(common.CalicoNamespace, kubeControllersGatewaySecret)[0]
	}

	return &kubeControllersComponent{
		cr:                           cr,
		managementCluster:            managementCluster,
		managementClusterConnection:  managementClusterConnection,
		managerInternalSecret:        managerInternalSecret,
		elasticsearchSecret:          elasticsearchSecret,
		kibanaSecret:                 kibanaSecret,
		logStorageExists:             logStorageExists,
		authentication:               authentication,
		k8sServiceEp:                 k8sServiceEp,
		enabledESOIDCWorkaround:      enabledESOIDCWorkaround,
		clusterDomain:                clusterDomain,
		kubeControllersGatewaySecret: kubeControllersGatewaySecret,
		metricsPort:                  metricsPort,
	}
}

type kubeControllersComponent struct {
	cr                           *operator.InstallationSpec
	managementCluster            *operator.ManagementCluster
	managementClusterConnection  *operator.ManagementClusterConnection
	managerInternalSecret        *v1.Secret
	elasticsearchSecret          *v1.Secret
	kibanaSecret                 *v1.Secret
	logStorageExists             bool
	authentication               *operator.Authentication
	k8sServiceEp                 k8sapi.ServiceEndpoint
	enabledESOIDCWorkaround      bool
	image                        string
	clusterDomain                string
	kubeControllersGatewaySecret *v1.Secret
	metricsPort                  int
}

func (c *kubeControllersComponent) ResolveImages(is *operator.ImageSet) error {
	reg := c.cr.Registry
	path := c.cr.ImagePath
	prefix := c.cr.ImagePrefix
	var err error
	if c.cr.Variant == operator.TigeraSecureEnterprise {
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
	if c.managerInternalSecret != nil {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(
			secret.CopyToNamespace(common.CalicoNamespace, c.managerInternalSecret)...)...)
	}

	if c.elasticsearchSecret != nil {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(
			secret.CopyToNamespace(common.CalicoNamespace, c.elasticsearchSecret)...)...)
	}

	if !c.isManagedCluster() && c.kubeControllersGatewaySecret != nil {
		objectsToCreate = append(objectsToCreate, secret.ToRuntimeObjects(c.kubeControllersGatewaySecret)...)
	}

	if c.cr.KubernetesProvider != operator.ProviderOpenShift {
		objectsToCreate = append(objectsToCreate, c.controllersPodSecurityPolicy())
	}

	if c.metricsPort != 0 {
		objectsToCreate = append(objectsToCreate, c.prometheusService())
	} else {
		objectsToDelete = append(objectsToDelete, c.prometheusService())
	}

	return objectsToCreate, objectsToDelete
}

func (c *kubeControllersComponent) Ready() bool {
	return true
}

func (c *kubeControllersComponent) controllersServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
	}
}

func (c *kubeControllersComponent) controllersRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-kube-controllers",
		},
		Rules: []rbacv1.PolicyRule{
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
				Resources: []string{"ippools"},
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
		},
	}

	if c.cr.Variant == operator.TigeraSecureEnterprise {
		extraRules := []rbacv1.PolicyRule{
			{
				APIGroups: []string{"elasticsearch.k8s.elastic.co"},
				Resources: []string{"elasticsearches"},
				Verbs:     []string{"watch", "get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"watch", "list", "get", "update", "create"},
			},
			// Used for the creation, synchronization and deletion of elasticsearch related secrets.
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"watch", "list", "get", "update", "create", "deletecollection"},
			},

			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"watch", "list", "get"},
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
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"remoteclusterconfigurations"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				// For federated services.
				APIGroups: []string{""},
				Resources: []string{"endpoints"},
				Verbs:     []string{"create", "update", "delete"},
			},
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "clusterrolebindings"},
				Verbs:     []string{"watch", "list", "get"},
			},
		}

		role.Rules = append(role.Rules, extraRules...)

		if c.managementCluster != nil {
			// For cross-cluster requests an authentication review will be done for authenticating the kube-controllers.
			// Requests on behalf of the kube-controllers will be sent to Voltron, where an authentication review will
			// take place with its bearer token.
			role.Rules = append(role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"authenticationreviews"},
				Verbs:     []string{"create"},
			})
		}

		if c.managementClusterConnection != nil {
			role.Rules = append(role.Rules, rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"licensekeys"},
				Verbs:     []string{"create", "update"},
			})
		}
	}

	if c.cr.KubernetesProvider != operator.ProviderOpenShift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"calico-kube-controllers"},
		})
	}

	return role
}

func (c *kubeControllersComponent) controllersRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-kube-controllers",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-kube-controllers",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-kube-controllers",
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

func (c *kubeControllersComponent) controllersDeployment() *apps.Deployment {
	env := []v1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
	}

	env = append(env, c.k8sServiceEp.EnvVars(false, c.cr.KubernetesProvider)...)

	enabledControllers := []string{"node"}
	if c.cr.Variant == operator.TigeraSecureEnterprise {
		enabledControllers = append(enabledControllers, "service", "federatedservices")

		if c.logStorageExists && c.kubeControllersGatewaySecret != nil && c.elasticsearchSecret != nil {
			// These controllers require that Elasticsearch exists within the cluster Kube Controllers is running in, i.e.
			// Full Standalone and Management clusters, not Minimal Standalone and Managed clusters.
			enabledControllers = append(enabledControllers, "authorization", "elasticsearchconfiguration")

			if c.enabledESOIDCWorkaround {
				env = append(env, v1.EnvVar{Name: "ENABLE_ELASTICSEARCH_OIDC_WORKAROUND", Value: "true"})
			}

			// These environment variables are for the "authorization" controller, so if it's not enabled don't provide
			// them.
			if c.authentication != nil {
				env = append(env,
					v1.EnvVar{Name: "OIDC_AUTH_USERNAME_PREFIX", Value: c.authentication.Spec.UsernamePrefix},
					v1.EnvVar{Name: "OIDC_AUTH_GROUP_PREFIX", Value: c.authentication.Spec.GroupsPrefix},
				)
			}
		}

		if c.managementCluster != nil {
			enabledControllers = append(enabledControllers, "managedcluster")
		}

		if c.cr.CalicoNetwork != nil && c.cr.CalicoNetwork.MultiInterfaceMode != nil {
			env = append(env, v1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cr.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	env = append(env, v1.EnvVar{Name: "ENABLED_CONTROLLERS", Value: strings.Join(enabledControllers, ",")})

	defaultMode := int32(420)

	container := v1.Container{
		Name:      "calico-kube-controllers",
		Image:     c.image,
		Env:       env,
		Resources: c.kubeControllersResources(),
		ReadinessProbe: &v1.Probe{
			PeriodSeconds: int32(10),
			Handler: v1.Handler{
				Exec: &v1.ExecAction{
					Command: []string{
						"/usr/bin/check-status",
						"-r",
					},
				},
			},
			TimeoutSeconds: 10,
		},
		LivenessProbe: &v1.Probe{
			PeriodSeconds:       int32(10),
			InitialDelaySeconds: int32(10),
			FailureThreshold:    int32(6),
			Handler: v1.Handler{
				Exec: &v1.ExecAction{
					Command: []string{
						"/usr/bin/check-status",
						"-l",
					},
				},
			},
			TimeoutSeconds: 10,
		},
		VolumeMounts: kubeControllersVolumeMounts(c.managerInternalSecret),
	}

	if c.logStorageExists && c.kubeControllersGatewaySecret != nil && c.elasticsearchSecret != nil {
		container = relasticsearch.ContainerDecorate(container, DefaultElasticsearchClusterName,
			ElasticsearchKubeControllersUserSecret, c.clusterDomain, rmeta.OSTypeLinux)
	}

	podSpec := v1.PodSpec{
		NodeSelector:       c.cr.ControlPlaneNodeSelector,
		Tolerations:        append(c.cr.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly),
		ImagePullSecrets:   c.cr.ImagePullSecrets,
		ServiceAccountName: "calico-kube-controllers",
		Containers:         []v1.Container{container},
		Volumes:            kubeControllersVolumes(defaultMode, c.managerInternalSecret),
	}

	if c.logStorageExists && c.kubeControllersGatewaySecret != nil && c.elasticsearchSecret != nil {
		podSpec = relasticsearch.PodSpecDecorate(podSpec)
	}

	d := apps.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				"k8s-app": "calico-kube-controllers",
			},
		},
		Spec: apps.DeploymentSpec{
			Replicas: &replicas,
			Strategy: apps.DeploymentStrategy{
				Type: apps.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "calico-kube-controllers",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-kube-controllers",
					Namespace: common.CalicoNamespace,
					Labels: map[string]string{
						"k8s-app": "calico-kube-controllers",
					},
					Annotations: c.annotations(),
				},
				Spec: podSpec,
			},
		},
	}
	setCriticalPod(&(d.Spec.Template))

	return &d
}

// prometheusService creates a Service which exposes and endpoint on kube-controllers for
// reporting Prometheus metrics.
func (c *kubeControllersComponent) prometheusService() *v1.Service {
	return &v1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers-metrics",
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": "calico-kube-controllers"},
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{"k8s-app": "calico-kube-controllers"},
			Type:     v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				{
					Name:       "metrics-port",
					Port:       int32(c.metricsPort),
					TargetPort: intstr.FromInt(int(c.metricsPort)),
					Protocol:   v1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *kubeControllersComponent) isManagedCluster() bool {
	return c.managementClusterConnection != nil
}

// kubeControllerResources creates the kube-controller's resource requirements.
func (c *kubeControllersComponent) kubeControllersResources() v1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cr, operator.ComponentNameKubeControllers)
}

func (c *kubeControllersComponent) annotations() map[string]string {
	am := map[string]string{}
	if c.managerInternalSecret != nil {
		am[ManagerInternalTLSHashAnnotation] = rmeta.AnnotationHash(c.managerInternalSecret.Data)
	}
	if c.elasticsearchSecret != nil {
		am[tlsSecretHashAnnotation] = rmeta.AnnotationHash(c.elasticsearchSecret.Data)
	}
	if c.kubeControllersGatewaySecret != nil {
		am[ElasticsearchUserHashAnnotation] = rmeta.AnnotationHash(c.kubeControllersGatewaySecret.Data)
	}
	if c.kibanaSecret != nil {
		am[KibanaTLSHashAnnotation] = rmeta.AnnotationHash(c.kibanaSecret.Data)
	}
	return am
}

func (c *kubeControllersComponent) controllersPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName("calico-kube-controllers")
	return psp
}

func kubeControllersVolumeMounts(managerSecret *v1.Secret) []v1.VolumeMount {
	if managerSecret != nil {
		return []v1.VolumeMount{{
			Name:      ManagerInternalTLSSecretName,
			MountPath: "/manager-tls",
			ReadOnly:  true,
		}}
	}

	return []v1.VolumeMount{}
}

func kubeControllersVolumes(defaultMode int32, managerSecret *v1.Secret) []v1.Volume {
	if managerSecret != nil {

		return []v1.Volume{
			{
				Name: ManagerInternalTLSSecretName,
				VolumeSource: v1.VolumeSource{
					Secret: &v1.SecretVolumeSource{
						DefaultMode: &defaultMode,
						SecretName:  ManagerInternalTLSSecretName,
						Items: []v1.KeyToPath{
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

	return []v1.Volume{}
}
