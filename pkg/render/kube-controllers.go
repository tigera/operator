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

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
)

var replicas int32 = 1

func KubeControllers(
	cr *operator.InstallationSpec,
	logStorageExists bool,
	managementCluster *operator.ManagementCluster,
	managementClusterConnection *operator.ManagementClusterConnection,
	managerInternalSecret *v1.Secret,
	authentication *operator.Authentication,
) *kubeControllersComponent {
	return &kubeControllersComponent{
		cr:                          cr,
		managementCluster:           managementCluster,
		managementClusterConnection: managementClusterConnection,
		managerInternalSecret:       managerInternalSecret,
		logStorageExists:            logStorageExists,
		authentication:              authentication,
	}
}

type kubeControllersComponent struct {
	cr                          *operator.InstallationSpec
	managementCluster           *operator.ManagementCluster
	managementClusterConnection *operator.ManagementClusterConnection
	managerInternalSecret       *v1.Secret
	logStorageExists            bool
	authentication              *operator.Authentication
}

func (c *kubeControllersComponent) SupportedOSType() OSType {
	return OSTypeLinux
}

func (c *kubeControllersComponent) Objects() ([]runtime.Object, []runtime.Object) {
	kubeControllerObjects := []runtime.Object{
		c.controllersServiceAccount(),
		c.controllersRole(),
		c.controllersRoleBinding(),
		c.controllersDeployment(),
	}
	if c.managerInternalSecret != nil {
		kubeControllerObjects = append(kubeControllerObjects, secretsToRuntimeObjects(CopySecrets(common.CalicoNamespace, c.managerInternalSecret)...)...)
	}

	if c.cr.KubernetesProvider != operator.ProviderOpenShift {
		kubeControllerObjects = append(kubeControllerObjects, c.controllersPodSecurityPolicy())
	}

	return kubeControllerObjects, nil
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
				// Pods are queried to check for existence.
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
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
				Verbs:     []string{"get", "list", "create", "update", "delete"},
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
				Resources: []string{"configmaps", "secrets"},
				Verbs:     []string{"watch", "list", "get", "update", "create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"watch", "list", "get"},
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
	tolerations := []v1.Toleration{
		{Key: "CriticalAddonsOnly", Operator: v1.TolerationOpExists},
		{Key: "node-role.kubernetes.io/master", Effect: v1.TaintEffectNoSchedule},
	}

	env := []v1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
	}

	enabledControllers := []string{"node"}
	if c.cr.Variant == operator.TigeraSecureEnterprise {
		enabledControllers = append(enabledControllers, "service", "federatedservices")

		if c.logStorageExists {
			// These controllers require that Elasticsearch exists within the cluster Kube Controllers is running in, i.e.
			// Full Standalone and Management clusters, not Minimal Standalone and Managed clusters.
			enabledControllers = append(enabledControllers, "authorization", "elasticsearchconfiguration")

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

	// Pick which image to use based on variant.
	image := components.GetReference(components.ComponentCalicoKubeControllers, c.cr.Registry, c.cr.ImagePath)
	if c.cr.Variant == operator.TigeraSecureEnterprise {
		image = components.GetReference(components.ComponentTigeraKubeControllers, c.cr.Registry, c.cr.ImagePath)
	}

	defaultMode := int32(420)

	d := apps.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				"k8s-app": "calico-kube-controllers",
			},
			Annotations: c.annotations(),
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
				},
				Spec: v1.PodSpec{
					NodeSelector:       c.cr.ControlPlaneNodeSelector,
					Tolerations:        tolerations,
					ImagePullSecrets:   c.cr.ImagePullSecrets,
					ServiceAccountName: "calico-kube-controllers",
					Containers: []v1.Container{
						{
							Name:      "calico-kube-controllers",
							Image:     image,
							Env:       env,
							Resources: c.kubeControllersResources(),
							ReadinessProbe: &v1.Probe{
								Handler: v1.Handler{
									Exec: &v1.ExecAction{
										Command: []string{
											"/usr/bin/check-status",
											"-r",
										},
									},
								},
							},
							VolumeMounts: kubeControllersVolumeMounts(c.managerInternalSecret),
						},
					},
					Volumes: kubeControllersVolumes(defaultMode, c.managerInternalSecret),
				},
			},
		},
	}
	setCriticalPod(&(d.Spec.Template))

	return &d
}

// kubeControllerResources creates the kube-controller's resource requirements.
func (c *kubeControllersComponent) kubeControllersResources() v1.ResourceRequirements {
	return GetResourceRequirements(c.cr, operator.ComponentNameKubeControllers)
}

func (c *kubeControllersComponent) annotations() map[string]string {
	if c.managerInternalSecret == nil {
		return make(map[string]string)
	}

	return map[string]string{
		ManagerInternalTLSHashAnnotation: AnnotationHash(c.managerInternalSecret.Data),
	}
}

func (c *kubeControllersComponent) controllersPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := basePodSecurityPolicy()
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
