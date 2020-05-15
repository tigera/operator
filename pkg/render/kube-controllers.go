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

	"github.com/tigera/operator/pkg/components"
	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/common"
)

var replicas int32 = 1

func KubeControllers(cr *operator.Installation, managerInternalSecret *v1.Secret) *kubeControllersComponent {
	return &kubeControllersComponent{
		cr:                    cr,
		managerInternalSecret: managerInternalSecret,
	}
}

type kubeControllersComponent struct {
	cr                    *operator.Installation
	managerInternalSecret *v1.Secret
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

	if c.cr.Spec.KubernetesProvider != operator.ProviderOpenShift {
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
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"calico-kube-controllers"},
			},
		},
	}

	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
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
		}

		role.Rules = append(role.Rules, extraRules...)

		if c.cr.Spec.ClusterManagementType == operator.ClusterManagementTypeManagement {
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
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		enabledControllers = append(enabledControllers, "service", "federatedservices")

		if c.cr.Spec.ClusterManagementType != operator.ClusterManagementTypeManaged {
			enabledControllers = append(enabledControllers, "elasticsearchconfiguration")
		}

		if c.cr.Spec.ClusterManagementType == operator.ClusterManagementTypeManagement {
			enabledControllers = append(enabledControllers, "managedcluster")
		}

		if c.cr.Spec.CalicoNetwork != nil && c.cr.Spec.CalicoNetwork.MultiInterfaceMode != nil {
			env = append(env, v1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cr.Spec.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	env = append(env, v1.EnvVar{Name: "ENABLED_CONTROLLERS", Value: strings.Join(enabledControllers, ",")})

	// Pick which image to use based on variant.
	image := components.GetReference(components.ComponentCalicoKubeControllers, c.cr.Spec.Registry, c.cr.Spec.ImagePath)
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		image = components.GetReference(components.ComponentTigeraKubeControllers, c.cr.Spec.Registry, c.cr.Spec.ImagePath)
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
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					Tolerations:        tolerations,
					ImagePullSecrets:   c.cr.Spec.ImagePullSecrets,
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

	// Add the ControlPlaneNodeSelector to our Deployment if one was specified.
	for k, v := range c.cr.Spec.ControlPlaneNodeSelector {
		d.Spec.Template.Spec.NodeSelector[k] = v
	}

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
	falseBool := false
	ptrBoolFalse := &falseBool
	return &policyv1beta1.PodSecurityPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "PodSecurityPolicy", APIVersion: "policy/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-kube-controllers",
			Namespace: common.CalicoNamespace,
			Annotations: map[string]string{
				"seccomp.security.alpha.kubernetes.io/allowedProfileNames": "*",
			},
		},
		Spec: policyv1beta1.PodSecurityPolicySpec{
			Privileged:               false,
			AllowPrivilegeEscalation: ptrBoolFalse,
			RequiredDropCapabilities: []v1.Capability{
				v1.Capability("ALL"),
			},
			Volumes: []policyv1beta1.FSType{
				policyv1beta1.ConfigMap,
				policyv1beta1.EmptyDir,
				policyv1beta1.Projected,
				policyv1beta1.Secret,
				policyv1beta1.DownwardAPI,
				policyv1beta1.PersistentVolumeClaim,
			},
			HostNetwork: false,
			HostPorts: []policyv1beta1.HostPortRange{
				policyv1beta1.HostPortRange{
					Min: int32(0),
					Max: int32(65535),
				},
			},
			HostIPC: false,
			HostPID: false,
			RunAsUser: policyv1beta1.RunAsUserStrategyOptions{
				Rule: policyv1beta1.RunAsUserStrategyMustRunAsNonRoot,
			},
			SELinux: policyv1beta1.SELinuxStrategyOptions{
				Rule: policyv1beta1.SELinuxStrategyRunAsAny,
			},
			SupplementalGroups: policyv1beta1.SupplementalGroupsStrategyOptions{
				Rule: policyv1beta1.SupplementalGroupsStrategyMustRunAs,
				Ranges: []policyv1beta1.IDRange{
					{
						Min: int64(1),
						Max: int64(65535),
					},
				},
			},
			FSGroup: policyv1beta1.FSGroupStrategyOptions{
				Rule: policyv1beta1.FSGroupStrategyMustRunAs,
				Ranges: []policyv1beta1.IDRange{
					{
						Min: int64(1),
						Max: int64(65535),
					},
				},
			},
			ReadOnlyRootFilesystem: false,
		},
	}
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
