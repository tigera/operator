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
	KubeController               = "calico-kube-controllers"
	KubeControllerServiceAccount = "calico-kube-controllers"
	KubeControllerRole           = "calico-kube-controllers"
	KubeControllerRoleBinding    = "calico-kube-controllers"
)

func KubeControllers(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operator.InstallationSpec,
	managementCluster *operator.ManagementCluster,
	managementClusterConnection *operator.ManagementClusterConnection,
	managerInternalSecret *v1.Secret,
	clusterDomain string,
	metricsPort int,
) *kubeControllersComponent {
	return &kubeControllersComponent{
		cr:                          cr,
		managementCluster:           managementCluster,
		managementClusterConnection: managementClusterConnection,
		managerInternalSecret:       managerInternalSecret,
		k8sServiceEp:                k8sServiceEp,
		clusterDomain:               clusterDomain,
		metricsPort:                 metricsPort,
	}
}

type kubeControllersComponent struct {
	cr                          *operator.InstallationSpec
	managementCluster           *operator.ManagementCluster
	managementClusterConnection *operator.ManagementClusterConnection
	managerInternalSecret       *v1.Secret
	authentication              *operator.Authentication
	k8sServiceEp                k8sapi.ServiceEndpoint
	image                       string
	clusterDomain               string
	metricsPort                 int
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
			Name:      KubeControllerServiceAccount,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
	}
}

func (c *kubeControllersComponent) controllersRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeControllerRole,
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
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"watch", "list", "get", "update", "create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"deletecollection"},
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
			ResourceNames: []string{KubeController},
		})
	}

	return role
}

func (c *kubeControllersComponent) controllersRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   KubeControllerRoleBinding,
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     KubeControllerRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      KubeControllerServiceAccount,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

func (c *kubeControllersComponent) controllersDeployment() *apps.Deployment {
	env := []v1.EnvVar{
		{Name: "KUBE_CONTROLLERS_CONFIG_NAME", Value: "default"},
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
	}

	env = append(env, c.k8sServiceEp.EnvVars()...)

	enabledControllers := []string{"node"}
	if c.cr.Variant == operator.TigeraSecureEnterprise {
		enabledControllers = append(enabledControllers, "service", "federatedservices")

		if c.cr.CalicoNetwork != nil && c.cr.CalicoNetwork.MultiInterfaceMode != nil {
			env = append(env, v1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cr.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	env = append(env, v1.EnvVar{Name: "ENABLED_CONTROLLERS", Value: strings.Join(enabledControllers, ",")})

	defaultMode := int32(420)

	container := v1.Container{
		Name:      KubeController,
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
		},
		VolumeMounts: kubeControllersVolumeMounts(c.managerInternalSecret),
	}

	podSpec := v1.PodSpec{
		NodeSelector:       c.cr.ControlPlaneNodeSelector,
		Tolerations:        append(c.cr.ControlPlaneTolerations, rmeta.TolerateMaster, rmeta.TolerateCriticalAddonsOnly),
		ImagePullSecrets:   c.cr.ImagePullSecrets,
		ServiceAccountName: KubeControllerServiceAccount,
		Containers:         []v1.Container{container},
		Volumes:            kubeControllersVolumes(defaultMode, c.managerInternalSecret),
	}

	d := apps.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeController,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				"k8s-app": KubeController,
			},
		},
		Spec: apps.DeploymentSpec{
			Replicas: &replicas,
			Strategy: apps.DeploymentStrategy{
				Type: apps.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": KubeController,
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      KubeController,
					Namespace: common.CalicoNamespace,
					Labels: map[string]string{
						"k8s-app": KubeController,
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
			Labels:    map[string]string{"k8s-app": KubeController},
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{"k8s-app": KubeController},
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
	return am
}

func (c *kubeControllersComponent) controllersPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(KubeController)
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
