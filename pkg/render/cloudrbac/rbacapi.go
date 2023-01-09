// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package cloudrbac

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"

	operatorv1 "github.com/tigera/operator/api/v1"
	oprender "github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	RBACApiName                               = "cc-rbac-api"
	RBACApiNamespace                          = "calico-cloud-rbac"
	RBACApiDeploymentName                     = RBACApiName
	RBACApiServiceAccountName                 = "calico-cloud-rbac-api"
	RBACApiClusterRoleName                    = "calico-cloud-rbac-api"
	RBACApiClusterRoleBindingName             = "calico-cloud-rbac-api"
	RBACApiNetworkAdminClusterRoleBindingName = "calico-cloud-rbac-api-network-admin"
	RBACApiContainerName                      = "api"
	RBACApiServiceName                        = RBACApiName
	RBACAPICertSecretName                     = "calico-cloud-rbac-tls"
)

func RBACApi(cfg *Configuration) oprender.Component {
	return &rbacApiComponent{config: cfg}
}

type Configuration struct {
	PullSecrets        []*corev1.Secret
	Installation       *operatorv1.InstallationSpec
	TrustedBundle      certificatemanagement.TrustedBundle
	TLSKeyPair         certificatemanagement.KeyPairInterface
	KeyValidatorConfig authentication.KeyValidatorConfig
	PortalURL          string
	rbacApiImage       string
}

type rbacApiComponent struct {
	config *Configuration
}

func (c *rbacApiComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		oprender.CreateNamespace(RBACApiNamespace, c.config.Installation.KubernetesProvider, oprender.PSSRestricted),
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.networkAdminClusterRoleBinding(),
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(RBACApiNamespace, c.config.PullSecrets...)...)...)

	if c.config.KeyValidatorConfig != nil {
		objs = append(objs, secret.ToRuntimeObjects(c.config.KeyValidatorConfig.RequiredSecrets(RBACApiNamespace)...)...)
		objs = append(objs, configmap.ToRuntimeObjects(c.config.KeyValidatorConfig.RequiredConfigMaps(RBACApiNamespace)...)...)
	}

	objs = append(objs,
		c.deployment(),
		c.service(),
	)

	return objs, []client.Object{}
}

func (c *rbacApiComponent) Ready() bool {
	return true
}

func (c *rbacApiComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *rbacApiComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.config.Installation.Registry
	path := c.config.Installation.ImagePath
	prefix := c.config.Installation.ImagePrefix
	var err error
	c.config.rbacApiImage, err = components.GetReference(components.ComponentCloudRBACApi, reg, path, prefix, is)
	return err
}

func (c *rbacApiComponent) serviceAccount() client.Object {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: RBACApiServiceAccountName, Namespace: RBACApiNamespace},
	}
}

func (c *rbacApiComponent) clusterRole() client.Object {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterrolebindings"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
		},
		{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: RBACApiClusterRoleName,
		},
		Rules: policyRules,
	}
}

func (c *rbacApiComponent) clusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: RBACApiClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     RBACApiClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      RBACApiServiceAccountName,
				Namespace: RBACApiNamespace,
			},
		},
	}
}

func (c *rbacApiComponent) networkAdminClusterRoleBinding() client.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: RBACApiNetworkAdminClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-network-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      RBACApiServiceAccountName,
				Namespace: RBACApiNamespace,
			},
		},
	}
}

func (c *rbacApiComponent) deployment() client.Object {
	var replicas int32 = 1

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RBACApiDeploymentName,
			Namespace: RBACApiNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        RBACApiDeploymentName,
					Namespace:   RBACApiNamespace,
					Annotations: c.config.TrustedBundle.HashAnnotations(),
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.config.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: RBACApiServiceAccountName,
					Tolerations:        append(c.config.Installation.ControlPlaneTolerations, rmeta.TolerateAll...),
					ImagePullSecrets:   secret.GetReferenceList(c.config.PullSecrets),
					RestartPolicy:      corev1.RestartPolicyAlways,
					Containers:         c.container(),
					Volumes:            c.volumes(),
				},
			},
		},
	}
}

func (c *rbacApiComponent) container() []corev1.Container {
	securityContext := securitycontext.NewBaseContext(1000, 0)
	// Build a security context for the pod that will allow the pod to be deployed
	securityContext.Capabilities = &corev1.Capabilities{
		Drop: []corev1.Capability{"ALL"},
	}
	securityContext.SeccompProfile = &corev1.SeccompProfile{
		Type: corev1.SeccompProfileTypeRuntimeDefault,
	}

	env := []corev1.EnvVar{
		{Name: "CC_RBAC_API_LISTEN_ADDR", Value: ":8443"},
		{Name: "CC_RBAC_API_LOG_LEVEL", Value: "INFO"},
		{Name: "CC_RBAC_API_HTTPS_ENABLED", Value: "true"},
		{Name: "CC_RBAC_API_HTTPS_KEY", Value: c.config.TLSKeyPair.VolumeMountKeyFilePath()},
		{Name: "CC_RBAC_API_HTTPS_CERT", Value: c.config.TLSKeyPair.VolumeMountCertificateFilePath()},
		{Name: "CC_RBAC_API_PORTAL_URL", Value: c.config.PortalURL},
		{Name: "CC_RBAC_API_OPEN_TELEMETRY_ENABLED", Value: "true"},
	}

	volumeMounts := []corev1.VolumeMount{
		c.config.TrustedBundle.VolumeMount(c.SupportedOSType()),
		c.config.TLSKeyPair.VolumeMount(c.SupportedOSType()),
	}

	if kvc := c.config.KeyValidatorConfig; kvc != nil {
		env = append(env, kvc.RequiredEnv("CC_RBAC_API_")...)
		volumeMounts = append(volumeMounts, kvc.RequiredVolumeMounts()...)
	}

	return []corev1.Container{
		{
			Name:            RBACApiContainerName,
			Image:           c.config.rbacApiImage,
			ImagePullPolicy: corev1.PullAlways,
			SecurityContext: securityContext,
			Env:             env,
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("750m"),
					corev1.ResourceMemory: resource.MustParse("150Mi"),
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("250m"),
					corev1.ResourceMemory: resource.MustParse("50Mi"),
				},
			},
			VolumeMounts: volumeMounts,
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path:   "/health",
						Port:   intstr.FromInt(8443),
						Scheme: corev1.URISchemeHTTPS,
					},
				},
				InitialDelaySeconds: 90,
				PeriodSeconds:       10,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path:   "/health",
						Port:   intstr.FromInt(8443),
						Scheme: corev1.URISchemeHTTPS,
					},
				},
				FailureThreshold: 10,
				PeriodSeconds:    10,
				SuccessThreshold: 1,
				TimeoutSeconds:   1,
			},
		},
	}
}

func (c *rbacApiComponent) volumes() []corev1.Volume {
	volumes := []corev1.Volume{
		c.config.TrustedBundle.Volume(),
		c.config.TLSKeyPair.Volume(),
	}

	if c.config.KeyValidatorConfig != nil {
		volumes = append(volumes, c.config.KeyValidatorConfig.RequiredVolumes()...)
	}

	return volumes
}

func (c *rbacApiComponent) service() *corev1.Service {
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RBACApiServiceName,
			Namespace: RBACApiNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeClusterIP,
			Selector:              map[string]string{"k8s-app": RBACApiDeploymentName},
			InternalTrafficPolicy: &internalTrafficPolicy,
			Ports: []corev1.ServicePort{
				{Name: "api-port", Port: 8443, Protocol: corev1.ProtocolTCP},
			},
		},
	}
}
