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
	"fmt"
	"strings"

	"github.com/tigera/operator/pkg/ptr"

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
	"github.com/tigera/operator/pkg/controller/migration"
	"github.com/tigera/operator/pkg/dns"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	TyphaServiceName              = "calico-typha"
	TyphaPortName                 = "calico-typha"
	TyphaK8sAppName               = "calico-typha"
	TyphaServiceAccountName       = "calico-typha"
	AppLabelName                  = "k8s-app"
	TyphaPort               int32 = 5473
	TyphaCAHashAnnotation         = "hash.operator.tigera.io/typha-ca"
	TyphaCertHashAnnotation       = "hash.operator.tigera.io/typha-cert"
)

var (
	TyphaTLSSecretName   = "typha-certs"
	TyphaCAConfigMapName = "typha-ca"
	TyphaCABundleName    = "caBundle"
)

// TyphaConfiguration is the public API used to provide information to the render code to
// generate Kubernetes objects for installing calico/typha on a cluster.
type TyphaConfiguration struct {
	K8sServiceEp           k8sapi.ServiceEndpoint
	Installation           *operatorv1.InstallationSpec
	TLS                    *TyphaNodeTLS
	AmazonCloudIntegration *operatorv1.AmazonCloudIntegration
	MigrateNamespaces      bool
	ClusterDomain          string
}

// Typha creates the typha daemonset and other resources for the daemonset to operate normally.
func Typha(cfg *TyphaConfiguration) Component {
	return &typhaComponent{cfg: cfg}
}

type typhaComponent struct {
	// Given configuration.
	cfg *TyphaConfiguration

	// Generated internal config, built from the given configuration.
	typhaImage       string
	certSignReqImage string
}

func (c *typhaComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.typhaImage, err = components.GetReference(components.ComponentTigeraTypha, reg, path, prefix, is)
	} else {
		c.typhaImage, err = components.GetReference(components.ComponentCalicoTypha, reg, path, prefix, is)
	}
	errMsgs := []string{}
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if c.cfg.Installation.CertificateManagement != nil {
		c.certSignReqImage, err = ResolveCSRInitImage(c.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *typhaComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *typhaComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.typhaServiceAccount(),
		c.typhaRole(),
		c.typhaRoleBinding(),
		c.typhaService(),
		c.typhaPodDisruptionBudget(),
	}

	if c.cfg.TLS.TyphaSecret != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(common.CalicoNamespace, c.cfg.TLS.TyphaSecret)...)...)
	}

	if c.cfg.Installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		objs = append(objs, c.typhaPodSecurityPolicy())
	}

	if c.cfg.Installation.CertificateManagement != nil {
		objs = append(objs, CSRClusterRoleBinding("calico-typha", common.CalicoNamespace))
	}

	// Add deployment last, as it may depend on the creation of previous objects in the list.
	objs = append(objs, c.typhaDeployment())

	return objs, nil
}

func (c *typhaComponent) typhaPodDisruptionBudget() *policyv1beta1.PodDisruptionBudget {
	maxUnavailable := intstr.FromInt(1)
	return &policyv1beta1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.TyphaDeploymentName,
			Namespace: common.CalicoNamespace,
		},
		Spec: policyv1beta1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					AppLabelName: TyphaK8sAppName,
				},
			},
		},
	}
}

func (c *typhaComponent) Ready() bool {
	return true
}

// typhaServiceAccount creates the typha's service account.
func (c *typhaComponent) typhaServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaServiceAccountName,
			Namespace: common.CalicoNamespace,
		},
	}
}

// typhaRoleBinding creates a clusterrolebinding giving the typha service account the required permissions to operate.
func (c *typhaComponent) typhaRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-typha",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-typha",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      TyphaServiceAccountName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
}

// typhaRole creates the clusterrole containing policy rules that allow the typha deployment to operate normally.
func (c *typhaComponent) typhaRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-typha",
			Labels: map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
			{
				// Calico uses endpoint slices for service-based network policy rules.
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"list", "watch"},
			},
			{
				// The CNI plugin needs to get pods, nodes, namespaces.
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				// Used to discover Typha endpoints and service IPs for advertisement.
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				// Some information is stored on the node status.
				APIGroups: []string{""},
				Resources: []string{"nodes/status"},
				Verbs:     []string{"patch", "update"},
			},
			{
				// For enforcing network policies.
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// Metadata from these are used in conjunction with network policy.
				APIGroups: []string{""},
				Resources: []string{"pods", "namespaces", "serviceaccounts"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// Calico patches the allocated IP onto the pod.
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				// For monitoring Calico-specific configuration.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"bgpconfigurations",
					"bgppeers",
					"blockaffinities",
					"caliconodestatuses",
					"clusterinformations",
					"felixconfigurations",
					"globalnetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
					"ipamblocks",
					"ippools",
					"ipreservations",
					"networkpolicies",
					"networksets",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// For migration code in calico/node startup only. Remove when the migration
				// code is removed from node.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"globalbgpconfigs",
					"globalfelixconfigs",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Calico creates some configuration on startup.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"clusterinformations",
					"felixconfigurations",
					"ippools",
				},
				Verbs: []string{"create", "update"},
			},
			{
				// Calico monitors nodes for some networking configuration.
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				// Most IPAM resources need full CRUD permissions so we can allocate and
				// release IP addresses for pods.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"blockaffinities",
					"ipamblocks",
					"ipamhandles",
				},
				Verbs: []string{"get", "list", "create", "update", "delete"},
			},
			{
				// But, we only need to be able to query for IPAM config.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"ipamconfigs"},
				Verbs:     []string{"get"},
			},
			{
				// confd (and in some cases, felix) watches block affinities for route aggregation.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"blockaffinities"},
				Verbs:     []string{"watch"},
			},
		},
	}
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		extraRules := []rbacv1.PolicyRule{
			{
				// Tigera Secure needs to be able to read licenses, tiers, and config.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"licensekeys",
					"remoteclusterconfigurations",
					"stagedglobalnetworkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"tiers",
					"packetcaptures",
					"deeppacketinspections",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Tigera Secure creates some tiers on startup.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"create"},
			},
		}
		role.Rules = append(role.Rules, extraRules...)
	}
	if c.cfg.Installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		role.Rules = append(role.Rules, rbacv1.PolicyRule{APIGroups: []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{common.TyphaDeploymentName},
		})
	}
	return role
}

// typhaDeployment creates the typha deployment.
func (c *typhaComponent) typhaDeployment() *appsv1.Deployment {
	var terminationGracePeriod int64 = 0
	var revisionHistoryLimit int32 = 2
	maxUnavailable := intstr.FromInt(1)
	maxSurge := intstr.FromString("25%")

	var initContainers []corev1.Container
	annotations := make(map[string]string)
	annotations[TyphaCAHashAnnotation] = rmeta.AnnotationHash(c.cfg.TLS.CAConfigMap.Data)
	if c.cfg.Installation.CertificateManagement == nil {
		annotations[TyphaCertHashAnnotation] = rmeta.AnnotationHash(c.cfg.TLS.TyphaSecret.Data)
	} else {
		initContainers = append(initContainers, CreateCSRInitContainer(
			c.cfg.Installation.CertificateManagement,
			c.certSignReqImage,
			"typha-certs",
			TyphaCommonName,
			TLSSecretKeyName,
			TLSSecretCertName,
			dns.GetServiceDNSNames(TyphaServiceName, common.CalicoNamespace, c.cfg.ClusterDomain),
			CSRLabelCalicoSystem))
	}

	// Include annotation for prometheus scraping configuration.
	if c.cfg.Installation.TyphaMetricsPort != nil {
		annotations["prometheus.io/scrape"] = "true"
		annotations["prometheus.io/port"] = fmt.Sprintf("%d", *c.cfg.Installation.TyphaMetricsPort)
	}

	// Allow tolerations to be overwritten by the end-user.
	tolerations := rmeta.TolerateAll
	if len(c.cfg.Installation.ControlPlaneTolerations) != 0 {
		tolerations = c.cfg.Installation.ControlPlaneTolerations
	}

	d := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.TyphaDeploymentName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{AppLabelName: TyphaK8sAppName},
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavailable,
					MaxSurge:       &maxSurge,
				},
			},
			RevisionHistoryLimit: &revisionHistoryLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						AppLabelName: TyphaK8sAppName,
					},
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					Tolerations:                   tolerations,
					Affinity:                      c.affinity(),
					ImagePullSecrets:              c.cfg.Installation.ImagePullSecrets,
					ServiceAccountName:            TyphaServiceAccountName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                initContainers,
					Containers:                    []corev1.Container{c.typhaContainer()},
					Volumes:                       c.volumes(),
				},
			},
		},
	}
	SetClusterCriticalPod(&(d.Spec.Template))
	if c.cfg.MigrateNamespaces {
		migration.SetTyphaAntiAffinity(&d)
	}
	return &d
}

// volumes creates the typha's volumes.
func (c *typhaComponent) volumes() []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "typha-ca",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: TyphaCAConfigMapName,
					},
				},
			},
		},
		{
			Name:         "typha-certs",
			VolumeSource: certificateVolumeSource(c.cfg.Installation.CertificateManagement, TyphaTLSSecretName),
		},
	}

	return volumes
}

// typhaVolumeMounts creates the typha's volume mounts.
func (c *typhaComponent) typhaVolumeMounts() []corev1.VolumeMount {
	volumeMounts := []corev1.VolumeMount{
		{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
		{MountPath: "/typha-certs", Name: "typha-certs", ReadOnly: true},
	}

	return volumeMounts
}

func (c *typhaComponent) typhaPorts() []corev1.ContainerPort {
	return []corev1.ContainerPort{
		{
			ContainerPort: TyphaPort,
			Name:          TyphaPortName,
			Protocol:      corev1.ProtocolTCP,
		},
	}
}

// typhaContainer creates the main typha container.
func (c *typhaComponent) typhaContainer() corev1.Container {
	lp, rp := c.livenessReadinessProbes()

	return corev1.Container{
		Name:           "calico-typha",
		Image:          c.typhaImage,
		Resources:      c.typhaResources(),
		Env:            c.typhaEnvVars(),
		VolumeMounts:   c.typhaVolumeMounts(),
		Ports:          c.typhaPorts(),
		LivenessProbe:  lp,
		ReadinessProbe: rp,
	}
}

// typhaResources creates the typha's resource requirements.
func (c *typhaComponent) typhaResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameTypha)
}

// typhaEnvVars creates the typha's envvars.
func (c *typhaComponent) typhaEnvVars() []corev1.EnvVar {
	var cnEnv corev1.EnvVar
	if c.cfg.Installation.CertificateManagement != nil {
		cnEnv = corev1.EnvVar{
			Name: "TYPHA_CLIENTCN", Value: FelixCommonName,
		}
	} else {
		cnEnv = corev1.EnvVar{
			Name: "TYPHA_CLIENTCN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: NodeTLSSecretName,
					},
					Key:      CommonName,
					Optional: ptr.BoolToPtr(true),
				},
			},
		}
	}

	typhaEnv := []corev1.EnvVar{
		{Name: "TYPHA_LOGSEVERITYSCREEN", Value: "info"},
		{Name: "TYPHA_LOGFILEPATH", Value: "none"},
		{Name: "TYPHA_LOGSEVERITYSYS", Value: "none"},
		{Name: "TYPHA_CONNECTIONREBALANCINGMODE", Value: "kubernetes"},
		{Name: "TYPHA_DATASTORETYPE", Value: "kubernetes"},
		{Name: "TYPHA_HEALTHENABLED", Value: "true"},
		{Name: "TYPHA_K8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "TYPHA_CAFILE", Value: "/typha-ca/caBundle"},
		{Name: "TYPHA_SERVERCERTFILE", Value: fmt.Sprintf("/typha-certs/%s", TLSSecretCertName)},
		{Name: "TYPHA_SERVERKEYFILE", Value: fmt.Sprintf("/typha-certs/%s", TLSSecretKeyName)},
		// We need at least the CN or URISAN set, we depend on the validation
		// done by the core_controller that the Secret will have one.
		cnEnv,
		{Name: "TYPHA_CLIENTURISAN", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: NodeTLSSecretName,
				},
				Key:      URISAN,
				Optional: ptr.BoolToPtr(true),
			},
		}},
	}

	switch c.cfg.Installation.CNI.Type {
	case operatorv1.PluginAmazonVPC:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
	case operatorv1.PluginGKE:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "gke"})
	case operatorv1.PluginAzureVNET:
		typhaEnv = append(typhaEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "azv"})
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
			typhaEnv = append(typhaEnv, corev1.EnvVar{
				Name:  "MULTI_INTERFACE_MODE",
				Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	typhaEnv = append(typhaEnv, GetTigeraSecurityGroupEnvVariables(c.cfg.AmazonCloudIntegration)...)
	typhaEnv = append(typhaEnv, c.cfg.K8sServiceEp.EnvVars(true, c.cfg.Installation.KubernetesProvider)...)

	if c.cfg.Installation.TyphaMetricsPort != nil {
		// If a typha metrics port was given, then enable typha prometheus metrics and set the port.
		typhaEnv = append(typhaEnv,
			corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSENABLED", Value: "true"},
			corev1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSPORT", Value: fmt.Sprintf("%d", *c.cfg.Installation.TyphaMetricsPort)},
		)
	}

	return typhaEnv
}

// livenessReadinessProbes creates the typha's liveness and readiness probes.
func (c *typhaComponent) livenessReadinessProbes() (*corev1.Probe, *corev1.Probe) {
	// Determine liveness and readiness configuration for typha.
	port := intstr.FromInt(9098)
	lp := &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: "localhost",
				Path: "/liveness",
				Port: port,
			},
		},
		TimeoutSeconds: 10,
	}
	rp := &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: "localhost",
				Path: "/readiness",
				Port: port,
			},
		},
		TimeoutSeconds: 10,
	}
	return lp, rp
}

func (c *typhaComponent) typhaService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaServiceName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       TyphaPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromString(TyphaPortName),
					Name:       TyphaPortName,
				},
			},
			Selector: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
	}
}

func (c *typhaComponent) typhaPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(common.TyphaDeploymentName)
	psp.Spec.HostNetwork = true
	return psp
}

// affinity sets the user-specified typha affinity if specified.
func (c *typhaComponent) affinity() (aff *corev1.Affinity) {
	if c.cfg.Installation.TyphaAffinity != nil && c.cfg.Installation.TyphaAffinity.NodeAffinity != nil {
		// this ensures we return nil if no affinity is specified.
		if c.cfg.Installation.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil && len(c.cfg.Installation.TyphaAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution) == 0 {
			return nil
		}
		aff = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution:  c.cfg.Installation.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
			PreferredDuringSchedulingIgnoredDuringExecution: c.cfg.Installation.TyphaAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
		},
		}

	}
	return aff
}
