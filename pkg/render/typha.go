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

	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	"github.com/tigera/operator/pkg/controller/migration"
	"github.com/tigera/operator/pkg/dns"
)

const (
	TyphaServiceName              = "calico-typha"
	TyphaPortName                 = "calico-typha"
	TyphaK8sAppName               = "calico-typha"
	TyphaServiceAccountName       = "calico-typha"
	AppLabelName                  = "k8s-app"
	TyphaPort               int32 = 5473
	typhaCAHashAnnotation         = "hash.operator.tigera.io/typha-ca"
	typhaCertHashAnnotation       = "hash.operator.tigera.io/typha-cert"
)

// Typha creates the typha daemonset and other resources for the daemonset to operate normally.
func Typha(
	k8sServiceEp k8sapi.ServiceEndpoint,
	installation *operator.InstallationSpec,
	tnTLS *TyphaNodeTLS,
	aci *operator.AmazonCloudIntegration,
	migrationNeeded bool,
	clusterDomain string,
) Component {
	return &typhaComponent{
		k8sServiceEp:       k8sServiceEp,
		installation:       installation,
		typhaNodeTLS:       tnTLS,
		amazonCloudInt:     aci,
		namespaceMigration: migrationNeeded,
		clusterDomain:      clusterDomain,
	}
}

type typhaComponent struct {
	k8sServiceEp       k8sapi.ServiceEndpoint
	installation       *operator.InstallationSpec
	typhaNodeTLS       *TyphaNodeTLS
	amazonCloudInt     *operator.AmazonCloudIntegration
	namespaceMigration bool
	clusterDomain      string
	typhaImage         string
	certSignReqImage   string
}

func (c *typhaComponent) ResolveImages(is *operator.ImageSet) error {
	reg := c.installation.Registry
	path := c.installation.ImagePath
	var err error
	if c.installation.Variant == operator.TigeraSecureEnterprise {
		c.typhaImage, err = components.GetReference(components.ComponentTigeraTypha, reg, path, is)
	} else {
		c.typhaImage, err = components.GetReference(components.ComponentCalicoTypha, reg, path, is)
	}
	errMsgs := []string{}
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if c.installation.CertificateManagement != nil {
		c.certSignReqImage, err = ResolveCSRInitImage(c.installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *typhaComponent) SupportedOSType() OSType {
	return OSTypeLinux
}

func (c *typhaComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.typhaServiceAccount(),
		c.typhaRole(),
		c.typhaRoleBinding(),
		c.typhaDeployment(),
		c.typhaService(),
		c.typhaPodDisruptionBudget(),
	}

	if c.installation.KubernetesProvider != operator.ProviderOpenShift {
		objs = append(objs, c.typhaPodSecurityPolicy())
	}

	if c.installation.CertificateManagement != nil {
		objs = append(objs, csrClusterRoleBinding("calico-typha", common.CalicoNamespace))
	}

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
func (c *typhaComponent) typhaServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
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

// typhaRole creates the clusterrole containing policy rules that allow the typha daemonset to operate normally.
func (c *typhaComponent) typhaRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-typha",
			Labels: map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
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
					"clusterinformations",
					"felixconfigurations",
					"globalnetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
					"ipamblocks",
					"ippools",
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
	if c.installation.Variant == operator.TigeraSecureEnterprise {
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
	if c.installation.KubernetesProvider != operator.ProviderOpenShift {
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
func (c *typhaComponent) typhaDeployment() *apps.Deployment {
	var terminationGracePeriod int64 = 0
	var revisionHistoryLimit int32 = 2
	maxUnavailable := intstr.FromInt(1)
	maxSurge := intstr.FromString("25%")

	var initContainers []v1.Container
	annotations := make(map[string]string)
	annotations[typhaCAHashAnnotation] = AnnotationHash(c.typhaNodeTLS.CAConfigMap.Data)
	if c.installation.CertificateManagement == nil {
		annotations[typhaCertHashAnnotation] = AnnotationHash(c.typhaNodeTLS.TyphaSecret.Data)
	} else {
		annotations[typhaCertHashAnnotation] = AnnotationHash(c.installation.CertificateManagement.CACert)
		initContainers = append(initContainers, CreateCSRInitContainer(
			c.installation,
			c.certSignReqImage,
			"typha-certs",
			TyphaCommonName,
			TLSSecretKeyName,
			TLSSecretCertName,
			dns.GetServiceDNSNames(TyphaServiceName, common.CalicoNamespace, c.clusterDomain),
			CSRLabelCalicoSystem))
	}

	// Include annotation for prometheus scraping configuration.
	if c.installation.TyphaMetricsPort != nil {
		annotations["prometheus.io/scrape"] = "true"
		annotations["prometheus.io/port"] = fmt.Sprintf("%d", *c.installation.TyphaMetricsPort)
	}

	d := apps.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.TyphaDeploymentName,
			Namespace: common.CalicoNamespace,
			Labels: map[string]string{
				AppLabelName: TyphaK8sAppName,
			},
		},
		Spec: apps.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{AppLabelName: TyphaK8sAppName},
			},
			Strategy: apps.DeploymentStrategy{
				Type: apps.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &apps.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavailable,
					MaxSurge:       &maxSurge,
				},
			},
			RevisionHistoryLimit: &revisionHistoryLimit,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						AppLabelName: TyphaK8sAppName,
					},
					Annotations: annotations,
				},
				Spec: v1.PodSpec{
					Tolerations:                   tolerateAll,
					Affinity:                      c.affinity(),
					ImagePullSecrets:              c.installation.ImagePullSecrets,
					ServiceAccountName:            TyphaServiceAccountName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                initContainers,
					Containers:                    []v1.Container{c.typhaContainer()},
					Volumes:                       c.volumes(),
				},
			},
		},
	}
	setCriticalPod(&(d.Spec.Template))
	if c.namespaceMigration {
		migration.SetTyphaAntiAffinity(&d)
	}
	return &d
}

// volumes creates the typha's volumes.
func (c *typhaComponent) volumes() []v1.Volume {
	volumes := []v1.Volume{
		{
			Name: "typha-ca",
			VolumeSource: v1.VolumeSource{
				ConfigMap: &v1.ConfigMapVolumeSource{
					LocalObjectReference: v1.LocalObjectReference{
						Name: TyphaCAConfigMapName,
					},
				},
			},
		},
		{
			Name:         "typha-certs",
			VolumeSource: certificateVolumeSource(c.installation.CertificateManagement, TyphaTLSSecretName),
		},
	}

	return volumes
}

// typhaVolumeMounts creates the typha's volume mounts.
func (c *typhaComponent) typhaVolumeMounts() []v1.VolumeMount {
	volumeMounts := []v1.VolumeMount{
		{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
		{MountPath: "/typha-certs", Name: "typha-certs", ReadOnly: true},
	}

	return volumeMounts
}

func (c *typhaComponent) typhaPorts() []v1.ContainerPort {
	return []v1.ContainerPort{
		{
			ContainerPort: TyphaPort,
			Name:          TyphaPortName,
			Protocol:      corev1.ProtocolTCP,
		},
	}
}

// typhaContainer creates the main typha container.
func (c *typhaComponent) typhaContainer() v1.Container {
	lp, rp := c.livenessReadinessProbes()

	return v1.Container{
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
func (c *typhaComponent) typhaResources() v1.ResourceRequirements {
	return GetResourceRequirements(c.installation, operator.ComponentNameTypha)
}

// typhaEnvVars creates the typha's envvars.
func (c *typhaComponent) typhaEnvVars() []v1.EnvVar {
	var cnEnv v1.EnvVar
	if c.installation.CertificateManagement != nil {
		cnEnv = v1.EnvVar{
			Name: "TYPHA_CLIENTCN", Value: FelixCommonName,
		}
	} else {
		cnEnv = v1.EnvVar{
			Name: "TYPHA_CLIENTCN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: NodeTLSSecretName,
					},
					Key:      CommonName,
					Optional: Bool(true),
				},
			},
		}
	}

	typhaEnv := []v1.EnvVar{
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
		{Name: "TYPHA_CLIENTURISAN", ValueFrom: &v1.EnvVarSource{
			SecretKeyRef: &v1.SecretKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: NodeTLSSecretName,
				},
				Key:      URISAN,
				Optional: Bool(true),
			},
		}},
	}

	switch c.installation.CNI.Type {
	case operator.PluginAmazonVPC:
		typhaEnv = append(typhaEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
	case operator.PluginGKE:
		typhaEnv = append(typhaEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "gke"})
	case operator.PluginAzureVNET:
		typhaEnv = append(typhaEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "azv"})
	}

	if c.installation.Variant == operator.TigeraSecureEnterprise {
		if c.installation.CalicoNetwork != nil && c.installation.CalicoNetwork.MultiInterfaceMode != nil {
			typhaEnv = append(typhaEnv, v1.EnvVar{
				Name:  "MULTI_INTERFACE_MODE",
				Value: c.installation.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	typhaEnv = append(typhaEnv, GetTigeraSecurityGroupEnvVariables(c.amazonCloudInt)...)
	typhaEnv = append(typhaEnv, c.k8sServiceEp.EnvVars()...)

	if c.installation.TyphaMetricsPort != nil {
		// If a typha metrics port was given, then enable typha prometheus metrics and set the port.
		typhaEnv = append(typhaEnv,
			v1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSENABLED", Value: "true"},
			v1.EnvVar{Name: "TYPHA_PROMETHEUSMETRICSPORT", Value: fmt.Sprintf("%d", *c.installation.TyphaMetricsPort)},
		)
	}

	return typhaEnv
}

// livenessReadinessProbes creates the typha's liveness and readiness probes.
func (c *typhaComponent) livenessReadinessProbes() (*v1.Probe, *v1.Probe) {
	// Determine liveness and readiness configuration for typha.
	port := intstr.FromInt(9098)
	lp := &v1.Probe{
		Handler: v1.Handler{
			HTTPGet: &v1.HTTPGetAction{
				Host: "localhost",
				Path: "/liveness",
				Port: port,
			},
		},
	}
	rp := &v1.Probe{
		Handler: v1.Handler{
			HTTPGet: &v1.HTTPGetAction{
				Host: "localhost",
				Path: "/readiness",
				Port: port,
			},
		},
	}
	return lp, rp
}

func (c *typhaComponent) typhaService() *v1.Service {
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
	psp := basePodSecurityPolicy()
	psp.GetObjectMeta().SetName(common.TyphaDeploymentName)
	psp.Spec.HostNetwork = true
	return psp
}

// affinity sets the affinity on typha, accounting for the kubernetes-provider and user-specified values.
func (c *typhaComponent) affinity() (aff *v1.Affinity) {
	// in AKS, there is a feature called 'virtual-nodes' which represent azure's container service as a node in the kubernetes cluster.
	// virtual-nodes have many limitations, namely it's unable to run hostNetworked pods. virtual-kubelets are tainted to prevent pods from running on them,
	// but typha tolerates all taints and will run there.
	// as such, we add a required anti-affinity for virtual-nodes if running on azure
	if c.installation.KubernetesProvider == operator.ProviderAKS {
		aff = &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{{
						MatchExpressions: []v1.NodeSelectorRequirement{
							{
								Key:      "type",
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{"virtual-node"},
							},
							{
								Key:      "kubernetes.azure.com/cluster",
								Operator: v1.NodeSelectorOpExists,
							},
						},
					}},
				},
			},
		}
	}

	// add the user-specified typha preferred affinity if specified.
	if c.installation.TyphaAffinity != nil && c.installation.TyphaAffinity.NodeAffinity != nil {
		// check if above code initialized affintiy or not.
		// this ensures we still return nil if neither condition is hit.
		if aff == nil {
			aff = &v1.Affinity{NodeAffinity: &v1.NodeAffinity{}}
		}
		aff.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution = c.installation.TyphaAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution
	}

	return aff
}
