// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package ccs

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/pkg/render"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

const (
	ControllerResourceName             = "tigera-ccs-controller"
	HostScannerConfigName              = "tigera-ccs-host-scanner-config"
	ScannerControlsConfigConfigMapName = "tigera-ccs-default-config-inputs"
	ScannerControlsConfigConfigMapKey  = "default-config-inputs.json"
	HostScannerConfigKey               = "host-scanner.yaml"
	HostScannerConfigMountPath         = "/etc/ccs"
	ScannerControlsConfigMountPath     = "/etc/ccs"
	HostScannerYamlPath                = HostScannerConfigMountPath + "/" + HostScannerConfigKey
)

func (c *component) controllerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ControllerResourceName, Namespace: c.cfg.Namespace},
	}
}

func (c *component) controllerRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ControllerResourceName, Namespace: c.cfg.Namespace},
		Rules:      []rbacv1.PolicyRule{},
	}
}

func (c *component) controllerRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ControllerResourceName, Namespace: c.cfg.Namespace},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     ControllerResourceName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ControllerResourceName,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *component) controllerClusterRole() *rbacv1.ClusterRole {
	// Set of permissions for kubescape host sensor.
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{
				"pods", "pods/proxy", "namespaces", "secrets", "nodes", "configmaps",
				"services", "serviceaccounts", "endpoints", "persistentvolumes",
				"persistentvolumeclaims", "limitranges", "replicationcontrollers",
				"podtemplates", "resourcequotas", "events",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		// TODO : namespace can be removed once we update the yaml
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"update", "create", "delete"},
		},
		{
			APIGroups: []string{"admissionregistration.k8s.io"},
			Resources: []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"apiregistration.k8s.io"},
			Resources: []string{"apiservices"},
			Verbs:     []string{"get", "watch", "list"},
		},
		// TODO : create may be removed have to check
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments", "statefulsets", "daemonsets", "replicasets", "controllerrevisions"},
			Verbs:     []string{"get", "watch", "list", "create", "update", "delete"},
		},
		{
			APIGroups: []string{"autoscaling"},
			Resources: []string{"horizontalpodautoscalers"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"batch"},
			Resources: []string{"jobs", "cronjobs"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"coordination.k8s.io"},
			Resources: []string{"leases"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"events.k8s.io"},
			Resources: []string{"events"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"hostdata.kubescape.cloud"},
			Resources: []string{"APIServerInfo", "ControlPlaneInfo"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"networkpolicies", "ingresses"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"policy"},
			Resources: []string{"poddisruptionbudgets", "podsecuritypolicies", "PodSecurityPolicy"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "clusterrolebindings", "roles", "rolebindings"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"storage.k8s.io"},
			Resources: []string{"csistoragecapacities", "storageclasses"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"extensions"},
			Resources: []string{"ingresses"},
			Verbs:     []string{"get", "watch", "list"},
		},
		{
			APIGroups: []string{"spdx.softwarecomposition.kubescape.io"},
			Resources: []string{"workloadconfigurationscans", "workloadconfigurationscansummaries"},
			Verbs:     []string{"create", "update", "patch"},
		},
	}

	// Add the rules for the CCS controller.
	rules = append(rules, []rbacv1.PolicyRule{
		{
			APIGroups: []string{"alphaccs.projectcalico.org"},
			Resources: []string{"frameworks"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"ccs.tigera.io"},
			Resources: []string{"runs"},
			Verbs:     []string{"get", "create", "update"},
		},
		{
			APIGroups: []string{"ccs.tigera.io"},
			Resources: []string{"results"},
			Verbs:     []string{"create"},
		},
	}...)

	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ControllerResourceName},
		Rules:      rules,
	}

}

func (c *component) controllerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: ControllerResourceName},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ControllerResourceName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ControllerResourceName,
				Namespace: c.cfg.Namespace,
			},
		},
	}
}

func (c *component) controllerDeployment() *appsv1.Deployment {
	var certPath string
	if c.cfg.APIKeyPair != nil {
		certPath = c.cfg.APIKeyPair.VolumeMountCertificateFilePath()
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "debug"},
		{Name: "CCS_API_CA", Value: certPath},
		{Name: "CCS_API_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		{Name: "CCS_HOST_SCANNER_YAML_PATH", Value: HostScannerYamlPath},
	}

	if c.cfg.Tenant != nil && c.cfg.Tenant.MultiTenant() {
		envVars = append(envVars, corev1.EnvVar{Name: "CCS_API_URL", Value: fmt.Sprintf("https://tigera-ccs-api.%s.svc", c.cfg.Tenant.Namespace)})
	} else {
		envVars = append(envVars, corev1.EnvVar{Name: "CCS_API_URL", Value: "https://tigera-ccs-api.tigera-compliance.svc"})
	}

	annots := c.cfg.TrustedBundle.HashAnnotations()
	// Add the hash of the host scanner controls config map to the annotations so that the controller will be restarted if the config changes.
	annots[ScannerControlsConfigConfigMapKey] = rmeta.AnnotationHash(c.hostScannerInputsConfigMap)
	if c.cfg.APIKeyPair != nil {
		annots[c.cfg.APIKeyPair.HashAnnotationKey()] = c.cfg.APIKeyPair.HashAnnotationValue()
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ControllerResourceName,
			Namespace:   c.cfg.Namespace,
			Labels:      map[string]string{"k8s-app": APIResourceName},
			Annotations: annots,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ControllerResourceName,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			Containers: []corev1.Container{
				{
					Name:            ControllerResourceName,
					Image:           "gcr.io/unique-caldron-775/suresh/ccs-controller:operator-v9", // TODO c.controllerImage,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					SecurityContext: securitycontext.NewNonRootContext(),
					VolumeMounts:    c.controllerVolumeMounts(),
				},
			},
			Volumes: c.controllerVolumes(),
		},
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ControllerResourceName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{"k8s-app": ControllerResourceName},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": ControllerResourceName},
			},
			Template: *podTemplate,
		},
	}

	if c.cfg.ComplianceConfigurationSecurity != nil {
		if overrides := c.cfg.ComplianceConfigurationSecurity.Spec.CCSControllerDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *component) controllerVolumeMounts() []corev1.VolumeMount {
	vms := []corev1.VolumeMount{
		c.cfg.APIKeyPair.VolumeMount(c.SupportedOSType()),
	}
	vms = append(vms, c.cfg.TrustedBundle.VolumeMounts(c.SupportedOSType())...)

	vms = append(vms, corev1.VolumeMount{
		Name:      HostScannerConfigName,
		ReadOnly:  true,
		MountPath: HostScannerConfigMountPath,
	})
	vms = append(vms, corev1.VolumeMount{
		Name:      ScannerControlsConfigConfigMapName,
		ReadOnly:  true,
		MountPath: ScannerControlsConfigMountPath,
	})

	return vms
}

func (c *component) controllerVolumes() []corev1.Volume {
	volumes := []corev1.Volume{c.cfg.APIKeyPair.Volume(), c.cfg.TrustedBundle.Volume()}
	volumes = append(volumes, corev1.Volume{
		Name: HostScannerConfigName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: HostScannerConfigName},
			},
		},
	})
	volumes = append(volumes, corev1.Volume{
		Name: ScannerControlsConfigConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: ScannerControlsConfigConfigMapName},
			},
		},
	})
	return volumes
}

func (c *component) controllerAllowTigeraNetworkPolicy() *calicov3.NetworkPolicy {
	_ = networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace)
	return &calicov3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ControllerAccessPolicyName,
			Namespace: c.cfg.Namespace,
		},
		Spec: calicov3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(ControllerResourceName),
			Types:    []calicov3.PolicyType{calicov3.PolicyTypeIngress, calicov3.PolicyTypeEgress},
			Ingress: []calicov3.Rule{
				{
					Action: calicov3.Allow,
				},
			},
			Egress: []calicov3.Rule{
				{
					Action: calicov3.Allow,
				},
			},
		},
	}
}

//go:embed host-scanner.yaml.template
var hostScannerConfigTemplate string

func (c *component) hostScannerYamlConfigMap() *corev1.ConfigMap {
	var config bytes.Buffer

	tpl, err := template.New("hostScannerConfigTemplate").Parse(hostScannerConfigTemplate)
	if err != nil {
		return nil
	}

	err = tpl.Execute(&config, c.cfg)
	if err != nil {
		return nil
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      HostScannerConfigName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			HostScannerConfigKey: config.String(),
		},
	}
}

//go:embed default-config-inputs.json
var defaultConfigInputs string

func (c *component) hostScannerDefaultConfigInputsConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ScannerControlsConfigConfigMapName,
			Namespace: c.cfg.Namespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			ScannerControlsConfigConfigMapKey: defaultConfigInputs,
		},
	}
}
