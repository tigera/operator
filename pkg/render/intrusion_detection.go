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
	"time"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render/common/configmap"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rkibana "github.com/tigera/operator/pkg/render/common/kibana"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/url"
)

const (
	IntrusionDetectionNamespace = "tigera-intrusion-detection"

	ElasticsearchIntrusionDetectionUserSecret    = "tigera-ee-intrusion-detection-elasticsearch-access"
	ElasticsearchIntrusionDetectionJobUserSecret = "tigera-ee-installer-elasticsearch-access"
	ElasticsearchADJobUserSecret                 = "tigera-ee-ad-job-elasticsearch-access"

	IntrusionDetectionInstallerJobName = "intrusion-detection-es-job-installer"

	DeepPacketInspectionNamespace = "tigera-dpi"
	DeepPacketInspectionName      = "tigera-dpi"
	DefaultMemoryLimitDPI         = "1Gi"
	DefaultMemoryRequestDPI       = "100Mi"
	DefaultCPULimitDPI            = "1"
	DefaultCPURequestDPI          = "100m"
)

func IntrusionDetection(
	ids *operatorv1.IntrusionDetection,
	lc *operatorv1.LogCollector,
	esSecrets []*corev1.Secret,
	kibanaCertSecret *corev1.Secret,
	installation *operatorv1.InstallationSpec,
	esClusterConfig *relasticsearch.ClusterConfig,
	pullSecrets []*corev1.Secret,
	openshift bool,
	clusterDomain string,
	esLicenseType ElasticsearchLicenseType,
	managedCluster bool,
	hasNoLicense bool,
	managerInternalTLSSecret *corev1.Secret,
	addDPIDaemonSet bool,
	nodeTLSSecret *corev1.Secret,
	typhaTLSSecret *corev1.Secret,
	typhaCAConfigMap *corev1.ConfigMap,
) Component {
	return &intrusionDetectionComponent{
		ids:                      ids,
		lc:                       lc,
		esSecrets:                esSecrets,
		kibanaCertSecret:         kibanaCertSecret,
		installation:             installation,
		esClusterConfig:          esClusterConfig,
		pullSecrets:              pullSecrets,
		openshift:                openshift,
		clusterDomain:            clusterDomain,
		esLicenseType:            esLicenseType,
		managedCluster:           managedCluster,
		hasNoLicense:             hasNoLicense,
		managerInternalTLSSecret: managerInternalTLSSecret,
		dpiDaemonSet:             addDPIDaemonSet,
		nodeTLSSecret:            nodeTLSSecret,
		typhaTLSSecret:           typhaTLSSecret,
		typhaCAConfigMap:         typhaCAConfigMap,
	}
}

type intrusionDetectionComponent struct {
	ids                      *operatorv1.IntrusionDetection
	lc                       *operatorv1.LogCollector
	esSecrets                []*corev1.Secret
	kibanaCertSecret         *corev1.Secret
	installation             *operatorv1.InstallationSpec
	esClusterConfig          *relasticsearch.ClusterConfig
	pullSecrets              []*corev1.Secret
	openshift                bool
	clusterDomain            string
	esLicenseType            ElasticsearchLicenseType
	jobInstallerImage        string
	controllerImage          string
	managedCluster           bool
	hasNoLicense             bool
	managerInternalTLSSecret *corev1.Secret
	dpiDaemonSet             bool
	nodeTLSSecret            *corev1.Secret
	typhaTLSSecret           *corev1.Secret
	typhaCAConfigMap         *corev1.ConfigMap
	dpiImage                 string
}

func (c *intrusionDetectionComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.installation.Registry
	path := c.installation.ImagePath
	prefix := c.installation.ImagePrefix
	errMsgs := []string{}
	var err error
	if !c.managedCluster {
		c.jobInstallerImage, err = components.GetReference(components.ComponentElasticTseeInstaller, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	c.controllerImage, err = components.GetReference(components.ComponentIntrusionDetectionController, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.dpiImage, err = components.GetReference(components.ComponentDeepPacketInspection, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *intrusionDetectionComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *intrusionDetectionComponent) Objects() ([]client.Object, []client.Object) {
	var toDelete []client.Object
	objs := []client.Object{CreateNamespace(IntrusionDetectionNamespace, c.installation.KubernetesProvider)}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(IntrusionDetectionNamespace, c.pullSecrets...)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(IntrusionDetectionNamespace, c.esSecrets...)...)...)
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(IntrusionDetectionNamespace, c.kibanaCertSecret)...)...)

	if c.managerInternalTLSSecret != nil {
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(IntrusionDetectionNamespace, c.managerInternalTLSSecret)...)...)
	}

	objs = append(objs, c.intrusionDetectionServiceAccount(),
		c.intrusionDetectionJobServiceAccount(),
		c.intrusionDetectionClusterRole(),
		c.intrusionDetectionClusterRoleBinding(),
		c.intrusionDetectionRole(),
		c.intrusionDetectionRoleBinding(),
		c.intrusionDetectionDeployment())

	if !c.managedCluster {
		objs = append(objs, c.intrusionDetectionElasticsearchJob())
	}

	objs = append(objs, c.globalAlertTemplates()...)

	if !c.openshift {
		objs = append(objs,
			c.intrusionDetectionPodSecurityPolicy(),
			c.intrusionDetectionPSPClusterRole(),
			c.intrusionDetectionPSPClusterRoleBinding())
	}

	if c.dpiDaemonSet {
		// Just update the IDS resource with the default values for DPI ComponentResources if it doesn't exist,
		// the DPI daemonset will use this values for setting container resource requirements.
		// Updated IDS resource is appended to the list of objects to be created if license is valid.
		c.defaultIntrusionDetectionComponentResources()
		objs = append(objs, CreateNamespace(DeepPacketInspectionNamespace, c.installation.KubernetesProvider))
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, c.nodeTLSSecret)...)...)
		objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(DeepPacketInspectionNamespace, c.typhaTLSSecret)...)...)
		objs = append(objs, configmap.ToRuntimeObjects(configmap.CopyToNamespace(DeepPacketInspectionNamespace, c.typhaCAConfigMap)...)...)
		objs = append(objs,
			c.dpiServiceAccount(),
			c.dpiClusterRole(),
			c.dpiClusterRoleBinding(),
			c.dpiDaemonset(),
		)
	} else {
		toDelete = append(toDelete, c.dpiNamespace())
	}

	if c.hasNoLicense {
		return nil, objs
	}

	// If IDS resource needs to be updated with default resourceRequirements,
	// append it after license check is done to avoid deleting IDS CR.
	if c.dpiDaemonSet {
		objs = append(objs, c.ids)
	}

	return objs, toDelete
}

func (c *intrusionDetectionComponent) Ready() bool {
	return true
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchJob() *batchv1.Job {
	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"job-name": IntrusionDetectionInstallerJobName},
		},
		Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
			Tolerations:      c.installation.ControlPlaneTolerations,
			NodeSelector:     c.installation.ControlPlaneNodeSelector,
			RestartPolicy:    corev1.RestartPolicyOnFailure,
			ImagePullSecrets: secret.GetReferenceList(c.pullSecrets),
			Containers: []corev1.Container{
				relasticsearch.ContainerDecorate(c.intrusionDetectionJobContainer(), c.esClusterConfig.ClusterName(),
					ElasticsearchIntrusionDetectionJobUserSecret, c.clusterDomain, rmeta.OSTypeLinux),
			},
			Volumes: []corev1.Volume{{
				Name: "kibana-ca-cert-volume",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: KibanaPublicCertSecret,
						Items: []corev1.KeyToPath{
							{Key: "tls.crt", Path: "ca.pem"},
						},
					},
				},
			}},
			ServiceAccountName: IntrusionDetectionInstallerJobName,
		}),
	}, c.esClusterConfig, c.esSecrets).(*corev1.PodTemplateSpec)

	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerJobName,
			Namespace: IntrusionDetectionNamespace,
		},
		Spec: batchv1.JobSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"job-name": IntrusionDetectionInstallerJobName,
				},
			},
			Template: *podTemplate,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionJobContainer() corev1.Container {
	kScheme, kHost, kPort, _ := url.ParseEndpoint(rkibana.HTTPSEndpoint(c.SupportedOSType(), c.clusterDomain))
	secretName := ElasticsearchIntrusionDetectionJobUserSecret
	return corev1.Container{
		Name:  "elasticsearch-job-installer",
		Image: c.jobInstallerImage,
		Env: []corev1.EnvVar{
			{
				Name:  "KIBANA_HOST",
				Value: kHost,
			},
			{
				Name:  "KIBANA_PORT",
				Value: kPort,
			},
			{
				Name:  "KIBANA_SCHEME",
				Value: kScheme,
			},
			{
				// We no longer need to start the xpack trial from the installer pod. Logstorage
				// now takes care of this in combination with the ECK operator (v1).
				Name:  "START_XPACK_TRIAL",
				Value: "false",
			},
			{
				Name:      "USER",
				ValueFrom: secret.GetEnvVarSource(secretName, "username", false),
			},
			{
				Name:      "PASSWORD",
				ValueFrom: secret.GetEnvVarSource(secretName, "password", false),
			},
			{
				Name:  "KB_CA_CERT",
				Value: KibanaDefaultCertPath,
			},
			{
				Name:  "CLUSTER_NAME",
				Value: c.esClusterConfig.ClusterName(),
			},
		},
		VolumeMounts: []corev1.VolumeMount{{
			Name:      "kibana-ca-cert-volume",
			MountPath: "/etc/ssl/kibana/",
		}},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionJobServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerJobName,
			Namespace: IntrusionDetectionNamespace,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"projectcalico.org",
			},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"globalnetworksets",
			},
			Verbs: []string{
				"get", "list", "watch", "create", "update", "patch", "delete",
			},
		},
		{
			APIGroups: []string{
				"crd.projectcalico.org",
			},
			Resources: []string{
				"licensekeys",
			},
			Verbs: []string{
				"get", "watch",
			},
		},
	}
	if !c.managedCluster {
		managementRule := []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"authenticationreviews"},
				Verbs:     []string{"create"},
			},
		}
		rules = append(rules, managementRule...)
	}
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "intrusion-detection-controller",
		},
		Rules: rules,
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "intrusion-detection-controller",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "intrusion-detection-controller",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "intrusion-detection-controller",
				Namespace: IntrusionDetectionNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"secrets",
					"configmaps",
				},
				Verbs: []string{
					"get",
				},
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "intrusion-detection-controller",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "intrusion-detection-controller",
				Namespace: IntrusionDetectionNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionDeployment() *appsv1.Deployment {
	var replicas int32 = 1

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
			Labels: map[string]string{
				"k8s-app": "intrusion-detection-controller",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "intrusion-detection-controller"},
			},
			Template: *c.deploymentPodTemplate(),
		},
	}
}

func (c *intrusionDetectionComponent) deploymentPodTemplate() *corev1.PodTemplateSpec {
	defaultMode := int32(420)
	ps := []corev1.LocalObjectReference{}
	for _, x := range c.pullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}

	// If syslog forwarding is enabled then set the necessary hostpath volume to write
	// logs for Fluentd to access.
	volumes := []corev1.Volume{}
	if c.syslogForwardingIsEnabled() {
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		volumes = []corev1.Volume{
			{
				Name: "var-log-calico",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/log/calico",
						Type: &dirOrCreate,
					},
				},
			},
		}
	}

	if c.managerInternalTLSSecret != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name: ManagerInternalTLSSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						DefaultMode: &defaultMode,
						SecretName:  ManagerInternalTLSSecretName,
						Items: []corev1.KeyToPath{
							{
								Key:  "cert",
								Path: "cert",
							},
						},
					},
				},
			})
	}

	container := relasticsearch.ContainerDecorateIndexCreator(
		relasticsearch.ContainerDecorate(c.intrusionDetectionControllerContainer(), c.esClusterConfig.ClusterName(),
			ElasticsearchIntrusionDetectionUserSecret, c.clusterDomain, rmeta.OSTypeLinux),
		c.esClusterConfig.Replicas(), c.esClusterConfig.Shards())

	if c.managedCluster {
		envVars := []corev1.EnvVar{
			{Name: "DISABLE_ALERTS", Value: "yes"},
		}
		container.Env = append(container.Env, envVars...)
	}

	return relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "intrusion-detection-controller",
			Namespace: IntrusionDetectionNamespace,
			Labels: map[string]string{
				"k8s-app": "intrusion-detection-controller",
			},
			Annotations: c.intrusionDetectionAnnotations(),
		},
		Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
			Tolerations:        c.installation.ControlPlaneTolerations,
			NodeSelector:       c.installation.ControlPlaneNodeSelector,
			ServiceAccountName: "intrusion-detection-controller",
			ImagePullSecrets:   ps,
			Containers: []corev1.Container{
				container,
			},
			Volumes: volumes,
		}),
	}, c.esClusterConfig, c.esSecrets).(*corev1.PodTemplateSpec)
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerContainer() corev1.Container {
	envs := []corev1.EnvVar{
		{
			Name:  "CLUSTER_NAME",
			Value: c.esClusterConfig.ClusterName(),
		},
	}

	privileged := false

	// If syslog forwarding is enabled then set the necessary ENV var and volume mount to
	// write logs for Fluentd.
	volumeMounts := []corev1.VolumeMount{}
	if c.syslogForwardingIsEnabled() {
		envs = append(envs,
			corev1.EnvVar{Name: "IDS_ENABLE_EVENT_FORWARDING", Value: "true"},
		)
		volumeMounts = append(volumeMounts, syslogEventsForwardingVolumeMount())
		// On OpenShift, if we need the volume mount to hostpath volume for syslog forwarding,
		// then ID controller needs privileged access to write event logs to that volume
		if c.openshift {
			privileged = true
		}
	}

	if c.managerInternalTLSSecret != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      ManagerInternalTLSSecretName,
			MountPath: "/manager-tls",
			ReadOnly:  true,
		})
	}

	return corev1.Container{
		Name:  "controller",
		Image: c.controllerImage,
		Env:   envs,
		// Needed for permissions to write to the audit log
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/healthz",
						"liveness",
					},
				},
			},
			InitialDelaySeconds: 5,
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		VolumeMounts: volumeMounts,
	}
}

// Determine whether this component's configuration has syslog forwarding enabled or not.
// Look inside LogCollector spec for whether or not Syslog log type SyslogLogIDSEvents
// exists. If it does, then we need to turn on forwarding for IDS event logs.
func (c *intrusionDetectionComponent) syslogForwardingIsEnabled() bool {
	if c.lc != nil && c.lc.Spec.AdditionalStores != nil {
		syslog := c.lc.Spec.AdditionalStores.Syslog
		if syslog != nil {
			if syslog.LogTypes != nil {
				for _, t := range syslog.LogTypes {
					switch t {
					case operatorv1.SyslogLogIDSEvents:
						return true
					}
				}
			}
		}
	}
	return false
}

func syslogEventsForwardingVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "var-log-calico",
		MountPath: "/var/log/calico",
	}
}

func (c *intrusionDetectionComponent) imagePullSecrets() []client.Object {
	secrets := []client.Object{}
	for _, s := range c.pullSecrets {
		s.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: IntrusionDetectionNamespace}

		secrets = append(secrets, s)
	}
	return secrets
}

func (c *intrusionDetectionComponent) globalAlertTemplates() []client.Object {
	return []client.Object{
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy.pod",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on any changes to pods within the cluster",
				Summary:     "[audit] [privileged access] change detected for pod ${objectRef.namespace}/${objectRef.name}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "audit",
				Query:       "(verb=create OR verb=update OR verb=delete OR verb=patch) AND 'objectRef.resource'=pods",
				AggregateBy: []string{"objectRef.name", "objectRef.namespace"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy.globalnetworkpolicy",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on any changes to network policies",
				Summary:     "[audit] [privileged access] change detected for ${objectRef.resource} ${objectRef.name}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "audit",
				Query:       "(verb=create OR verb=update OR verb=delete OR verb=patch) AND 'objectRef.resource'=globalnetworkpolicies",
				AggregateBy: []string{"objectRef.name", "objectRef.resource"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy.globalnetworkset",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on any changes to global network sets",
				Summary:     "[audit] [privileged access] change detected for ${objectRef.resource} ${objectRef.name}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "audit",
				Query:       "(verb=create OR verb=update OR verb=delete OR verb=patch) AND 'objectRef.resource'=globalnetworksets",
				AggregateBy: []string{"objectRef.resource", "objectRef.name"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "policy.serviceaccount",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on any changes to service accounts within the cluster",
				Summary:     "[audit] [privileged access] change detected for serviceaccount ${objectRef.namespace}/${objectRef.name}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "audit",
				Query:       "(verb=create OR verb=update OR verb=delete OR verb=patch) AND 'objectRef.resource'='serviceaccounts'",
				AggregateBy: []string{"objectRef.namespace", "objectRef.name"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "network.cloudapi",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on access to cloud metadata APIs",
				Summary:     "[flows] [cloud API] cloud metadata API accessed by ${source_namespace}/${source_name_aggr}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "flows",
				Query:       "(dest_name_aggr='metadata-api' OR dest_ip='169.254.169.254' OR dest_name_aggr='kse.kubernetes') AND proto='tcp' AND action='allow' AND reporter=src AND (source_namespace='default')",
				AggregateBy: []string{"source_namespace", "source_name_aggr"},
				Field:       "num_flows",
				Metric:      "sum",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "network.ssh",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts on the use of ssh to and from a specific namespace (e.g. default)",
				Summary:     "[flows] ssh flow in default namespace detected from ${source_namespace}/${source_name_aggr}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "flows",
				Query:       "proto='tcp' AND action='allow' AND dest_port='22' AND (source_namespace='default' OR dest_namespace='default') AND reporter=src",
				AggregateBy: []string{"source_namespace", "source_name_aggr"},
				Field:       "num_flows",
				Metric:      "sum",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "network.lateral.access",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts when pods with a specific label (e.g. app=monitor) accessed by other workloads within the cluster",
				Summary:     "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} with label app=monitor is accessed",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "flows",
				Query:       "'source_labels.labels'='app=monitor' AND proto=tcp AND action=allow AND reporter=dst",
				AggregateBy: []string{"source_namespace", "source_name_aggr"},
				Field:       "num_flows",
				Metric:      "sum",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "network.lateral.originate",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts when pods with a specific label (e.g. app=monitor) initiate connections to other workloads within the cluster",
				Summary:     "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} with label app=monitor initiated connection",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "flows",
				Query:       "'source_labels.labels'='app=monitor' AND proto=tcp AND action=allow AND reporter=src AND NOT dest_name_aggr='metadata-api' AND NOT dest_name_aggr='pub' AND NOT dest_name_aggr='kse.kubernetes'",
				AggregateBy: []string{"source_namespace", "source_name_aggr"},
				Field:       "num_flows",
				Metric:      "sum",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "dns.servfail",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts when SERVFAIL response code is detected",
				Summary:     "[dns] SERVFAIL response detected for ${client_namespace}/${client_name_aggr}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "dns",
				Query:       "rcode='SERVFAIL'",
				AggregateBy: []string{"client_namespace", "client_name_aggr", "qname"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   0,
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "dns.dos",
			},
			Spec: v3.GlobalAlertSpec{
				Description: "Alerts when DNS DOS attempt is detected",
				Summary:     "[dns] DOS attempt detected by ${client_namespace}/${client_name_aggr}",
				Severity:    100,
				Period:      &metav1.Duration{Duration: 10 * time.Minute},
				Lookback:    &metav1.Duration{Duration: 10 * time.Minute},
				DataSet:     "dns",
				Query:       "",
				AggregateBy: []string{"client_namespace", "client_name_aggr"},
				Metric:      "count",
				Condition:   "gt",
				Threshold:   50000,
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName("intrusion-detection")

	if c.syslogForwardingIsEnabled() {
		psp.Spec.Volumes = append(psp.Spec.Volumes, policyv1beta1.HostPath)
		psp.Spec.AllowedHostPaths = []policyv1beta1.AllowedHostPath{
			{
				PathPrefix: "/var/log/calico",
				ReadOnly:   false,
			},
		}
	}

	psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny
	return psp
}

func (c *intrusionDetectionComponent) intrusionDetectionPSPClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "intrusion-detection-psp",
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"intrusion-detection"},
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionPSPClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "intrusion-detection-psp",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "intrusion-detection-psp",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "intrusion-detection-controller",
				Namespace: IntrusionDetectionNamespace,
			},
			{
				Kind:      "ServiceAccount",
				Name:      IntrusionDetectionInstallerJobName,
				Namespace: IntrusionDetectionNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionAnnotations() map[string]string {
	if c.managerInternalTLSSecret != nil {
		return map[string]string{
			ManagerInternalTLSHashAnnotation: rmeta.AnnotationHash(c.managerInternalTLSSecret.Data),
		}
	}
	return nil
}

// defaultIntrusionDetectionComponentResources sets the default requirements value for DPI in IDS resource if it is not set.
func (c *intrusionDetectionComponent) defaultIntrusionDetectionComponentResources() {
	if c.ids.Spec.ComponentResources == nil {
		c.ids.Spec.ComponentResources = []operatorv1.IntrusionDetectionComponentResource{
			{
				ComponentName: operatorv1.ComponentNameDeepPacketInspection,
				ResourceRequirements: &corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse(DefaultMemoryLimitDPI),
						corev1.ResourceCPU:    resource.MustParse(DefaultCPULimitDPI),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse(DefaultMemoryRequestDPI),
						corev1.ResourceCPU:    resource.MustParse(DefaultCPURequestDPI),
					},
				},
			},
		}
	}
}

func (c *intrusionDetectionComponent) dpiDaemonset() *appsv1.DaemonSet {
	var terminationGracePeriod int64 = 0

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: DeepPacketInspectionNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": DeepPacketInspectionName}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": DeepPacketInspectionName,
					},
					Annotations: c.dpiAnnotations(),
				},
				Spec: corev1.PodSpec{
					Tolerations:                   rmeta.TolerateAll,
					ImagePullSecrets:              secret.GetReferenceList(c.pullSecrets),
					ServiceAccountName:            DeepPacketInspectionName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					Containers:                    []corev1.Container{c.dpiContainer()},
					Volumes:                       c.dpiVolumes(),
				},
			},
		},
	}
}

func (c *intrusionDetectionComponent) dpiContainer() corev1.Container {
	privileged := false
	// On OpenShift Snort needs privileged access to access host network
	if c.openshift {
		privileged = true
	}

	return corev1.Container{
		Name:         DeepPacketInspectionName,
		Image:        c.dpiImage,
		Resources:    *c.ids.Spec.ComponentResources[0].ResourceRequirements,
		Env:          c.dpiEnvVars(),
		VolumeMounts: c.dpiVolumeMounts(),
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		ReadinessProbe: c.dpiReadinessProbes(),
	}
}

func (c *intrusionDetectionComponent) dpiVolumes() []corev1.Volume {
	var defaultMode int32 = 420

	return []corev1.Volume{
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
			Name: "node-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  NodeTLSSecretName,
					DefaultMode: &defaultMode,
				},
			},
		},
	}
}

func (c *intrusionDetectionComponent) dpiEnvVars() []corev1.EnvVar {
	var cnEnv corev1.EnvVar
	if c.installation.CertificateManagement != nil {
		cnEnv = corev1.EnvVar{
			Name: "DPI_TYPHACN", Value: TyphaCommonName,
		}
	} else {
		cnEnv = corev1.EnvVar{
			Name: "DPI_TYPHACN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: TyphaTLSSecretName,
					},
					Key:      CommonName,
					Optional: ptr.BoolToPtr(true),
				},
			},
		}
	}

	return []corev1.EnvVar{
		{
			Name: "NODENAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{Name: "DPI_TYPHAK8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "DPI_TYPHAK8SSERVICENAME", Value: TyphaServiceName},
		{Name: "DPI_TYPHACAFILE", Value: "/typha-ca/caBundle"},
		{Name: "DPI_TYPHACERTFILE", Value: fmt.Sprintf("/node-certs/%s", TLSSecretCertName)},
		{Name: "DPI_TYPHAKEYFILE", Value: fmt.Sprintf("/node-certs/%s", TLSSecretKeyName)},
		// We need at least the CN or URISAN set, we depend on the validation
		// done by the core_controller that the Secret will have one.
		cnEnv,
		{Name: "DPI_TYPHAURISAN", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: TyphaTLSSecretName,
				},
				Key:      URISAN,
				Optional: ptr.BoolToPtr(true),
			},
		}},
	}
}

func (c *intrusionDetectionComponent) dpiVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
		{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
	}
}

func (c *intrusionDetectionComponent) dpiReadinessProbes() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Host:   "localhost",
				Path:   "/readiness",
				Port:   intstr.FromInt(9097),
				Scheme: corev1.URISchemeHTTP,
			},
		},
		TimeoutSeconds:      10,
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

func (c *intrusionDetectionComponent) dpiServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeepPacketInspectionName,
			Namespace: DeepPacketInspectionNamespace,
		},
	}
}

func (c *intrusionDetectionComponent) dpiClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   DeepPacketInspectionName,
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     DeepPacketInspectionName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      DeepPacketInspectionName,
				Namespace: DeepPacketInspectionNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) dpiClusterRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DeepPacketInspectionName,
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"deeppacketinspections",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Used to update the DPI resource status
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"deeppacketinspections/status",
				},
				Verbs: []string{"update"},
			},
			{
				// Used to discover Typha endpoints and service IPs for advertisement.
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
		},
	}
	if c.installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{DeepPacketInspectionName},
		})
	}
	return role
}

func (c *intrusionDetectionComponent) dpiNamespace() *corev1.Namespace {
	return &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DeepPacketInspectionNamespace,
		},
	}
}

func (c *intrusionDetectionComponent) dpiAnnotations() map[string]string {
	return map[string]string{
		typhaCAHashAnnotation:   rmeta.AnnotationHash(c.typhaCAConfigMap.Data),
		nodeCertHashAnnotation:  rmeta.AnnotationHash(c.nodeTLSSecret.Data),
		typhaCertHashAnnotation: rmeta.AnnotationHash(c.typhaTLSSecret.Data),
	}
}
