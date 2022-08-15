// Copyright (c) 2019,2022 Tigera, Inc. All rights reserved.

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
	"strconv"
	"strings"
	"time"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rkibana "github.com/tigera/operator/pkg/render/common/kibana"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

const (
	IntrusionDetectionNamespace = "tigera-intrusion-detection"
	IntrusionDetectionName      = "intrusion-detection-controller"

	ElasticsearchIntrusionDetectionUserSecret    = "tigera-ee-intrusion-detection-elasticsearch-access"
	ElasticsearchIntrusionDetectionJobUserSecret = "tigera-ee-installer-elasticsearch-access"
	ElasticsearchADJobUserSecret                 = "tigera-ee-ad-job-elasticsearch-access"
	ElasticsearchPerformanceHotspotsUserSecret   = "tigera-ee-performance-hotspots-elasticsearch-access"

	IntrusionDetectionInstallerJobName     = "intrusion-detection-es-job-installer"
	IntrusionDetectionControllerName       = "intrusion-detection-controller"
	IntrusionDetectionControllerPolicyName = networkpolicy.TigeraComponentPolicyPrefix + IntrusionDetectionControllerName
	IntrusionDetectionInstallerPolicyName  = networkpolicy.TigeraComponentPolicyPrefix + "intrusion-detection-elastic"

	ADJobPodTemplateBaseName      = "tigera.io.detectors"
	adDetectorPrefixName          = "tigera.io.detector."
	adDetectorName                = "anomaly-detectors"
	ADDetectorPolicyName          = networkpolicy.TigeraComponentPolicyPrefix + adDetectorName
	adDetectionJobsDefaultPeriod  = 15 * time.Minute
	ADResourceGroup               = "detectors.tigera.io"
	ADDetectorsModelResourceName  = "models"
	ADLogTypeMetaDataResourceName = "metadata"

	ADAPIObjectName          = "anomaly-detection-api"
	ADAPIObjectPortName      = "anomaly-detection-api-https"
	ADAPITLSSecretName       = "anomaly-detection-api-tls"
	ADAPIExpectedServiceName = "anomaly-detection-api.tigera-intrusion-detection.svc"
	ADAPIPolicyName          = networkpolicy.TigeraComponentPolicyPrefix + ADAPIObjectName
	adAPIPort                = 8080
)

var adAPIReplicas int32 = 1

var intrusionDetectionNamespaceSelector = fmt.Sprintf("projectcalico.org/name == '%s'", IntrusionDetectionNamespace)
var IntrusionDetectionSourceEntityRule = v3.EntityRule{
	NamespaceSelector: intrusionDetectionNamespaceSelector,
	Selector:          fmt.Sprintf("k8s-app == '%s'", IntrusionDetectionControllerName),
}
var IntrusionDetectionInstallerSourceEntityRule = v3.EntityRule{
	NamespaceSelector: intrusionDetectionNamespaceSelector,
	Selector:          fmt.Sprintf("job-name == '%s'", IntrusionDetectionInstallerJobName),
}

func IntrusionDetection(cfg *IntrusionDetectionConfiguration) Component {
	return &intrusionDetectionComponent{
		cfg: cfg,
	}
}

// IntrusionDetectionConfiguration contains all the config information needed to render the component.
type IntrusionDetectionConfiguration struct {
	LogCollector          *operatorv1.LogCollector
	ESSecrets             []*corev1.Secret
	Installation          *operatorv1.InstallationSpec
	ESClusterConfig       *relasticsearch.ClusterConfig
	PullSecrets           []*corev1.Secret
	Openshift             bool
	ClusterDomain         string
	ESLicenseType         ElasticsearchLicenseType
	ManagedCluster        bool
	HasNoLicense          bool
	TrustedCertBundle     certificatemanagement.TrustedBundle
	ADAPIServerCertSecret certificatemanagement.KeyPairInterface

	// Whether or not the cluster supports pod security policies.
	UsePSP bool
}

type intrusionDetectionComponent struct {
	cfg               *IntrusionDetectionConfiguration
	jobInstallerImage string
	controllerImage   string
	adDetectorsImage  string
	adAPIImage        string
}

func (c *intrusionDetectionComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var errMsgs []string
	var err error
	if !c.cfg.ManagedCluster {
		c.jobInstallerImage, err = components.GetReference(components.ComponentElasticTseeInstaller, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}

		c.adDetectorsImage, err = components.GetReference(components.ComponentAnomalyDetectionJobs, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}

		c.adAPIImage, err = components.GetReference(components.ComponentAnomalyDetectionAPI, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	c.controllerImage, err = components.GetReference(components.ComponentIntrusionDetectionController, reg, path, prefix, is)
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
	// Configure pod security standard. If syslog forwarding is enabled, we
	// need hostpath volumes which require a privileged PSS.
	pss := PSSBaseline
	if c.syslogForwardingIsEnabled() {
		pss = PSSPrivileged
	}
	objs := []client.Object{
		// In order to switch to a restricted policy, we need to set the following on all containers in the namespace:
		// - securityContext.allowPrivilegeEscalation=false)
		// - securityContext.capabilities.drop=["ALL"]
		// - securityContext.runAsNonRoot=true)
		// - securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost"
		CreateNamespace(IntrusionDetectionNamespace, c.cfg.Installation.KubernetesProvider, PodSecurityStandard(pss)),
		c.intrusionDetectionControllerAllowTigeraPolicy(),
		networkpolicy.AllowTigeraDefaultDeny(IntrusionDetectionNamespace),
	}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(IntrusionDetectionNamespace, c.cfg.PullSecrets...)...)...)

	objs = append(objs,
		c.intrusionDetectionServiceAccount(),
		c.intrusionDetectionJobServiceAccount(),
		c.intrusionDetectionClusterRole(),
		c.intrusionDetectionClusterRoleBinding(),
		c.intrusionDetectionRole(),
		c.intrusionDetectionRoleBinding(),
		c.intrusionDetectionDeployment(),
	)

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(IntrusionDetectionNamespace, c.cfg.ESSecrets...)...)...)
	objs = append(objs, c.globalAlertTemplates()...)

	// AD Related deployment only for management/standalone cluster
	// When FIPS mode is enabled, we currently disable our python based images.
	if !c.cfg.ManagedCluster && !operatorv1.IsFIPSModeEnabled(c.cfg.Installation.FIPSMode) {
		// Service + Deployment + RBAC for AD API
		objs = append(objs,
			c.adAPIAllowTigeraPolicy(),
			c.adAPIServiceAccount(),
			c.adAPIAccessClusterRole(),
			c.adAPIAccessRoleBinding(),
		)
		objs = append(objs,
			c.adAPIService(),
			c.adAPIDeployment(),
		)

		// RBAC for AD Detector Pods
		objs = append(objs,
			c.adDetectorAllowTigeraPolicy(),
			c.adDetectorServiceAccount(),
			c.adDetectorSecret(),
			c.adDetectorAccessRole(),
			c.adDetectorRoleBinding(),
		)
		objs = append(objs, c.adDetectorPodTemplates()...)
	}

	// When FIPS mode is enabled, we currently disable our python based images.
	if !c.cfg.ManagedCluster && !operatorv1.IsFIPSModeEnabled(c.cfg.Installation.FIPSMode) {
		objs = append(objs, c.intrusionDetectionElasticsearchAllowTigeraPolicy())
		objs = append(objs, c.intrusionDetectionElasticsearchJob())
	}

	if !c.cfg.Openshift {
		objs = append(objs,
			c.intrusionDetectionPSPClusterRole(),
			c.intrusionDetectionPSPClusterRoleBinding())
		if c.cfg.UsePSP {
			objs = append(objs, c.intrusionDetectionPodSecurityPolicy())
		}
	}

	if c.cfg.HasNoLicense {
		return nil, objs
	}

	return objs, nil
}

func (c *intrusionDetectionComponent) Ready() bool {
	return true
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchJob() *batchv1.Job {
	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"job-name": IntrusionDetectionInstallerJobName},
		},
		Spec: corev1.PodSpec{
			Tolerations:      c.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:     c.cfg.Installation.ControlPlaneNodeSelector,
			RestartPolicy:    corev1.RestartPolicyOnFailure,
			ImagePullSecrets: secret.GetReferenceList(c.cfg.PullSecrets),
			Containers: []corev1.Container{
				relasticsearch.ContainerDecorate(c.intrusionDetectionJobContainer(), c.cfg.ESClusterConfig.ClusterName(),
					ElasticsearchIntrusionDetectionJobUserSecret, c.cfg.ClusterDomain, rmeta.OSTypeLinux),
			},
			Volumes:            []corev1.Volume{c.cfg.TrustedCertBundle.Volume()},
			ServiceAccountName: IntrusionDetectionInstallerJobName,
		},
	}, c.cfg.ESClusterConfig, c.cfg.ESSecrets).(*corev1.PodTemplateSpec)

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
	kScheme, kHost, kPort, _ := url.ParseEndpoint(rkibana.HTTPSEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain))
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
				Value: c.cfg.TrustedCertBundle.MountPath(),
			},
			{
				Name:  "CLUSTER_NAME",
				Value: c.cfg.ESClusterConfig.ClusterName(),
			},
		},
		VolumeMounts: []corev1.VolumeMount{c.cfg.TrustedCertBundle.VolumeMount(c.SupportedOSType())},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
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
		{
			APIGroups: []string{""},
			Resources: []string{"podtemplates"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get"},
		},
	}

	if !c.cfg.ManagedCluster {
		managementRule := []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs", "jobs"},
				Verbs: []string{
					"get", "list", "watch", "create", "update", "patch", "delete",
				},
			},
		}

		// Used when IDS Controller creates Cronjobs for AD as the IDS deployment
		// is the owner of the AD Cronjobs - Openshift blocks setting an
		// blockOwnerDeletion to true if an ownerReference refers to a resource
		// you can't set finalizers on
		if c.cfg.Openshift {
			managementRule = append(managementRule,
				rbacv1.PolicyRule{
					APIGroups: []string{"apps"},
					Resources: []string{"deployments/finalizers"},
					Verbs:     []string{"update"},
				})
		}

		rules = append(rules, managementRule...)
	}
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: IntrusionDetectionName,
		},
		Rules: rules,
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: IntrusionDetectionName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     IntrusionDetectionName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      IntrusionDetectionName,
				Namespace: IntrusionDetectionNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
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
			Name:      IntrusionDetectionName,
			Namespace: IntrusionDetectionNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     IntrusionDetectionName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      IntrusionDetectionName,
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
			Name:      IntrusionDetectionName,
			Namespace: IntrusionDetectionNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: *c.deploymentPodTemplate(),
		},
	}
}

func (c *intrusionDetectionComponent) deploymentPodTemplate() *corev1.PodTemplateSpec {
	var ps []corev1.LocalObjectReference
	for _, x := range c.cfg.PullSecrets {
		ps = append(ps, corev1.LocalObjectReference{Name: x.Name})
	}

	// If syslog forwarding is enabled then set the necessary hostpath volume to write
	// logs for Fluentd to access.
	volumes := []corev1.Volume{
		c.cfg.TrustedCertBundle.Volume(),
	}
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

	container := relasticsearch.ContainerDecorateIndexCreator(
		relasticsearch.ContainerDecorate(c.intrusionDetectionControllerContainer(), c.cfg.ESClusterConfig.ClusterName(),
			ElasticsearchIntrusionDetectionUserSecret, c.cfg.ClusterDomain, rmeta.OSTypeLinux),
		c.cfg.ESClusterConfig.Replicas(), c.cfg.ESClusterConfig.Shards())

	if c.cfg.ManagedCluster {
		envVars := []corev1.EnvVar{
			{Name: "DISABLE_ALERTS", Value: "yes"},
			{Name: "DISABLE_ANOMALY_DETECTION", Value: "yes"},
		}
		container.Env = append(container.Env, envVars...)
	}

	return relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        IntrusionDetectionName,
			Namespace:   IntrusionDetectionNamespace,
			Annotations: c.intrusionDetectionAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:        c.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: IntrusionDetectionName,
			ImagePullSecrets:   ps,
			Containers: []corev1.Container{
				container,
			},
			Volumes: volumes,
		},
	}, c.cfg.ESClusterConfig, c.cfg.ESSecrets).(*corev1.PodTemplateSpec)
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerContainer() corev1.Container {
	envs := []corev1.EnvVar{
		{
			Name:  "CLUSTER_NAME",
			Value: c.cfg.ESClusterConfig.ClusterName(),
		},
		{
			Name:  "MULTI_CLUSTER_FORWARDING_CA",
			Value: c.cfg.TrustedCertBundle.MountPath(),
		},
		{
			Name:  "FIPS_MODE_ENABLED",
			Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode),
		},
	}

	sc := securitycontext.NewBaseContext(securitycontext.RunAsUserID, securitycontext.RunAsGroupID)

	// If syslog forwarding is enabled then set the necessary ENV var and volume mount to
	// write logs for Fluentd.
	volumeMounts := []corev1.VolumeMount{
		c.cfg.TrustedCertBundle.VolumeMount(c.SupportedOSType()),
	}
	if c.syslogForwardingIsEnabled() {
		envs = append(envs,
			corev1.EnvVar{Name: "IDS_ENABLE_EVENT_FORWARDING", Value: "true"},
		)
		volumeMounts = append(volumeMounts, syslogEventsForwardingVolumeMount())
		// On OpenShift, if we need the volume mount to hostpath volume for syslog forwarding,
		// then ID controller needs privileged access to write event logs to that volume
		if c.cfg.Openshift {
			sc.Privileged = ptr.BoolToPtr(true)
		}
	}

	return corev1.Container{
		Name:  "controller",
		Image: "gcr.io/tigera-dev/rd/tigera/intrusion-detection-controller:rene-fips", ImagePullPolicy: "Always", // todo: c.controllerImage,
		Env: envs,
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
		SecurityContext: sc,
		VolumeMounts:    volumeMounts,
	}
}

// Determine whether this component's configuration has syslog forwarding enabled or not.
// Look inside LogCollector spec for whether or not Syslog log type SyslogLogIDSEvents
// exists. If it does, then we need to turn on forwarding for IDS event logs.
func (c *intrusionDetectionComponent) syslogForwardingIsEnabled() bool {
	if c.cfg.LogCollector != nil && c.cfg.LogCollector.Spec.AdditionalStores != nil {
		syslog := c.cfg.LogCollector.Spec.AdditionalStores.Syslog
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

func (c *intrusionDetectionComponent) globalAlertTemplates() []client.Object {
	globalAlertTemplates := []client.Object{
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

	globalAlertTemplates = append(globalAlertTemplates, c.adJobsGlobalertTemplates()...)

	return globalAlertTemplates
}

func (c *intrusionDetectionComponent) adJobsGlobalertTemplates() []client.Object {
	return []client.Object{
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "dga",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "DGA detection",
				Summary:     "Looks for the domain names that could be created by the Domain Generation Algorithms (DGA), frequently used by malware.",
				Detector: &v3.DetectorParams{
					Name: "dga",
				},
				Severity: 100,
				Period:   &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "http-connection-spike",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "HTTP connection spike anomaly",
				Summary:     "Looks for the services that get too many HTTP inbound connections.",
				Severity:    100,
				Detector: &v3.DetectorParams{
					Name: "http_connection_spike",
				},
				Period: &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "http-response-codes",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "HTTP Response Code detection",
				Summary:     "Looks for services that respond with unusual numbers of 4xx and 5xx HTTP response codes.",
				Detector: &v3.DetectorParams{
					Name: "http_response_codes",
				},
				Severity: 100,
				Period:   &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "http-verbs",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "HTTP Response Verbs detection",
				Summary:     "Looks for the services that sent HTTP requests with rare verbs, like HEAD, CONNECT, OPTIONS.",
				Detector: &v3.DetectorParams{
					Name: "http_verbs",
				},
				Severity: 100,
				Period:   &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "port-scan",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "Port Scan detection",
				Summary:     "Looks for pods in your cluster that are sending packets to one destination on multiple ports.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "port_scan"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "generic-dns",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "Excessive value anomaly in DNS log",
				Summary:     "Looks for excessive values in several fields in the DNS log.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "generic_dns"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "generic-flows",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "Excessive value anomaly in flows log",
				Summary:     "Looks for excessive values in several fields in the flows log.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "generic_flows"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "generic-l7",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "Time series anomaly in L7 log",
				Summary:     "Looks at all numeric fields in the L7 log and how they changed over time.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "generic_l7"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "dns-latency",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "DNS latency",
				Summary:     "Looks for the clients that have too high latency of the DNS requests.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "dns_latency"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "l7-bytes",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "L7 bytes",
				Summary:     "Looks for pods that send or receive an excessive number of bytes in the L7 requests.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "l7_bytes"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "l7-latency",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "DNS Latency anomaly",
				Summary:     "Looks for the clients that have too high latency of the DNS requests.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "l7_latency"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "bytes-in",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "Inbound Service bytes anomaly",
				Summary:     "Looks for services that receive a high amount of data.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "bytes_in"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "bytes-out",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "Outbound Service bytes anomaly",
				Summary:     "Looks for pods that send a high amount of data.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "bytes_out"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "process-bytes",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "Process bytes",
				Summary:     "Looks for the processes with an excessive number of bytes sent or received.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "process_bytes"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
			},
		},
		&v3.GlobalAlertTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalAlertTemplate",
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorPrefixName + "process-restarts",
			},
			Spec: v3.GlobalAlertSpec{
				Type:        v3.GlobalAlertTypeAnomalyDetection,
				Description: "Process restarts anomaly",
				Summary:     "Looks for pods with excessive number of the process restarts.",
				Severity:    100,
				Detector:    &v3.DetectorParams{Name: "process_restarts"},
				Period:      &metav1.Duration{Duration: adDetectionJobsDefaultPeriod},
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
				Name:      IntrusionDetectionName,
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
	return c.cfg.TrustedCertBundle.HashAnnotations()
}

// AD API RBAC for accessing token and subject access reviews for AD Pod token verification
func (c *intrusionDetectionComponent) adAPIServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ADAPIObjectName,
			Namespace: IntrusionDetectionNamespace,
		},
	}
}

func (c *intrusionDetectionComponent) adAPIAccessClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ADAPIObjectName,
		},
		Rules: []rbacv1.PolicyRule{
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
		},
	}
}

func (c *intrusionDetectionComponent) adAPIAccessRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: ADAPIObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ADAPIObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ADAPIObjectName,
				Namespace: IntrusionDetectionNamespace,
			},
		},
	}
}

// AD API Service and Deployment
func (c *intrusionDetectionComponent) adAPIService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ADAPIObjectName,
			Namespace: IntrusionDetectionNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": ADAPIObjectName,
			},
			Ports: []corev1.ServicePort{
				{
					Name: ADAPIObjectPortName,
					Port: adAPIPort,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: adAPIPort,
					},
					Protocol: corev1.ProtocolTCP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func (c *intrusionDetectionComponent) adAPIDeployment() *appsv1.Deployment {
	adAPIStorageVolumePath := "/storage"
	adAPIStorageVolumeName := "volume-storage"
	var initContainers []corev1.Container
	if c.cfg.ADAPIServerCertSecret.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.ADAPIServerCertSecret.InitContainer(IntrusionDetectionNamespace))
	}
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ADAPIObjectName,
			Namespace: IntrusionDetectionNamespace,
			Labels: map[string]string{
				"k8s-app": ADAPIObjectName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &adAPIReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": ADAPIObjectName}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ADAPIObjectName,
					Namespace: IntrusionDetectionNamespace,
					Labels: map[string]string{
						"k8s-app": ADAPIObjectName,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: ADAPIObjectName,
					// setting tolerations, nodeselector as the node affinity setting respecting
					// the control plane tagged node as the centeralized node for anomaly
					// detection storage
					Tolerations:      c.cfg.Installation.ControlPlaneTolerations,
					NodeSelector:     c.cfg.Installation.ControlPlaneNodeSelector,
					ImagePullSecrets: secret.GetReferenceList(c.cfg.PullSecrets),
					Volumes: []corev1.Volume{
						c.cfg.TrustedCertBundle.Volume(),
						c.cfg.ADAPIServerCertSecret.Volume(),
						{
							Name: adAPIStorageVolumeName,
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
					InitContainers: initContainers,
					Containers: []corev1.Container{
						{
							Name:  ADAPIObjectName,
							Image: c.adAPIImage,
							Env: []corev1.EnvVar{
								{Name: "LOG_LEVEL", Value: "info"},
								{Name: "STORAGE_PATH", Value: adAPIStorageVolumePath},
								{Name: "TLS_KEY", Value: c.cfg.ADAPIServerCertSecret.VolumeMountKeyFilePath()},
								{Name: "TLS_CERT", Value: c.cfg.ADAPIServerCertSecret.VolumeMountCertificateFilePath()},
								{Name: "FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode)},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/health",
										Port:   intstr.FromInt(adAPIPort),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
							},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/health",
										Port:   intstr.FromInt(adAPIPort),
										Scheme: corev1.URISchemeHTTPS,
									},
								},
							},
							Command: []string{"/anomaly-detection-api"},
							VolumeMounts: []corev1.VolumeMount{
								c.cfg.TrustedCertBundle.VolumeMount(c.SupportedOSType()),
								c.cfg.ADAPIServerCertSecret.VolumeMount(c.SupportedOSType()),
								{
									MountPath: adAPIStorageVolumePath,
									Name:      adAPIStorageVolumeName,
									ReadOnly:  false,
								},
							},
						},
					},
				},
			},
		},
	}
}

// AD Detector PodTemplate  with RBAC
func (c *intrusionDetectionComponent) adDetectorServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      adDetectorName,
			Namespace: IntrusionDetectionNamespace,
		},
	}
}

// adDetectorSecret creates an external statuc secret resource associated with
// anomaly-detectors service account to for the podtemplate to reference instead
// of the one dynamically created with the ServiceAccount
func (c *intrusionDetectionComponent) adDetectorSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      adDetectorName,
			Namespace: IntrusionDetectionNamespace,
			Annotations: map[string]string{
				corev1.ServiceAccountNameKey: adDetectorName,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
}

func (c *intrusionDetectionComponent) adDetectorAccessRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      adDetectorName,
			Namespace: IntrusionDetectionNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					ADResourceGroup,
				},
				Resources: []string{
					ADDetectorsModelResourceName, ADLogTypeMetaDataResourceName,
				},
				Verbs: []string{
					"get",
					"create",
					"update",
				},
			},
		},
	}
}

func (c *intrusionDetectionComponent) adDetectorRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      adDetectorName,
			Namespace: IntrusionDetectionNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     adDetectorName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) adDetectorPodTemplates() []client.Object {
	trainingJobPodTemplate := c.getBaseADDetectorsPodTemplate(ADJobPodTemplateBaseName + ".training")
	detecionADJobPodTemplate := c.getBaseADDetectorsPodTemplate(ADJobPodTemplateBaseName + ".detection")

	return []client.Object{&trainingJobPodTemplate, &detecionADJobPodTemplate}
}

func (c *intrusionDetectionComponent) getBaseADDetectorsPodTemplate(podTemplateName string) corev1.PodTemplate {
	privileged := false
	if c.cfg.Openshift {
		privileged = true
	}

	envVars := []corev1.EnvVar{
		{
			Name:  "MODEL_STORAGE_API_HOST",
			Value: ADAPIExpectedServiceName,
		},
		{
			Name:  "MODEL_STORAGE_API_PORT",
			Value: strconv.Itoa(adAPIPort),
		},
		{
			Name:  "MODEL_STORAGE_CLIENT_CERT",
			Value: c.cfg.ADAPIServerCertSecret.VolumeMountCertificateFilePath(),
		},
		{
			Name:      "MODEL_STORAGE_API_TOKEN",
			ValueFrom: secret.GetEnvVarSource(adDetectorName, "token", false),
		},
		{
			Name:  "FIPS_MODE_ENABLED",
			Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode),
		},
	}

	container := corev1.Container{
		Name:  "adjobs",
		Image: c.adDetectorsImage,
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		Env: envVars,
		VolumeMounts: []corev1.VolumeMount{
			c.cfg.TrustedCertBundle.VolumeMount(c.SupportedOSType()),
			c.cfg.ADAPIServerCertSecret.VolumeMount(c.SupportedOSType()),
		},
	}

	return corev1.PodTemplate{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PodTemplate",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: IntrusionDetectionNamespace,
			Name:      podTemplateName,
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podTemplateName,
				Namespace: IntrusionDetectionNamespace,
				Labels: map[string]string{
					"k8s-app": IntrusionDetectionControllerName,
				},
			},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{
					c.cfg.TrustedCertBundle.Volume(),
					c.cfg.ADAPIServerCertSecret.Volume(),
				},
				DNSPolicy:          corev1.DNSClusterFirst,
				ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
				RestartPolicy:      corev1.RestartPolicyOnFailure,
				ServiceAccountName: adDetectorName,
				Tolerations:        append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateControlPlane...),
				Containers: []corev1.Container{
					relasticsearch.ContainerDecorate(container, c.cfg.ESClusterConfig.ClusterName(), ElasticsearchADJobUserSecret, c.cfg.ClusterDomain, c.SupportedOSType()),
				},
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerAllowTigeraPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		// Block any link local IPs, e.g. cloud metadata, which are often targets of server-side request forgery (SSRF) attacks
		{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets: []string{"169.254.0.0/16"},
			},
		},
		{
			Action:   v3.Deny,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Nets: []string{"fe80::/10"},
			},
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Openshift)
	if c.cfg.ManagedCluster {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: GuardianEntityRule,
		})
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.ESGatewayEntityRule,
		})
	}
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			// Pass to subsequent tiers for further enforcement
			Action: v3.Pass,
		},
	}...)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionControllerPolicyName,
			Namespace: IntrusionDetectionNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(IntrusionDetectionControllerName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					// Intrusion detection controller doesn't listen on any external ports
					Action: v3.Deny,
				},
			},
			Egress: egressRules,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchAllowTigeraPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.ESGatewayEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerPolicyName,
			Namespace: IntrusionDetectionNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: fmt.Sprintf("job-name == '%s'", IntrusionDetectionInstallerJobName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

func adAPIIngressRuleForDetector(detectorCycle string) v3.Rule {
	return v3.Rule{
		Action:   v3.Allow,
		Protocol: &networkpolicy.TCPProtocol,
		Source: v3.EntityRule{
			Selector:          detectorCycleSelector(detectorCycle),
			NamespaceSelector: intrusionDetectionNamespaceSelector,
		},
		Destination: v3.EntityRule{
			Ports: networkpolicy.Ports(adAPIPort),
		},
	}
}

func (c *intrusionDetectionComponent) adAPIAllowTigeraPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.KubeAPIServerEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ADAPIPolicyName,
			Namespace: IntrusionDetectionNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(ADAPIObjectName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				adAPIIngressRuleForDetector("detection"),
				adAPIIngressRuleForDetector("training"),
			},
			Egress: egressRules,
		},
	}
}

func detectorCycleSelector(detectorCycles ...string) string {
	var builder strings.Builder
	if len(detectorCycles) > 1 {
		builder.WriteByte('(')
	}
	for idx, detectorCycle := range detectorCycles {
		builder.WriteString("tigera.io.detector-cycle == '")
		builder.WriteString(detectorCycle)
		builder.WriteByte('\'')
		if idx != len(detectorCycles)-1 {
			builder.WriteString(" || ")
		}
	}
	if len(detectorCycles) > 1 {
		builder.WriteByte(')')
	}
	return builder.String()
}

func (c *intrusionDetectionComponent) adDetectorAllowTigeraPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Openshift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.CreateEntityRule(ElasticsearchNamespace, "tigera-secure-es-gateway", 5554, 9200),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.CreateEntityRule(ElasticsearchNamespace, ADAPIObjectName, adAPIPort),
		},
	}...)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ADDetectorPolicyName,
			Namespace: IntrusionDetectionNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: detectorCycleSelector("training", "detection"),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source: v3.EntityRule{
						Selector:          networkpolicy.KubernetesAppSelector(ADAPIObjectName),
						NamespaceSelector: intrusionDetectionNamespaceSelector,
					},
				},
			},
			Egress: egressRules,
		},
	}
}
