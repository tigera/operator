// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
)

const (
	IntrusionDetectionNamespace = "tigera-intrusion-detection"
	IntrusionDetectionName      = "intrusion-detection-controller"

	ElasticsearchIntrusionDetectionUserSecret    = "tigera-ee-intrusion-detection-elasticsearch-access"
	ElasticsearchIntrusionDetectionJobUserSecret = "tigera-ee-installer-elasticsearch-access"
	ElasticsearchPerformanceHotspotsUserSecret   = "tigera-ee-performance-hotspots-elasticsearch-access"

	IntrusionDetectionInstallerJobName     = "intrusion-detection-es-job-installer"
	IntrusionDetectionControllerName       = "intrusion-detection-controller"
	IntrusionDetectionControllerPolicyName = networkpolicy.TigeraComponentPolicyPrefix + IntrusionDetectionControllerName
	IntrusionDetectionInstallerPolicyName  = networkpolicy.TigeraComponentPolicyPrefix + "intrusion-detection-elastic"

	ADAPIObjectName                 = "anomaly-detection-api"
	ADAPIPodSecurityPolicyName      = "anomaly-detection-api"
	IntrusionDetectionTLSSecretName = "intrusion-detection-tls"
	DPITLSSecretName                = "deep-packet-inspection-tls"
	ADAPIPolicyName                 = networkpolicy.TigeraComponentPolicyPrefix + ADAPIObjectName

	ADPersistentVolumeClaimName = "tigera-anomaly-detection"
	ADJobPodTemplateBaseName    = "tigera.io.detectors"
	adDetectorPrefixName        = "tigera.io.detector."
	adDetectorName              = "anomaly-detectors"
	ADDetectorPolicyName        = networkpolicy.TigeraComponentPolicyPrefix + adDetectorName
)

// Register secret/certs that need Server and Client Key usage
var (
	intrusionDetectionNamespaceSelector = fmt.Sprintf("projectcalico.org/name == '%s'", IntrusionDetectionNamespace)
	IntrusionDetectionSourceEntityRule  = v3.EntityRule{
		NamespaceSelector: intrusionDetectionNamespaceSelector,
		Selector:          fmt.Sprintf("k8s-app == '%s'", IntrusionDetectionControllerName),
	}
)

var IntrusionDetectionInstallerSourceEntityRule = v3.EntityRule{
	NamespaceSelector: intrusionDetectionNamespaceSelector,
	Selector:          fmt.Sprintf("job-name == '%s'", IntrusionDetectionInstallerJobName),
}

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(DPITLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

func IntrusionDetection(cfg *IntrusionDetectionConfiguration) Component {
	return &intrusionDetectionComponent{
		cfg: cfg,
	}
}

// IntrusionDetectionConfiguration contains all the config information needed to render the component.
type IntrusionDetectionConfiguration struct {
	IntrusionDetection operatorv1.IntrusionDetection
	LogCollector       *operatorv1.LogCollector
	Installation       *operatorv1.InstallationSpec
	PullSecrets        []*corev1.Secret
	Openshift          bool
	ClusterDomain      string
	ESLicenseType      ElasticsearchLicenseType
	ManagedCluster     bool
	ManagementCluster  bool

	HasNoLicense                 bool
	TrustedCertBundle            certificatemanagement.TrustedBundleRO
	IntrusionDetectionCertSecret certificatemanagement.KeyPairInterface

	Namespace      string
	BindNamespaces []string
	Tenant         *operatorv1.Tenant
}

type intrusionDetectionComponent struct {
	cfg                    *IntrusionDetectionConfiguration
	controllerImage        string
	webhooksProcessorImage string
}

func (c *intrusionDetectionComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var errMsgs []string
	var err error

	c.controllerImage, err = components.GetReference(components.ComponentIntrusionDetectionController, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.webhooksProcessorImage, err = components.GetReference(components.ComponentSecurityEventWebhooksProcessor, reg, path, prefix, is)
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
	pss := PSSRestricted
	if c.syslogForwardingIsEnabled() {
		pss = PSSPrivileged
	}

	objs := []client.Object{}
	if !c.cfg.Tenant.MultiTenant() {
		// In multi-tenant environments, the namespace is pre-created. So, only create it if we're not in a multi-tenant environment.
		objs = append(objs, CreateNamespace(c.cfg.Namespace, c.cfg.Installation.KubernetesProvider, PodSecurityStandard(pss)))

		// GlobalAlertTemplates are not used in multi-tenant management clusters.
		objs = append(objs, c.globalAlertTemplates()...)
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(c.cfg.Namespace, c.cfg.PullSecrets...)...)...)

	objs = append(objs,
		c.intrusionDetectionControllerAllowTigeraPolicy(),
		networkpolicy.AllowTigeraDefaultDeny(c.cfg.Namespace),
		c.intrusionDetectionServiceAccount(),
		c.intrusionDetectionClusterRole(),
		c.intrusionDetectionClusterRoleBinding(),
		c.intrusionDetectionRole(),
		c.intrusionDetectionRoleBinding(),
		c.intrusionDetectionDeployment(),
	)

	objsToDelete := []client.Object{
		// PSPs have been removed from the Kubenretes API since v1.25, so we can delete
		// any resources related to them that might still exist.
		c.intrusionDetectionPSPClusterRole(),
		c.intrusionDetectionPSPClusterRoleBinding(),
	}

	if !c.cfg.ManagedCluster && !c.cfg.Tenant.MultiTenant() {
		// Delete any anomaly detection components that might still exist.
		// These were removed in an earlier version of the operator.
		objsToDelete = append(objsToDelete, c.adComponentsToDelete()...)
	}

	if !c.cfg.ManagedCluster && !c.cfg.Tenant.MultiTenant() {
		// For now, we don't create the installer job in multi-tenant clusters.
		idsObjs := []client.Object{
			c.intrusionDetectionJobServiceAccount(),
			c.intrusionDetectionElasticsearchAllowTigeraPolicy(),
			c.intrusionDetectionElasticsearchJob(),
		}
		objsToDelete = append(objsToDelete, idsObjs...)
	}

	if c.cfg.ManagedCluster {
		// For managed clusters, we must create a role binding to allow Linseed to
		// manage access token secrets in our namespace.
		objs = append(objs, c.externalLinseedRoleBinding())
	} else {
		// We can delete the role binding for management and standalone clusters, since
		// for these cluster types normal serviceaccount tokens are used.
		objsToDelete = append(objsToDelete, c.externalLinseedRoleBinding())
	}

	if c.cfg.HasNoLicense {
		return nil, objs
	}
	return objs, objsToDelete
}

func (c *intrusionDetectionComponent) Ready() bool {
	return true
}

func (c *intrusionDetectionComponent) intrusionDetectionElasticsearchJob() *batchv1.Job {
	return &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerJobName,
			Namespace: c.cfg.Namespace,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
			Namespace: c.cfg.Namespace,
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionJobServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerJobName,
			Namespace: c.cfg.Namespace,
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
		{
			// Add write access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"events"},
			Verbs:     []string{"create"},
		},
		{
			// Add write/read/delete access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"threatfeeds_ipset", "threatfeeds_domainnameset"},
			Verbs:     []string{"create", "delete", "get"},
		},
		{
			// Add read access to Linseed APIs.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{
				"waflogs",
				"dnslogs",
				"l7logs",
				"flowlogs",
				"auditlogs",
				"events",
			},
			Verbs: []string{"get"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"secrets", "configmaps"},
			Verbs:     []string{"get", "watch"},
		},
		{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "watch", "update"},
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

		// We don't have AD CronJobs any more, but leaving this here in case it now applies
		// to more cases, as there's nothing actual specific to AD CronJobs in the following
		// rule definition.
		//
		// "Used when IDS Controller creates Cronjobs for AD as the IDS deployment
		// is the owner of the AD Cronjobs - Openshift blocks setting an
		// blockOwnerDeletion to true if an ownerReference refers to a resource
		// you can't set finalizers on"
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

	if c.cfg.Installation.KubernetesProvider == operatorv1.ProviderOpenShift {
		if c.syslogForwardingIsEnabled() {
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{PSSPrivileged},
			})
		}
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
	return rcomponents.ClusterRoleBinding(IntrusionDetectionName, IntrusionDetectionName, IntrusionDetectionName, c.cfg.BindNamespaces)
}

func (c *intrusionDetectionComponent) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	// For managed clusters, we must create a role binding to allow Linseed to manage access token secrets
	// in our namespace.
	linseed := "tigera-linseed"
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      linseed,
			Namespace: c.cfg.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     TigeraLinseedSecretsClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      linseed,
				Namespace: ElasticsearchNamespace,
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
			Namespace: c.cfg.Namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get"},
			},
			{
				// Intrusion detection forwarder snapshots its state to a specific ConfigMap.
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "create", "update"},
			},
		},
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionName,
			Namespace: c.cfg.Namespace,
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
				Namespace: c.cfg.Namespace,
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
			Namespace: c.cfg.Namespace,
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

	volumes := []corev1.Volume{
		c.cfg.TrustedCertBundle.Volume(),
		c.cfg.IntrusionDetectionCertSecret.Volume(),
	}
	// If syslog forwarding is enabled then set the necessary hostpath volume to write
	// logs for Fluentd to access.
	if c.syslogForwardingIsEnabled() {
		dirOrCreate := corev1.HostPathDirectoryOrCreate
		volumes = append(volumes, corev1.Volume{
			Name: "var-log-calico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico",
					Type: &dirOrCreate,
				},
			},
		})
	}

	if c.cfg.ManagedCluster {
		volumes = append(volumes,
			corev1.Volume{
				Name: LinseedTokenVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf(LinseedTokenSecret, IntrusionDetectionName),
						Items:      []corev1.KeyToPath{{Key: LinseedTokenKey, Path: LinseedTokenSubPath}},
					},
				},
			})
	}

	intrusionDetectionContainer := c.intrusionDetectionControllerContainer()

	if c.cfg.ManagedCluster {
		envVars := []corev1.EnvVar{
			{Name: "DISABLE_ALERTS", Value: "yes"},
		}
		intrusionDetectionContainer.Env = append(intrusionDetectionContainer.Env, envVars...)
	}
	var initContainers []corev1.Container
	if c.cfg.IntrusionDetectionCertSecret != nil && c.cfg.IntrusionDetectionCertSecret.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.IntrusionDetectionCertSecret.InitContainer(c.cfg.Namespace))
	}

	containers := []corev1.Container{
		intrusionDetectionContainer,
		c.webhooksControllerContainer(),
	}

	return &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        IntrusionDetectionName,
			Namespace:   c.cfg.Namespace,
			Annotations: c.intrusionDetectionAnnotations(),
		},
		Spec: corev1.PodSpec{
			Tolerations:        c.cfg.Installation.ControlPlaneTolerations,
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: IntrusionDetectionName,
			ImagePullSecrets:   ps,
			InitContainers:     initContainers,
			Containers:         containers,
			Volumes:            volumes,
		},
	}
}

func (c *intrusionDetectionComponent) webhooksControllerContainer() corev1.Container {
	envVars := []corev1.EnvVar{
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, ElasticsearchNamespace),
		},
		{
			Name:  "LINSEED_CA",
			Value: c.cfg.TrustedCertBundle.MountPath(),
		},
		{
			Name:  "LINSEED_CLIENT_CERT",
			Value: c.cfg.IntrusionDetectionCertSecret.VolumeMountCertificateFilePath(),
		},
		{
			Name:  "LINSEED_CLIENT_KEY",
			Value: c.cfg.IntrusionDetectionCertSecret.VolumeMountKeyFilePath(),
		},
		{
			Name:  "LINSEED_TOKEN",
			Value: GetLinseedTokenPath(c.cfg.ManagedCluster),
		},
	}

	volumeMounts := c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())
	volumeMounts = append(volumeMounts, c.cfg.IntrusionDetectionCertSecret.VolumeMount(c.SupportedOSType()))
	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: LinseedVolumeMountPath,
			})
	}

	return corev1.Container{
		Name:            "webhooks-processor",
		Image:           c.webhooksProcessorImage,
		ImagePullPolicy: ImagePullPolicy(),
		Env:             envVars,
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerContainer() corev1.Container {
	envs := []corev1.EnvVar{
		{
			Name:  "MULTI_CLUSTER_FORWARDING_CA",
			Value: c.cfg.TrustedCertBundle.MountPath(),
		},
		{
			Name:  "FIPS_MODE_ENABLED",
			Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode),
		},
		{
			Name:  "LINSEED_URL",
			Value: relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, ElasticsearchNamespace),
		},
		{
			Name:  "LINSEED_CA",
			Value: c.cfg.TrustedCertBundle.MountPath(),
		},
		{
			Name:  "LINSEED_CLIENT_CERT",
			Value: c.cfg.IntrusionDetectionCertSecret.VolumeMountCertificateFilePath(),
		},
		{
			Name:  "LINSEED_CLIENT_KEY",
			Value: c.cfg.IntrusionDetectionCertSecret.VolumeMountKeyFilePath(),
		},
		{
			Name:  "LINSEED_TOKEN",
			Value: GetLinseedTokenPath(c.cfg.ManagedCluster),
		},
	}

	sc := securitycontext.NewNonRootContext()

	// If syslog forwarding is enabled then set the necessary ENV var and volume mount to
	// write logs for Fluentd.
	volumeMounts := c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType())
	volumeMounts = append(volumeMounts, c.cfg.IntrusionDetectionCertSecret.VolumeMount(c.SupportedOSType()))
	if c.syslogForwardingIsEnabled() {
		envs = append(envs,
			corev1.EnvVar{Name: "IDS_ENABLE_EVENT_FORWARDING", Value: "true"},
		)
		volumeMounts = append(volumeMounts, syslogEventsForwardingVolumeMount())
		// When syslog forwarding is enabled, IDS controller mounts host volume /var/log/calico
		// and writes events to it. This host path is owned by root user and group so we have to
		// use privileged UID/GID 0.
		// On OpenShift, if we need the volume mount to hostpath volume for syslog forwarding,
		// then IDS controller needs privileged access to write event logs to that volume
		sc = securitycontext.NewRootContext(c.cfg.Openshift)
	}

	if c.cfg.ManagedCluster {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      LinseedTokenVolumeName,
				MountPath: LinseedVolumeMountPath,
			})
	}

	return corev1.Container{
		Name:            "controller",
		Image:           c.controllerImage,
		ImagePullPolicy: ImagePullPolicy(),
		Env:             envs,
		// Needed for permissions to write to the audit log
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/usr/bin/healthz",
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

	return globalAlertTemplates
}

func (c *intrusionDetectionComponent) intrusionDetectionAnnotations() map[string]string {
	return c.cfg.TrustedCertBundle.HashAnnotations()
}

func (c *intrusionDetectionComponent) intrusionDetectionControllerAllowTigeraPolicy() *v3.NetworkPolicy {
	helper := networkpolicy.Helper(c.cfg.Tenant.MultiTenant(), c.cfg.Namespace)

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
			Destination: helper.LinseedEntityRule(),
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
			Namespace: c.cfg.Namespace,
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
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      IntrusionDetectionInstallerPolicyName,
			Namespace: c.cfg.Namespace,
		},
	}
}

// adComponentsToDelete returns a list of objects to delete. Anomaly detection used to be installed here,
// but has since been removed. This function is kept around to clean up any old objects that may be left.
func (c intrusionDetectionComponent) adComponentsToDelete() []client.Object {
	objs := []client.Object{
		&corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADAPIObjectName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: ADAPIObjectName,
			},
		},

		&rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: ADAPIObjectName,
			},
		},

		&corev1.Service{
			TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADAPIObjectName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&corev1.PersistentVolumeClaim{
			TypeMeta: metav1.TypeMeta{
				Kind:       "PersistentVolumeClaim",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADPersistentVolumeClaimName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADAPIObjectName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&corev1.ServiceAccount{
			TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorName,
			},
		},

		&rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      adDetectorName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: adDetectorName,
			},
		},

		&v3.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADAPIPolicyName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&v3.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ADDetectorPolicyName,
				Namespace: IntrusionDetectionNamespace,
			},
		},

		&corev1.PodTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "PodTemplate",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: IntrusionDetectionNamespace,
				Name:      ADJobPodTemplateBaseName + ".training",
			},
		},

		&corev1.PodTemplate{
			TypeMeta: metav1.TypeMeta{
				Kind:       "PodTemplate",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: IntrusionDetectionNamespace,
				Name:      ADJobPodTemplateBaseName + ".detection",
			},
		},
	}

	adAlgorithms := []string{
		"dga",
		"http-connection-spike",
		"http-response-codes",
		"http-verbs",
		"port-scan",
		"generic-dns",
		"generic-flows",
		"multivariable-flow",
		"generic-l7",
		"dns-latency",
		"dns-tunnel",
		"l7-bytes",
		"l7-latency",
		"bytes-in",
		"bytes-out",
		"process-bytes",
		"process-restarts",
	}

	for _, alg := range adAlgorithms {
		objs = append(objs,
			&v3.GlobalAlertTemplate{
				TypeMeta: metav1.TypeMeta{
					Kind:       "GlobalAlertTemplate",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: adDetectorPrefixName + alg,
				},
			},
			&v3.GlobalAlert{
				TypeMeta: metav1.TypeMeta{
					Kind:       "GlobalAlert",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: adDetectorPrefixName + alg,
				},
			},
		)
	}

	return objs
}

// instrusionDetectionPSPClusterRole returns metadata for the legacy PSP cluster role. This is no longer installed, and this function
// exists solely to remove it from the cluster if it exists.
func (c *intrusionDetectionComponent) intrusionDetectionPSPClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-psp"},
	}
}

// intrusionDetectionPSPClusterRoleBinding returns metadata for the legacy PSP cluster role binding. This is no longer installed, and this function
// exists solely to remove it from the cluster if it exists.
func (c *intrusionDetectionComponent) intrusionDetectionPSPClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "intrusion-detection-psp"},
	}
}
