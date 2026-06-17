// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package enterprise

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	auditLogsVolumeName   = "calico-audit-logs"
	auditPolicyVolumeName = "calico-audit-policy"
)

// apiServer carries the rendered API server configuration and resolved image so the
// enterprise builders (moved verbatim from the render package) can construct the
// Enterprise-only objects and deployment additions.
type apiServer struct {
	cfg         *render.APIServerConfiguration
	calicoImage string
}

func registerAPIServer(s *extensions.Set) {
	s.Register(operatorv1.CalicoEnterprise, render.ComponentNameAPIServer, extensions.Extension{
		Modify: modifyAPIServer,
	})
	// When running Calico, clean up any Enterprise objects left behind by a prior
	// Enterprise installation.
	s.Register(operatorv1.Calico, render.ComponentNameAPIServer, extensions.Extension{
		Modify: cleanupAPIServer,
	})
}

// modifyAPIServer layers Calico Enterprise behavior onto the rendered API server objects:
// the query server container and its volumes, audit logging on the aggregation API server
// container, the Enterprise RBAC objects, and the query server port on the Service.
func modifyAPIServer(ctx extensions.RenderContext, create, del []client.Object) ([]client.Object, []client.Object) {
	ec, ok := ctx.Component.(render.APIServerExtensionContext)
	if !ok {
		logrus.Errorf("BUG: apiserver modifier got %T, want render.APIServerExtensionContext; leaving objects unchanged", ctx.Component)
		return create, del
	}
	c := &apiServer{cfg: ec.Config, calicoImage: ec.CalicoImage}

	if dep, ok := extensions.FindObject[*appsv1.Deployment](create, render.APIServerName); ok {
		c.layerDeployment(dep)
	}
	if svc, ok := extensions.FindObject[*corev1.Service](create, render.APIServerServiceName); ok {
		c.addQueryServerPort(svc)
	}
	// Enterprise serves staged policies through the tiered-policy passthrough role.
	if role, ok := extensions.FindObject[*rbacv1.ClusterRole](create, "calico-tiered-policy-passthrough"); ok {
		for i := range role.Rules {
			if contains(role.Rules[i].Resources, "networkpolicies") {
				role.Rules[i].Resources = append(role.Rules[i].Resources, "stagednetworkpolicies", "stagedglobalnetworkpolicies")
			}
		}
	}

	// Global Enterprise RBAC.
	create = append(create, c.tigeraAPIServerClusterRole(), c.tigeraAPIServerClusterRoleBinding())
	if !c.cfg.MultiTenant {
		// These resources are only installed in zero-tenant clusters.
		create = append(create, c.tigeraUserClusterRole(), c.tigeraNetworkAdminClusterRole())
	}
	if c.cfg.ManagementCluster != nil {
		create = append(create, c.managedClusterWatchClusterRole())
		if c.cfg.MultiTenant {
			create = append(create, c.multiTenantSecretsRBAC()...)
			create = append(create, c.multiTenantManagedClusterAccessClusterRoles()...)
		} else {
			create = append(create, c.secretsRBAC()...)
		}
	} else {
		// If we're not a management cluster, the API server doesn't need permissions to access secrets.
		del = append(del, c.multiTenantSecretsRBAC()...)
		del = append(del, c.secretsRBAC()...)
		del = append(del, c.multiTenantManagedClusterAccessClusterRoles()...)
		del = append(del, c.managedClusterWatchClusterRole())
	}

	// Namespaced Enterprise objects.
	if c.cfg.TrustedBundle != nil {
		create = append(create, c.cfg.TrustedBundle.ConfigMap(render.QueryserverNamespace))
	}
	if c.cfg.ManagementClusterConnection != nil {
		create = append(create, c.externalLinseedRoleBinding())
	}

	// Objects that only exist alongside the aggregation API server.
	aggregationObjects := []client.Object{
		c.uiSettingsGroupGetterClusterRole(),
		c.kubeControllerManagerUISettingsGroupGetterClusterRoleBinding(),
		c.uiSettingsPassthruClusterRole(),
		c.uiSettingsPassthruClusterRolebinding(),
		c.auditPolicyConfigMap(),
	}
	if c.cfg.RequiresAggregationServer {
		create = append(create, aggregationObjects...)
	} else {
		del = append(del, aggregationObjects...)
	}

	// Clean up cluster-scoped resources that were created with the 'tigera' prefix.
	del = append(del, c.deprecatedResources()...)

	// Re-apply deployment overrides so the modifier-added query server container picks up
	// any per-container overrides. The override appliers use replace/merge semantics, so
	// re-running over the render-applied containers is idempotent.
	if dep, ok := extensions.FindObject[*appsv1.Deployment](create, render.APIServerName); ok {
		if overrides := c.cfg.APIServer.APIServerDeployment; overrides != nil {
			rcomp.ApplyDeploymentOverrides(dep, overrides)
		}
	}

	return create, del
}

// cleanupAPIServer deletes the Enterprise API server objects when running Calico, so a
// cluster switched from Enterprise to Calico does not leave them behind.
func cleanupAPIServer(ctx extensions.RenderContext, create, del []client.Object) ([]client.Object, []client.Object) {
	ec, ok := ctx.Component.(render.APIServerExtensionContext)
	if !ok {
		logrus.Errorf("BUG: apiserver cleanup got %T, want render.APIServerExtensionContext; leaving objects unchanged", ctx.Component)
		return create, del
	}
	c := &apiServer{cfg: ec.Config}

	del = append(del, c.tigeraAPIServerClusterRole(), c.tigeraAPIServerClusterRoleBinding())
	if !c.cfg.MultiTenant {
		del = append(del, c.tigeraUserClusterRole(), c.tigeraNetworkAdminClusterRole())
	}
	del = append(del, c.multiTenantSecretsRBAC()...)
	del = append(del, c.secretsRBAC()...)
	del = append(del, c.multiTenantManagedClusterAccessClusterRoles()...)
	del = append(del, c.managedClusterWatchClusterRole())

	return create, del
}

// layerDeployment adds the Enterprise query server container, audit logging, and the
// query server / trusted bundle volumes to the rendered API server deployment.
func (c *apiServer) layerDeployment(d *appsv1.Deployment) {
	// Audit logging is performed through the aggregation API server container, which is
	// only present when the aggregation API server is running.
	if c.cfg.RequiresAggregationServer {
		for i := range d.Spec.Template.Spec.Containers {
			ctr := &d.Spec.Template.Spec.Containers[i]
			if ctr.Name != string(render.APIServerContainerName) {
				continue
			}
			ctr.VolumeMounts = append(ctr.VolumeMounts,
				corev1.VolumeMount{Name: auditLogsVolumeName, MountPath: "/var/log/calico/audit"},
				corev1.VolumeMount{Name: auditPolicyVolumeName, MountPath: "/etc/tigera/audit"},
			)
			ctr.Args = append(ctr.Args,
				"--audit-policy-file=/etc/tigera/audit/policy.conf",
				"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			)
			// In case of OpenShift, apiserver needs privileged access to write audit logs to the
			// host path volume. Audit logs are owned by root on hosts so we need to be root.
			ctr.SecurityContext = securitycontext.NewRootContext(c.cfg.OpenShift)
		}

		d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, c.auditVolumes()...)
	}

	d.Spec.Template.Spec.Containers = append(d.Spec.Template.Spec.Containers, c.queryServerContainer())

	if c.cfg.TrustedBundle != nil {
		d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, c.cfg.TrustedBundle.Volume())
		for k, v := range c.cfg.TrustedBundle.HashAnnotations() {
			d.Spec.Template.Annotations[k] = v
		}
	}
}

// auditVolumes are the host-path audit log and audit policy volumes used by the
// aggregation API server container.
func (c *apiServer) auditVolumes() []corev1.Volume {
	return []corev1.Volume{
		{
			Name: auditLogsVolumeName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/audit",
					Type: ptr.To(corev1.HostPathDirectoryOrCreate),
				},
			},
		},
		{
			Name: auditPolicyVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: auditPolicyVolumeName},
					Items: []corev1.KeyToPath{
						{
							Key:  "config",
							Path: "policy.conf",
						},
					},
				},
			},
		},
	}
}

func (c *apiServer) addQueryServerPort(s *corev1.Service) {
	queryServerTargetPort := render.GetContainerPort(c.cfg, render.TigeraAPIServerQueryServerContainerName)
	s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{
		Name:       render.QueryServerPortName,
		Port:       render.QueryServerPort,
		Protocol:   corev1.ProtocolTCP,
		TargetPort: intstr.FromInt32(queryServerTargetPort.ContainerPort),
	})
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (c *apiServer) multiTenantSecretsRBAC() []client.Object {
	return render.TunnelSecretRBAC(render.APIServerSecretsRBACName, render.APIServerServiceAccountName, c.cfg.ManagementCluster, true)
}

func (c *apiServer) secretsRBAC() []client.Object {
	return render.TunnelSecretRBAC(render.APIServerSecretsRBACName, render.APIServerServiceAccountName, c.cfg.ManagementCluster, false)
}

func (c *apiServer) queryServerContainer() corev1.Container {
	queryServerTargetPort := render.GetContainerPort(c.cfg, render.TigeraAPIServerQueryServerContainerName).ContainerPort

	var tlsSecret certificatemanagement.KeyPairInterface
	if c.cfg.QueryServerTLSKeyPairCertificateManagementOnly != nil {
		tlsSecret = c.cfg.QueryServerTLSKeyPairCertificateManagementOnly
	} else {
		tlsSecret = c.cfg.TLSKeyPair
	}
	env := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "LISTEN_ADDR", Value: fmt.Sprintf(":%d", queryServerTargetPort)},
		{Name: "TLS_CERT", Value: fmt.Sprintf("/%s/tls.crt", tlsSecret.GetName())},
		{Name: "TLS_KEY", Value: fmt.Sprintf("/%s/tls.key", tlsSecret.GetName())},
	}
	if c.cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "TRUSTED_BUNDLE_PATH", Value: c.cfg.TrustedBundle.MountPath()})
	}

	if render.HostNetwork(c.cfg) {
		env = append(env, c.cfg.K8SServiceEndpoint.EnvVars()...)
	} else {
		env = append(env, c.cfg.K8SServiceEndpointPodNetwork.EnvVars()...)
	}

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("")...)
	}

	linseedURL := relasticsearch.LinseedEndpoint(rmeta.OSTypeLinux, c.cfg.ClusterDomain, render.ElasticsearchNamespace, c.cfg.ManagementClusterConnection != nil, false)
	env = append(env,
		corev1.EnvVar{Name: "LINSEED_URL", Value: linseedURL},
		corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: fmt.Sprintf("/%s/tls.crt", tlsSecret.GetName())},
		corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: fmt.Sprintf("/%s/tls.key", tlsSecret.GetName())},
	)
	if c.cfg.ManagementClusterConnection != nil {
		env = append(env,
			corev1.EnvVar{Name: "CLUSTER_ID", Value: ""},
			corev1.EnvVar{Name: "LINSEED_TOKEN", Value: render.GetLinseedTokenPath(true)},
		)
	}
	if c.cfg.TrustedBundle != nil {
		env = append(env, corev1.EnvVar{Name: "LINSEED_CA", Value: c.cfg.TrustedBundle.MountPath()})
	}

	// set LogLEVEL for queryserver container
	if logging := c.cfg.APIServer.Logging; logging != nil &&
		logging.QueryServerLogging != nil && logging.QueryServerLogging.LogSeverity != nil {
		env = append(env,
			corev1.EnvVar{Name: "LOGLEVEL", Value: strings.ToLower(string(*logging.QueryServerLogging.LogSeverity))})
	} else {
		// set default LOGLEVEL to info when not set by the user
		env = append(env, corev1.EnvVar{Name: "LOGLEVEL", Value: "info"})
	}

	volumeMounts := []corev1.VolumeMount{
		tlsSecret.VolumeMount(rmeta.OSTypeLinux),
	}
	if c.cfg.TrustedBundle != nil {
		volumeMounts = append(volumeMounts, c.cfg.TrustedBundle.VolumeMounts(rmeta.OSTypeLinux)...)
	}
	if c.cfg.ManagementClusterConnection != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      render.LinseedTokenVolumeName,
			MountPath: render.LinseedVolumeMountPath,
		})
	}

	container := corev1.Container{
		Name:    string(render.TigeraAPIServerQueryServerContainerName),
		Image:   c.calicoImage,
		Command: []string{components.CalicoBinaryPath, "component", "queryserver"},
		Env:     env,
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt32(queryServerTargetPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts:    volumeMounts,
	}
	return container
}

func (c *apiServer) externalLinseedRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-linseed",
			Namespace: render.APIServerNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.TigeraLinseedSecretsClusterRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.GuardianServiceAccountName,
				Namespace: render.GuardianNamespace,
			},
		},
	}
}

func (c *apiServer) tigeraAPIServerClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Read access to Linseed policy activity data for queryserver enrichment.
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"policyactivity"},
			Verbs:     []string{"get"},
		},
		{
			// Calico Enterprise backing storage.
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"bfdconfigurations",
				"deeppacketinspections",
				"deeppacketinspections/status",
				"egressgatewaypolicies",
				"externalnetworks",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalreports",
				"globalreports/status",
				"globalreporttypes",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"licensekeys",
				"managedclusters",
				"managedclusters/status",
				"networks",
				"packetcaptures",
				"packetcaptures/status",
				"policyrecommendationscopes",
				"policyrecommendationscopes/status",
				"remoteclusterconfigurations",
				"securityeventwebhooks",
				"securityeventwebhooks/status",
				"uisettings",
				"uisettingsgroups",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
				"create",
				"update",
				"delete",
				"patch",
			},
		},
		{
			// The queryserver's RBAC calculator needs to list tiers,
			// uisettingsgroups, and managedclusters via the aggregated
			// API to evaluate user permissions for the /policies endpoint.
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"tiers",
				"uisettingsgroups",
				"managedclusters",
			},
			Verbs: []string{"get", "list", "watch"},
		},
		{
			// Required by the AuthorizationReview calculator in queryserver to evaluate
			// RBAC permissions for users.
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{
				"clusterroles",
				"clusterrolebindings",
				"roles",
				"rolebindings",
			},
			Verbs: []string{"get", "list", "watch"},
		},
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: render.APIServerName,
		},
		Rules: rules,
	}
}

func (c *apiServer) tigeraAPIServerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: render.APIServerName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.APIServerServiceAccountName,
				Namespace: render.APIServerNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     render.APIServerName,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func (c *apiServer) uiSettingsGroupGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettingsgroup-getter",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"uisettingsgroups",
				},
				Verbs: []string{"get"},
			},
		},
	}
}

func (c *apiServer) kubeControllerManagerUISettingsGroupGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettingsgroup-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-uisettingsgroup-getter",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "system:kube-controller-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}
}

func (c *apiServer) tigeraUserClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// List requests that the Tigera manager needs.
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
				"",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "calico-tiered-policy-passthrough" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"namespaces",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"policyrecommendationscopes",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to view Networks.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		// Additional "list" requests required to view serviceaccount labels.
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		// Access for WAF API to read in coreruleset configmap
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"coreruleset-default"},
			Verbs:         []string{"get"},
		},
		// Access to statistics.
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:calico-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		// Access to policies in all tiers
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
		},
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// Access to hostendpoints from the UI ServiceGraph.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list"},
		},
		// List and view the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		// User can:
		// - read UISettings in the cluster-settings group
		// - read and write UISettings in the user-settings group
		// Default settings group and settings are created in manager.go.
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups"},
			Verbs:         []string{"get"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"get", "list", "watch"},
			ResourceNames: []string{"cluster-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"user-settings"},
		},
		// Allow the user to read applicationlayers to detect if WAF is enabled/disabled.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to read services to view WAF configuration.
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Allow the user to read felixconfigurations to detect if wireguard and/or other features are enabled.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		// Allow the user to only view securityeventwebhooks.
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list"},
		},
	}

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.cfg.ManagementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics.
		// Access to log into Kibana for oidc users.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "recommendations",
			},
			Verbs: []string{"get"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-ui-user",
		},
		Rules: rules,
	}
}

func (c *apiServer) tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// Full access to all network policies
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "calico-tiered-policy-passthrough" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"packetcaptures",
				"policyrecommendationscopes",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{
				"policy.networking.k8s.io",
			},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		// Allow the user to CRUD Networks.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// Additional "list" requests that the Tigera Secure manager needs
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"watch", "list"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		// Additional "list" requests required to view serviceaccount labels.
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		// Access for WAF API to read in coreruleset configmap
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"coreruleset-default"},
			Verbs:         []string{"get"},
		},
		// Access to statistics.
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:calico-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		// Manage globalreport configuration, view report generation status, and list reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports/status"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		// Access to cluster information containing Calico and EE versions from the UI.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// Access to hostendpoints from the UI ServiceGraph.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list"},
		},
		// Manage the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// User can:
		// - read and write UISettings in the cluster-settings group, and rename the group
		// - read and write UISettings in the user-settings group, and rename the group
		// Default settings group and settings are created in manager.go.
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups"},
			Verbs:         []string{"get", "patch", "update"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		// Allow the user to read and write applicationlayers to enable/disable WAF.
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get", "update", "patch", "create", "delete"},
		},
		// Allow the user to read deployments to view WAF configuration.
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		// Allow the user to read felixconfigurations to detect if wireguard and/or other features are enabled.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		// Allow the user to perform CRUD operations on securityeventwebhooks.
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list", "update", "patch", "create", "delete"},
		},
		// Allow the user to create secrets.
		{
			APIGroups: []string{""},
			Resources: []string{
				"secrets",
			},
			Verbs: []string{"create"},
		},
		// Allow the user to patch webhooks-secret secret.
		{
			APIGroups: []string{""},
			Resources: []string{
				"secrets",
			},
			ResourceNames: []string{
				"webhooks-secret",
			},
			Verbs: []string{"patch"},
		},
	}

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.cfg.ManagementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics.
		// Elasticsearch superuser access once logged into Kibana.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "elasticsearch_superuser", "recommendations",
			},
			Verbs: []string{"get"},
		})
	}

	// In v3 CRD / webhooks mode there is no aggregated apiserver, and the
	// calico-uisettings-passthrough ClusterRole that normally grants the broad
	// uisettings permission isn't deployed. Grant write verbs here so the
	// calico-webhooks UISettings handler (which narrows access via a SAR on
	// uisettingsgroups/data) gets invoked instead of being short-circuited by
	// kube-apiserver RBAC.
	if !c.cfg.RequiresAggregationServer {
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettings"},
			Verbs:     []string{"create", "update", "delete", "patch"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-network-admin",
		},
		Rules: rules,
	}
}

func (c *apiServer) uiSettingsPassthruClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettings-passthrough",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettings"},
				Verbs:     []string{"*"},
			},
		},
	}
}

func (c *apiServer) uiSettingsPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-uisettings-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-uisettings-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func (c *apiServer) auditPolicyConfigMap() *corev1.ConfigMap {
	const defaultAuditPolicy = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  omitStages:
  - RequestReceived
  verbs:
  - create
  - patch
  - update
  - delete
  resources:
  - group: projectcalico.org
    resources:
    - globalnetworkpolicies
    - networkpolicies
    - stagedglobalnetworkpolicies
    - stagednetworkpolicies
    - stagedkubernetesnetworkpolicies
    - globalnetworksets
    - networksets
    - tiers
    - hostendpoints`

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			// This object is for Enterprise only, so pass it explicitly.
			Namespace: render.APIServerNamespace,
			Name:      auditPolicyVolumeName,
		},
		Data: map[string]string{
			"config": defaultAuditPolicy,
		},
	}
}

func (c *apiServer) multiTenantManagedClusterAccessClusterRoles() []client.Object {
	var objects []client.Object
	objects = append(objects, &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: render.MultiTenantManagedClustersAccessClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs: []string{
					// The Authentication Proxy in Voltron checks if Enterprise Components (using impersonation headers for
					// the service in the canonical namespace) can get a managed clusters before sending the request down the tunnel.
					// This ClusterRole will be assigned to each component using a RoleBinding in the canonical or tenant namespace.
					"get",
				},
			},
		},
	})

	return objects
}

func (c *apiServer) managedClusterWatchClusterRole() client.Object {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: render.ManagedClustersWatchClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs: []string{
					"get", "list", "watch",
				},
			},
		},
	}
}

func (c *apiServer) deprecatedResources() []client.Object {
	return []client.Object{
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-secrets-access"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-secrets-access"},
		},

		// delegateAuthClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver-delegate-auth"},
		},

		// authClusterRole
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-auth-access"},
		},

		// authClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-extension-apiserver-auth-access"},
		},
		// authReaderRoleBinding - need clean up in diff namespace kube-system
		&rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-auth-reader",
				Namespace: "kube-system",
			},
		},
		// webhookReaderClusterRole
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-webhook-reader"},
		},

		// webhookReaderClusterRoleBinding
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver-webhook-reader"},
		},

		// calico-apiserver CR and CRB
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-apiserver"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettingsgroup-getter"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettingsgroup-getter"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-tiered-policy-passthrough"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-tiered-policy-passthrough"},
		},

		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettings-passthrough"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-uisettings-passthrough"},
		},

		// Clean up legacy secrets in the tigera-operator namespace
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-api-cert", Namespace: common.OperatorNamespace()},
		},
	}
}
