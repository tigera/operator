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

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"
	"k8s.io/apimachinery/pkg/api/resource"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/policy/v1beta1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Tigera Secure Fluentd rendering tests", func() {
	var cfg *render.FluentdConfiguration
	var cli client.Client

	expectedFluentdPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/fluentd_unmanaged.json")
	expectedFluentdPolicyForUnmanagedOpenshift := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/fluentd_unmanaged_ocp.json")
	expectedFluentdPolicyForManaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/fluentd_managed.json")

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		metricsSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.FluentdPrometheusTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		eksSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.EKSLogForwarderTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		cfg = &render.FluentdConfiguration{
			LogCollector:  &operatorv1.LogCollector{},
			ClusterDomain: dns.DefaultClusterDomain,
			OSType:        rmeta.OSTypeLinux,
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
			},
			FluentdKeyPair:         metricsSecret,
			EKSLogForwarderKeyPair: eksSecret,
			TrustedBundle:          certificateManager.CreateTrustedBundle(),
			UsePSP:                 true,
		}
	})

	It("should render properly when PSP is not supported by the cluster", func() {
		cfg.UsePSP = false
		component := render.Fluentd(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// Should not contain any PodSecurityPolicies
		for _, r := range resources {
			Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("PodSecurityPolicy"))
		}
	})

	It("should render security context constrains properly when provider is openshift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		component := render.Fluentd(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		// tigera-fluentd clusterRole should have openshift securitycontextconstraints PolicyRule
		fluentdRole := rtest.GetResource(resources, "tigera-fluentd", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(fluentdRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"privileged"},
		}))
	})

	It("should render with a default configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.FluentdPolicyName, ns: render.LogCollectorNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.FluentdMetricsService, ns: render.LogCollectorNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.PacketCaptureAPIRole, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: render.PacketCaptureAPIRoleBinding, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		// Check the namespace.
		ns := rtest.GetResource(resources, "tigera-fluentd", "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(ns.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("privileged"))
		Expect(ns.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Volumes[0].VolumeSource.HostPath.Path).To(Equal("/var/log/calico"))
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		Expect(envs).Should(ContainElements(
			corev1.EnvVar{Name: "LINSEED_ENABLED", Value: "true"},
			corev1.EnvVar{Name: "LINSEED_ENDPOINT", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			corev1.EnvVar{Name: "LINSEED_CA_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			corev1.EnvVar{Name: "TLS_KEY_PATH", Value: "/tigera-fluentd-prometheus-tls/tls.key"},
			corev1.EnvVar{Name: "TLS_CRT_PATH", Value: "/tigera-fluentd-prometheus-tls/tls.crt"},
			corev1.EnvVar{Name: "FLUENT_UID", Value: "0"},
			corev1.EnvVar{Name: "FLOW_LOG_FILE", Value: "/var/log/calico/flowlogs/flows.log"},
			corev1.EnvVar{Name: "DNS_LOG_FILE", Value: "/var/log/calico/dnslogs/dns.log"},
			corev1.EnvVar{Name: "FLUENTD_ES_SECURE", Value: "true"},
			corev1.EnvVar{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		))

		Expect(envs).ShouldNot(ContainElements(
			corev1.EnvVar{Name: "ELASTIC_INDEX_SUFFIX", Value: "clusterTestName"},
			corev1.EnvVar{Name: "ELASTIC_SCHEME", Value: "https"},
			corev1.EnvVar{Name: "ELASTIC_HOST", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc"},
			corev1.EnvVar{Name: "ELASTIC_PORT", Value: "9200"},
			corev1.EnvVar{Name: "ELASTIC_USER", ValueFrom: secret.GetEnvVarSource("tigera-eks-log-forwarder-elasticsearch-access", "username", false)},
			corev1.EnvVar{Name: "ELASTIC_PASSWORD", ValueFrom: secret.GetEnvVarSource("tigera-eks-log-forwarder-elasticsearch-access", "password", false)},
			corev1.EnvVar{Name: "ELASTIC_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		))

		container := ds.Spec.Template.Spec.Containers[0]

		Expect(container.ReadinessProbe.Exec.Command).To(ConsistOf([]string{"sh", "-c", "/bin/readiness.sh"}))
		Expect(container.ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.LivenessProbe.Exec.Command).To(ConsistOf([]string{"sh", "-c", "/bin/liveness.sh"}))
		Expect(container.LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.LivenessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.StartupProbe.Exec.Command).To(ConsistOf([]string{"sh", "-c", "/bin/liveness.sh"}))
		Expect(container.StartupProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.StartupProbe.PeriodSeconds).To(BeEquivalentTo(60))
		Expect(container.StartupProbe.FailureThreshold).To(BeEquivalentTo(10))

		Expect(*container.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*container.SecurityContext.Privileged).To(BeFalse())
		Expect(*container.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*container.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*container.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(container.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(container.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		podExecRole := rtest.GetResource(resources, render.PacketCaptureAPIRole, render.LogCollectorNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(podExecRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
		}))
		podExecRoleBinding := rtest.GetResource(resources, render.PacketCaptureAPIRoleBinding, render.LogCollectorNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(podExecRoleBinding.RoleRef.Name).To(Equal(render.PacketCaptureAPIRole))
		Expect(podExecRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.PacketCaptureServiceAccountName,
				Namespace: render.PacketCaptureNamespace,
			},
		}))

		// The metrics service should have the correct configuration.
		ms := rtest.GetResource(resources, render.FluentdMetricsService, render.LogCollectorNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless to prevent kube-proxy from rendering too many iptables rules")
	})

	It("should render fluentd Daemonset with resources requests/limits", func() {

		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		metricsSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.FluentdPrometheusTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		cfg.FluentdKeyPair = metricsSecret

		fluentdResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}

		logCollectorcfg := operatorv1.LogCollector{
			Spec: operatorv1.LogCollectorSpec{
				FluentdDaemonSet: &operatorv1.FluentdDaemonSet{
					Spec: &operatorv1.FluentdDaemonSetSpec{
						Template: &operatorv1.FluentdDaemonSetPodTemplateSpec{
							Spec: &operatorv1.FluentdDaemonSetPodSpec{
								InitContainers: []operatorv1.FluentdDaemonSetInitContainer{{
									Name:      "tigera-fluentd-prometheus-tls-key-cert-provisioner",
									Resources: &fluentdResources,
								}},
								Containers: []operatorv1.FluentdDaemonSetContainer{{
									Name:      "fluentd",
									Resources: &fluentdResources,
								}},
							},
						},
					},
				},
			},
		}

		cfg.LogCollector = &logCollectorcfg
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))

		container := test.GetContainer(ds.Spec.Template.Spec.Containers, "fluentd")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(fluentdResources))

		Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		initContainer := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "tigera-fluentd-prometheus-tls-key-cert-provisioner")
		Expect(initContainer).NotTo(BeNil())
		Expect(initContainer.Resources).To(Equal(fluentdResources))
	})

	It("should render with a configuration for a managed cluster", func() {
		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.LogCollectorNamespace}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.FluentdPolicyName, Namespace: render.LogCollectorNamespace}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.FluentdMetricsService, Namespace: render.LogCollectorNamespace}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}},
			&v1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.FluentdNodeName, Namespace: render.LogCollectorNamespace}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureAPIRole, Namespace: render.LogCollectorNamespace}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureAPIRoleBinding, Namespace: render.LogCollectorNamespace}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: render.FluentdNodeName, Namespace: render.LogCollectorNamespace}},
		}

		// Should render the correct resources.
		managedCfg := &render.FluentdConfiguration{
			LogCollector:   cfg.LogCollector,
			ClusterDomain:  cfg.ClusterDomain,
			OSType:         cfg.OSType,
			Installation:   cfg.Installation,
			FluentdKeyPair: cfg.FluentdKeyPair,
			TrustedBundle:  cfg.TrustedBundle,
			UsePSP:         true,
			ManagedCluster: true,
		}
		component := render.Fluentd(managedCfg)
		createResources, deleteResources := component.Objects()
		rtest.ExpectResources(createResources, expectedResources)
		Expect(deleteResources).To(BeEmpty())

		// Check the namespace.
		ns := rtest.GetResource(createResources, "tigera-fluentd", "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(ns.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("privileged"))
		Expect(ns.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

		ds := rtest.GetResource(createResources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Volumes[0].VolumeSource.HostPath.Path).To(Equal("/var/log/calico"))
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		Expect(envs).Should(ContainElements(
			corev1.EnvVar{Name: "LINSEED_ENABLED", Value: "true"},
			corev1.EnvVar{Name: "LINSEED_ENDPOINT", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			corev1.EnvVar{Name: "LINSEED_CA_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			corev1.EnvVar{Name: "TLS_KEY_PATH", Value: "/tigera-fluentd-prometheus-tls/tls.key"},
			corev1.EnvVar{Name: "TLS_CRT_PATH", Value: "/tigera-fluentd-prometheus-tls/tls.crt"},
			corev1.EnvVar{Name: "FLUENT_UID", Value: "0"},
			corev1.EnvVar{Name: "FLOW_LOG_FILE", Value: "/var/log/calico/flowlogs/flows.log"},
			corev1.EnvVar{Name: "DNS_LOG_FILE", Value: "/var/log/calico/dnslogs/dns.log"},
			corev1.EnvVar{Name: "FLUENTD_ES_SECURE", Value: "true"},
			corev1.EnvVar{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/tigera.io/linseed/token"},
		))

		container := ds.Spec.Template.Spec.Containers[0]

		Expect(container.ReadinessProbe.Exec.Command).To(ConsistOf([]string{"sh", "-c", "/bin/readiness.sh"}))
		Expect(container.ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.LivenessProbe.Exec.Command).To(ConsistOf([]string{"sh", "-c", "/bin/liveness.sh"}))
		Expect(container.LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.LivenessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.StartupProbe.Exec.Command).To(ConsistOf([]string{"sh", "-c", "/bin/liveness.sh"}))
		Expect(container.StartupProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.StartupProbe.PeriodSeconds).To(BeEquivalentTo(60))
		Expect(container.StartupProbe.FailureThreshold).To(BeEquivalentTo(10))

		Expect(*container.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*container.SecurityContext.Privileged).To(BeFalse())
		Expect(*container.SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*container.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*container.SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(container.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(container.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		linseedRoleBinding := rtest.GetResource(createResources, "tigera-linseed", render.LogCollectorNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(linseedRoleBinding.RoleRef.Name).To(Equal("tigera-linseed-secrets"))
		Expect(linseedRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.LinseedServiceName,
				Namespace: render.ElasticsearchNamespace,
			},
		}))

		podExecRole := rtest.GetResource(createResources, render.PacketCaptureAPIRole, render.LogCollectorNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(podExecRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
		}))
		podExecRoleBinding := rtest.GetResource(createResources, render.PacketCaptureAPIRoleBinding, render.LogCollectorNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(podExecRoleBinding.RoleRef.Name).To(Equal(render.PacketCaptureAPIRole))
		Expect(podExecRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.PacketCaptureServiceAccountName,
				Namespace: render.PacketCaptureNamespace,
			},
		}))

		// The metrics service should have the correct configuration.
		ms := rtest.GetResource(createResources, render.FluentdMetricsService, render.LogCollectorNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(ms.Spec.ClusterIP).To(Equal("None"), "metrics service should be headless to prevent kube-proxy from rendering too many iptables rules")
	})

	It("should render with a resource quota for provider GKE", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

		// Should render the correct resources.
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()

		// Should render resource quota
		Expect(rtest.GetResource(resources, "tigera-critical-pods", "tigera-fluentd", "", "v1", "ResourceQuota")).ToNot(BeNil())
	})

	It("should render for Windows nodes", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.FluentdPolicyName, ns: render.LogCollectorNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.FluentdMetricsServiceWindows, ns: render.LogCollectorNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-fluentd-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd-windows", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "fluentd-node-windows", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.PacketCaptureAPIRole, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: render.PacketCaptureAPIRoleBinding, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "fluentd-node-windows", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		cfg.OSType = rmeta.OSTypeWindows
		// Should render the correct resources.
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := rtest.GetResource(resources, "fluentd-node-windows", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Volumes[0].VolumeSource.HostPath.Path).To(Equal("c:/TigeraCalico"))

		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []corev1.EnvVar{
			{Name: "LINSEED_ENABLED", Value: "true"},
			{Name: "LINSEED_ENDPOINT", Value: "https://tigera-linseed.tigera-elasticsearch.svc.cluster.local"},
			{Name: "LINSEED_CA_PATH", Value: certificatemanagement.TrustedCertBundleMountPathWindows},
			{Name: "TLS_KEY_PATH", Value: "c:/tigera-fluentd-prometheus-tls/tls.key"},
			{Name: "TLS_CRT_PATH", Value: "c:/tigera-fluentd-prometheus-tls/tls.crt"},
			{Name: "FLUENT_UID", Value: "0"},
			{Name: "FLOW_LOG_FILE", Value: "c:/var/log/calico/flowlogs/flows.log"},
			{Name: "DNS_LOG_FILE", Value: "c:/var/log/calico/dnslogs/dns.log"},
			{Name: "FLUENTD_ES_SECURE", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
			{Name: "LINSEED_TOKEN", Value: "c:/var/run/secrets/kubernetes.io/serviceaccount/token"},
		}
		for _, expected := range expectedEnvs {
			Expect(envs).To(ContainElement(expected))
		}

		ds = rtest.GetResource(resources, "fluentd-node-windows", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		envs = ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs = []corev1.EnvVar{
			{Name: "FLUENT_UID", Value: "0"},
			{Name: "FLOW_LOG_FILE", Value: "c:/var/log/calico/flowlogs/flows.log"},
			{Name: "DNS_LOG_FILE", Value: "c:/var/log/calico/dnslogs/dns.log"},
			{Name: "FLUENTD_ES_SECURE", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
		}
		for _, expected := range expectedEnvs {
			Expect(envs).To(ContainElement(expected))
		}

		container := ds.Spec.Template.Spec.Containers[0]

		Expect(container.ReadinessProbe.Exec.Command).To(ConsistOf([]string{`c:\ruby\msys64\usr\bin\bash.exe`, `-lc`, `/c/bin/readiness.sh`}))
		Expect(container.ReadinessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.LivenessProbe.Exec.Command).To(ConsistOf([]string{`c:\ruby\msys64\usr\bin\bash.exe`, `-lc`, `/c/bin/liveness.sh`}))
		Expect(container.LivenessProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.LivenessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(container.StartupProbe.Exec.Command).To(ConsistOf([]string{`c:\ruby\msys64\usr\bin\bash.exe`, `-lc`, `/c/bin/liveness.sh`}))
		Expect(container.StartupProbe.TimeoutSeconds).To(BeEquivalentTo(10))
		Expect(container.StartupProbe.PeriodSeconds).To(BeEquivalentTo(60))
		Expect(container.StartupProbe.FailureThreshold).To(BeEquivalentTo(10))

		Expect(container.SecurityContext).To(BeNil())
	})

	It("should render with S3 configuration", func() {
		cfg.S3Credential = &render.S3Credential{
			KeyId:     []byte("IdForTheKey"),
			KeySecret: []byte("SecretForTheKey"),
		}
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			S3: &operatorv1.S3StoreSpec{
				Region:     "anyplace",
				BucketName: "thebucket",
				BucketPath: "bucketpath",
			},
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.FluentdPolicyName, ns: render.LogCollectorNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.FluentdMetricsService, ns: render.LogCollectorNamespace, group: "", version: "v1", kind: "Service"},
			{name: "log-collector-s3-credentials", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.PacketCaptureAPIRole, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: render.PacketCaptureAPIRoleBinding, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/s3-credentials"))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"S3_STORAGE", "true", "", ""},
			{"S3_BUCKET_NAME", "thebucket", "", ""},
			{"AWS_REGION", "anyplace", "", ""},
			{"S3_BUCKET_PATH", "bucketpath", "", ""},
			{"S3_FLUSH_INTERVAL", "5s", "", ""},
			{"AWS_KEY_ID", "", "log-collector-s3-credentials", "key-id"},
			{"AWS_SECRET_KEY", "", "log-collector-s3-credentials", "key-secret"},
		}
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						},
					},
				}))
			}
		}
	})
	It("should render with Syslog configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.FluentdPolicyName, ns: render.LogCollectorNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.FluentdMetricsService, ns: render.LogCollectorNamespace, group: "", version: "v1", kind: "Service"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.PacketCaptureAPIRole, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: render.PacketCaptureAPIRoleBinding, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		var ps int32 = 180
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				Endpoint:   "tcp://1.2.3.4:80",
				PacketSize: &ps,
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogDNS,
					operatorv1.SyslogLogFlows,
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(3))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"SYSLOG_HOST", "1.2.3.4", "", ""},
			{"SYSLOG_PORT", "80", "", ""},
			{"SYSLOG_PROTOCOL", "tcp", "", ""},
			{"SYSLOG_FLUSH_INTERVAL", "5s", "", ""},
			{"SYSLOG_PACKET_SIZE", "180", "", ""},
			{"SYSLOG_DNS_LOG", "true", "", ""},
			{"SYSLOG_FLOW_LOG", "true", "", ""},
			{"SYSLOG_IDS_EVENT_LOG", "true", "", ""},
		}
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						},
					},
				}))
			}
		}
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "SYSLOG_HOSTNAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "spec.nodeName",
				},
			},
		}))
	})
	It("should render with Syslog configuration with TLS and user's corporate CA", func() {
		cfg.UseSyslogCertificate = true
		var ps int32 = 180
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				Endpoint:   "tcp://1.2.3.4:80",
				Encryption: operatorv1.EncryptionTLS,
				PacketSize: &ps,
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogDNS,
					operatorv1.SyslogLogFlows,
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(3))

		var volnames []string
		for _, vol := range ds.Spec.Template.Spec.Volumes {
			volnames = append(volnames, vol.Name)
		}
		Expect(volnames).To(ContainElement("tigera-ca-bundle"))

		envs := ds.Spec.Template.Spec.Containers[0].Env

		Expect(envs).To(ContainElements([]corev1.EnvVar{
			{Name: "SYSLOG_HOST", Value: "1.2.3.4", ValueFrom: nil},
			{Name: "SYSLOG_PORT", Value: "80", ValueFrom: nil},
			{Name: "SYSLOG_PROTOCOL", Value: "tcp", ValueFrom: nil},
			{Name: "SYSLOG_FLUSH_INTERVAL", Value: "5s", ValueFrom: nil},
			{Name: "SYSLOG_PACKET_SIZE", Value: "180", ValueFrom: nil},
			{Name: "SYSLOG_DNS_LOG", Value: "true", ValueFrom: nil},
			{Name: "SYSLOG_FLOW_LOG", Value: "true", ValueFrom: nil},
			{Name: "SYSLOG_IDS_EVENT_LOG", Value: "true", ValueFrom: nil},
			{Name: "SYSLOG_TLS", Value: "true", ValueFrom: nil},
			{Name: "SYSLOG_VERIFY_MODE", Value: "1", ValueFrom: nil},
			{Name: "SYSLOG_CA_FILE", Value: cfg.TrustedBundle.MountPath(), ValueFrom: nil},
		}))
	})

	It("should render with Syslog configuration with TLS and Internet CA", func() {
		cfg.UseSyslogCertificate = false
		var ps int32 = 180
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				Endpoint:   "tcp://1.2.3.4:80",
				Encryption: operatorv1.EncryptionTLS,
				PacketSize: &ps,
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogDNS,
					operatorv1.SyslogLogFlows,
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(3))

		envs := ds.Spec.Template.Spec.Containers[0].Env

		Expect(envs).To(ContainElements([]corev1.EnvVar{
			{Name: "SYSLOG_HOST", Value: "1.2.3.4", ValueFrom: nil},
			{Name: "SYSLOG_PORT", Value: "80", ValueFrom: nil},
			{Name: "SYSLOG_PROTOCOL", Value: "tcp", ValueFrom: nil},
			{Name: "SYSLOG_FLUSH_INTERVAL", Value: "5s", ValueFrom: nil},
			{Name: "SYSLOG_PACKET_SIZE", Value: "180", ValueFrom: nil},
			{Name: "SYSLOG_DNS_LOG", Value: "true", ValueFrom: nil},
			{Name: "SYSLOG_FLOW_LOG", Value: "true", ValueFrom: nil},
			{Name: "SYSLOG_IDS_EVENT_LOG", Value: "true", ValueFrom: nil},
			{Name: "SYSLOG_TLS", Value: "true", ValueFrom: nil},
			{Name: "SYSLOG_VERIFY_MODE", Value: "1", ValueFrom: nil},
			{Name: "SYSLOG_CA_FILE", Value: render.SysLogPublicCAPath, ValueFrom: nil},
		}))
	})

	It("should render with splunk configuration with ca", func() {
		cfg.SplkCredential = &render.SplunkCredential{
			Token:       []byte("TokenForHEC"),
			Certificate: []byte("Certificates"),
		}
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Splunk: &operatorv1.SplunkStoreSpec{
				Endpoint: "https://1.2.3.4:8088",
			},
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.FluentdPolicyName, ns: render.LogCollectorNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.FluentdMetricsService, ns: render.LogCollectorNamespace, group: "", version: "v1", kind: "Service"},
			{name: "logcollector-splunk-credentials", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "logcollector-splunk-public-certificate", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.PacketCaptureAPIRole, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: render.PacketCaptureAPIRoleBinding, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(4))

		var volnames []string
		for _, vol := range ds.Spec.Template.Spec.Volumes {
			volnames = append(volnames, vol.Name)
		}
		Expect(volnames).To(ContainElement("splunk-certificates"))

		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"SPLUNK_FLOW_LOG", "true", "", ""},
			{"SPLUNK_AUDIT_LOG", "true", "", ""},
			{"SPLUNK_DNS_LOG", "true", "", ""},
			{"SPLUNK_HEC_HOST", "1.2.3.4", "", ""},
			{"SPLUNK_HEC_PORT", "8088", "", ""},
			{"SPLUNK_PROTOCOL", "https", "", ""},
			{"SPLUNK_FLUSH_INTERVAL", "5s", "", ""},
			{"SPLUNK_HEC_TOKEN", "", "logcollector-splunk-credentials", "token"},
			{"SPLUNK_CA_FILE", "/etc/pki/splunk/ca.pem", "", ""},
		}
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						},
					},
				}))
			}
		}
	})

	It("should render with splunk configuration without ca", func() {
		cfg.SplkCredential = &render.SplunkCredential{
			Token: []byte("TokenForHEC"),
		}
		cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Splunk: &operatorv1.SplunkStoreSpec{
				Endpoint: "https://1.2.3.4:8088",
			},
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.FluentdPolicyName, ns: render.LogCollectorNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.FluentdMetricsService, ns: render.LogCollectorNamespace, group: "", version: "v1", kind: "Service"},
			{name: "logcollector-splunk-credentials", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.PacketCaptureAPIRole, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: render.PacketCaptureAPIRoleBinding, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"SPLUNK_FLOW_LOG", "true", "", ""},
			{"SPLUNK_AUDIT_LOG", "true", "", ""},
			{"SPLUNK_DNS_LOG", "true", "", ""},
			{"SPLUNK_HEC_HOST", "1.2.3.4", "", ""},
			{"SPLUNK_HEC_PORT", "8088", "", ""},
			{"SPLUNK_PROTOCOL", "https", "", ""},
			{"SPLUNK_FLUSH_INTERVAL", "5s", "", ""},
			{"SPLUNK_HEC_TOKEN", "", "logcollector-splunk-credentials", "token"},
		}

		Expect(envs).NotTo(ContainElement(corev1.EnvVar{Name: "SPLUNK_CA_FILE", Value: "/etc/ssl/splunk/ca.pem"}))
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						},
					},
				}))
			}
		}
	})

	It("should render with filter", func() {
		cfg.Filters = &render.FluentdFilters{
			Flow: "flow-filter",
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: render.FluentdPolicyName, ns: render.LogCollectorNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: render.FluentdMetricsService, ns: render.LogCollectorNamespace, group: "", version: "v1", kind: "Service"},
			{name: "fluentd-filters", ns: "tigera-fluentd", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.PacketCaptureAPIRole, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: render.PacketCaptureAPIRoleBinding, ns: render.LogCollectorNamespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/fluentd-filters"))
		envs := ds.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "FLUENTD_FLOW_FILTERS", Value: "true"}))
		Expect(envs).ToNot(ContainElement(corev1.EnvVar{Name: "FLUENTD_DNS_FILTERS", Value: "true"}))
	})

	It("should render with EKS Cloudwatch Log", func() {
		expectedResources := getExpectedResourcesForEKS()
		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		cfg.ESClusterConfig = relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider:      operatorv1.ProviderEKS,
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		rtest.ExpectResources(resources, expectedResources)
		deploy := rtest.GetResource(resources, "eks-log-forwarder", "tigera-fluentd", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/eks-cloudwatch-log-credentials"))
		Expect(deploy.Spec.Template.Spec.Tolerations).To(ContainElement(t))
		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))

		envs := deploy.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "K8S_PLATFORM", Value: "eks"}))
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "AWS_REGION", Value: cfg.EKSConfig.AwsRegion}))

		Expect(*deploy.Spec.Template.Spec.InitContainers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.InitContainers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.InitContainers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*deploy.Spec.Template.Spec.InitContainers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.InitContainers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*deploy.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(deploy.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		expectedEnvVars := []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "info", ValueFrom: nil},
			{Name: "FLUENT_UID", Value: "0", ValueFrom: nil},
			{Name: "MANAGED_K8S", Value: "true", ValueFrom: nil},
			{Name: "K8S_PLATFORM", Value: "eks", ValueFrom: nil},
			{Name: "FLUENTD_ES_SECURE", Value: "true"},
			{Name: "EKS_CLOUDWATCH_LOG_GROUP", Value: "dummy-eks-cluster-cloudwatch-log-group"},
			{Name: "EKS_CLOUDWATCH_LOG_STREAM_PREFIX", Value: ""},
			{Name: "EKS_CLOUDWATCH_LOG_FETCH_INTERVAL", Value: "900"},
			{Name: "AWS_REGION", Value: "us-west-1", ValueFrom: nil},
			{Name: "AWS_ACCESS_KEY_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-eks-log-forwarder-secret",
						},
						Key: "aws-id",
					}},
			},
			{Name: "AWS_SECRET_ACCESS_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-eks-log-forwarder-secret",
						},
						Key:      "aws-key",
						Optional: nil,
					}},
			},
			{Name: "LINSEED_ENABLED", Value: "true"},
			{Name: "LINSEED_ENDPOINT", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			{Name: "LINSEED_CA_PATH", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "TLS_CRT_PATH", Value: "/tigera-eks-log-forwarder-tls/tls.crt"},
			{Name: "TLS_KEY_PATH", Value: "/tigera-eks-log-forwarder-tls/tls.key"},
			{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		}

		Expect(envs).To(Equal(expectedEnvVars))
	})

	It("should render with EKS Cloudwatch Log with resources", func() {

		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		cfg.ESClusterConfig = relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderEKS,
		}

		eksResources := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":     resource.MustParse("2"),
				"memory":  resource.MustParse("300Mi"),
				"storage": resource.MustParse("20Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":     resource.MustParse("1"),
				"memory":  resource.MustParse("150Mi"),
				"storage": resource.MustParse("10Gi"),
			},
		}

		logCollectorcfg := operatorv1.LogCollector{
			Spec: operatorv1.LogCollectorSpec{
				EKSLogForwarderDeployment: &operatorv1.EKSLogForwarderDeployment{
					Spec: &operatorv1.EKSLogForwarderDeploymentSpec{
						Template: &operatorv1.EKSLogForwarderDeploymentPodTemplateSpec{
							Spec: &operatorv1.EKSLogForwarderDeploymentPodSpec{
								Containers: []operatorv1.EKSLogForwarderDeploymentContainer{{
									Name:      "eks-log-forwarder",
									Resources: &eksResources,
								}},
							},
						},
					},
				},
			},
		}

		cfg.LogCollector = &logCollectorcfg
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		deploy := rtest.GetResource(resources, "eks-log-forwarder", "tigera-fluentd", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
		container := test.GetContainer(deploy.Spec.Template.Spec.Containers, "eks-log-forwarder")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(eksResources))

		initContainer := test.GetContainer(deploy.Spec.Template.Spec.InitContainers, "eks-log-forwarder-startup")
		Expect(initContainer).NotTo(BeNil())
		Expect(initContainer.Resources).To(Equal(corev1.ResourceRequirements{}))

	})

	It("should render with EKS Cloudwatch Log with multi tenant envvars", func() {

		expectedResources := getExpectedResourcesForEKS()
		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		cfg.ESClusterConfig = relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider:      operatorv1.ProviderEKS,
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		cfg.ExternalElastic = true

		// Create the Tenant object.
		tenant := &operatorv1.Tenant{}
		tenant.Name = "default"
		tenant.Namespace = "tenant-namespace"
		tenant.Spec.ID = "test-tenant-id"
		cfg.Tenant = tenant

		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		rtest.ExpectResources(resources, expectedResources)

		deploy := rtest.GetResource(resources, "eks-log-forwarder", "tigera-fluentd", "apps", "v1", "Deployment").(*appsv1.Deployment)
		envs := deploy.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_ENDPOINT", Value: "https://tigera-linseed.tenant-namespace.svc"}))
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: "test-tenant-id"}))
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"}))
	})

	It("should render with EKS Cloudwatch Log for managed cluster with linseed token volume", func() {

		expectedResources := getExpectedResourcesForEKS()

		expectedResources = append(expectedResources,
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: render.LogCollectorNamespace}})

		cfg.EKSConfig = setupEKSCloudwatchLogConfig()
		cfg.ESClusterConfig = relasticsearch.NewClusterConfig("clusterTestName", 1, 1, 1)
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		cfg.Installation = &operatorv1.InstallationSpec{
			KubernetesProvider:      operatorv1.ProviderEKS,
			ControlPlaneTolerations: []corev1.Toleration{t},
		}
		cfg.ManagedCluster = true
		component := render.Fluentd(cfg)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		rtest.ExpectResources(resources, expectedResources)

		deploy := rtest.GetResource(resources, "eks-log-forwarder", "tigera-fluentd", "apps", "v1", "Deployment").(*appsv1.Deployment)
		envs := deploy.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/tigera.io/linseed/token"}))

		volumeMounts := deploy.Spec.Template.Spec.Containers[0].VolumeMounts
		Expect(volumeMounts).To(ContainElement(corev1.VolumeMount{Name: "linseed-token", MountPath: "/var/run/secrets/tigera.io/linseed/"}))
	})

	Context("allow-tigera rendering", func() {
		policyName := types.NamespacedName{Name: "allow-tigera.allow-fluentd-node", Namespace: "tigera-fluentd"}

		getExpectedPolicy := func(scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if scenario.ManagedCluster {
				return expectedFluentdPolicyForManaged
			} else {
				return testutils.SelectPolicyByProvider(scenario, expectedFluentdPolicyForUnmanaged, expectedFluentdPolicyForUnmanagedOpenshift)
			}
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				if scenario.Openshift {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
				} else {
					cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
				}
				cfg.ManagedCluster = scenario.ManagedCluster

				component := render.Fluentd(cfg)
				resources, _ := component.Objects()

				policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, Openshift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, Openshift: true}),
		)
	})
})

func setupEKSCloudwatchLogConfig() *render.EksCloudwatchLogConfig {
	fetchInterval := int32(900)
	return &render.EksCloudwatchLogConfig{
		AwsId:         []byte("aws-id"),
		AwsKey:        []byte("aws-key"),
		AwsRegion:     "us-west-1",
		GroupName:     "dummy-eks-cluster-cloudwatch-log-group",
		FetchInterval: fetchInterval,
	}
}

func getExpectedResourcesForEKS() []client.Object {
	return []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.FluentdPolicyName, Namespace: render.LogCollectorNamespace},
			TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},

		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.FluentdMetricsService, Namespace: render.LogCollectorNamespace}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder", Namespace: "tigera-fluentd"}},
		&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "fluentd-node", Namespace: "tigera-fluentd"}},
		&policyv1beta1.PodSecurityPolicy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-fluentd"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "eks-log-forwarder", Namespace: render.LogCollectorNamespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-eks-log-forwarder-secret", Namespace: render.LogCollectorNamespace}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureAPIRole, Namespace: render.LogCollectorNamespace}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureAPIRoleBinding, Namespace: render.LogCollectorNamespace}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "fluentd-node", Namespace: render.LogCollectorNamespace}},
	}
}
