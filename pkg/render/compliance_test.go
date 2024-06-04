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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"
)

var _ = Describe("compliance rendering tests", func() {
	ns := "tigera-compliance"
	rbac := "rbac.authorization.k8s.io"
	clusterDomain := dns.DefaultClusterDomain
	var cfg *render.ComplianceConfiguration
	var cli client.Client

	expectedCompliancePolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/compliance_unmanaged.json")
	expectedCompliancePolicyForManaged := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/compliance_managed.json")
	expectedCompliancePolicyForUnmanagedOpenshift := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/compliance_unmanaged_ocp.json")
	expectedCompliancePolicyForManagedOpenshift := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/compliance_managed_ocp.json")
	expectedComplianceServerPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/compliance-server.json")
	expectedComplianceServerPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/compliance-server_ocp.json")

	complianceResources := corev1.ResourceRequirements{
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

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		bundle := certificateManager.CreateTrustedBundle()
		serverKP, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceServerCertSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		controllerKP, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceControllerSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		benchmarkerKP, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceBenchmarkerSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		reporterKP, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceReporterSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		snapshotterKP, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceSnapshotterSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		cfg = &render.ComplianceConfiguration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			},
			ServerKeyPair:      serverKP,
			ControllerKeyPair:  controllerKP,
			ReporterKeyPair:    reporterKP,
			BenchmarkerKeyPair: benchmarkerKP,
			SnapshotterKeyPair: snapshotterKP,
			OpenShift:          false,
			ClusterDomain:      clusterDomain,
			TrustedBundle:      bundle,
			Namespace:          render.ComplianceNamespace,
		}
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.OpenShift = true
		component, err := render.Compliance(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		clusterRole := rtest.GetResource(resources, "tigera-compliance-benchmarker", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"hostaccess"},
		}))

		role := rtest.GetResource(resources, "tigera-compliance-controller", "tigera-compliance", "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))

		clusterRole = rtest.GetResource(resources, "tigera-compliance-reporter", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"hostaccess"},
		}))

		clusterRole = rtest.GetResource(resources, "tigera-compliance-server", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))

		clusterRole = rtest.GetResource(resources, "tigera-compliance-snapshotter", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	It("should render the env variable for queryserver when FIPS is enabled", func() {
		fipsEnabled := operatorv1.FIPSModeEnabled
		cfg.Installation.FIPSMode = &fipsEnabled
		component, err := render.Compliance(cfg)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "FIPS_MODE_ENABLED", Value: "true"}))
	})

	It("should render resource requests and limits for compliance components", func() {
		cfg.Compliance = &operatorv1.Compliance{
			Spec: operatorv1.ComplianceSpec{
				ComplianceServerDeployment: &operatorv1.ComplianceServerDeployment{
					Spec: &operatorv1.ComplianceServerDeploymentSpec{
						Template: &operatorv1.ComplianceServerDeploymentPodTemplateSpec{
							Spec: &operatorv1.ComplianceServerDeploymentPodSpec{
								Containers: []operatorv1.ComplianceServerDeploymentContainer{{
									Name:      "compliance-server",
									Resources: &complianceResources,
								}},
							},
						},
					},
				},
				ComplianceControllerDeployment: &operatorv1.ComplianceControllerDeployment{
					Spec: &operatorv1.ComplianceControllerDeploymentSpec{
						Template: &operatorv1.ComplianceControllerDeploymentPodTemplateSpec{
							Spec: &operatorv1.ComplianceControllerDeploymentPodSpec{
								Containers: []operatorv1.ComplianceControllerDeploymentContainer{{
									Name:      "compliance-controller",
									Resources: &complianceResources,
								}},
							},
						},
					},
				},
				ComplianceSnapshotterDeployment: &operatorv1.ComplianceSnapshotterDeployment{
					Spec: &operatorv1.ComplianceSnapshotterDeploymentSpec{
						Template: &operatorv1.ComplianceSnapshotterDeploymentPodTemplateSpec{
							Spec: &operatorv1.ComplianceSnapshotterDeploymentPodSpec{
								Containers: []operatorv1.ComplianceSnapshotterDeploymentContainer{{
									Name:      "compliance-snapshotter",
									Resources: &complianceResources,
								}},
							},
						},
					},
				},

				ComplianceBenchmarkerDaemonSet: &operatorv1.ComplianceBenchmarkerDaemonSet{
					Spec: &operatorv1.ComplianceBenchmarkerDaemonSetSpec{
						Template: &operatorv1.ComplianceBenchmarkerDaemonSetPodTemplateSpec{
							Spec: &operatorv1.ComplianceBenchmarkerDaemonSetPodSpec{
								Containers: []operatorv1.ComplianceBenchmarkerDaemonSetContainer{{
									Name:      "compliance-benchmarker",
									Resources: &complianceResources,
								}},
							},
						},
					},
				},
			},
		}

		component, err := render.Compliance(cfg)
		Expect(err).ShouldNot(HaveOccurred())
		resources, _ := component.Objects()
		d, ok := rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container := test.GetContainer(d.Spec.Template.Spec.Containers, "compliance-server")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(complianceResources))

		d, ok = rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container = test.GetContainer(d.Spec.Template.Spec.Containers, "compliance-controller")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(complianceResources))

		d, ok = rtest.GetResource(resources, "compliance-snapshotter", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container = test.GetContainer(d.Spec.Template.Spec.Containers, "compliance-snapshotter")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(complianceResources))

		ds, ok := rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ok).To(BeTrue())
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		container = test.GetContainer(ds.Spec.Template.Spec.Containers, "compliance-benchmarker")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(complianceResources))
	})

	It("should render without resource requests and limits for compliance resources when not set", func() {
		cfg.Compliance = &operatorv1.Compliance{
			Spec: operatorv1.ComplianceSpec{
				ComplianceSnapshotterDeployment: &operatorv1.ComplianceSnapshotterDeployment{
					Spec: &operatorv1.ComplianceSnapshotterDeploymentSpec{
						Template: &operatorv1.ComplianceSnapshotterDeploymentPodTemplateSpec{
							Spec: &operatorv1.ComplianceSnapshotterDeploymentPodSpec{
								Containers: []operatorv1.ComplianceSnapshotterDeploymentContainer{{
									Name:      "compliance-snapshotter",
									Resources: &complianceResources,
								}},
							},
						},
					},
				},
				ComplianceBenchmarkerDaemonSet: &operatorv1.ComplianceBenchmarkerDaemonSet{
					Spec: &operatorv1.ComplianceBenchmarkerDaemonSetSpec{
						Template: &operatorv1.ComplianceBenchmarkerDaemonSetPodTemplateSpec{
							Spec: &operatorv1.ComplianceBenchmarkerDaemonSetPodSpec{
								Containers: []operatorv1.ComplianceBenchmarkerDaemonSetContainer{{
									Name:      "compliance-benchmarker",
									Resources: &complianceResources,
								}},
							},
						},
					},
				},
			},
		}

		component, err := render.Compliance(cfg)
		Expect(err).ShouldNot(HaveOccurred())
		resources, _ := component.Objects()

		// Compliance-server should NOT have resource values when not set
		d, ok := rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container := test.GetContainer(d.Spec.Template.Spec.Containers, "compliance-server")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(corev1.ResourceRequirements{}))

		// Compliance-controller should NOT have resource values when not set
		d, ok = rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container = test.GetContainer(d.Spec.Template.Spec.Containers, "compliance-controller")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(corev1.ResourceRequirements{}))

		// Compliance-snapshotter should have resource values set
		d, ok = rtest.GetResource(resources, "compliance-snapshotter", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container = test.GetContainer(d.Spec.Template.Spec.Containers, "compliance-snapshotter")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(complianceResources))

		// Compliance-benchmark should have resource values set
		ds, ok := rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ok).To(BeTrue())
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		container = test.GetContainer(ds.Spec.Template.Spec.Containers, "compliance-benchmarker")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(complianceResources))

	})

	It("should render resource requests and limits for compliance report", func() {
		cfg.Compliance = &operatorv1.Compliance{
			Spec: operatorv1.ComplianceSpec{
				ComplianceReporterPodTemplate: &operatorv1.ComplianceReporterPodTemplate{
					Template: &operatorv1.ComplianceReporterPodTemplateSpec{
						Spec: &operatorv1.ComplianceReporterPodSpec{
							Containers: []operatorv1.ComplianceReporterPodTemplateContainer{{
								Name:      "reporter",
								Resources: &complianceResources,
							}},
						},
					},
				},
			},
		}

		component, err := render.Compliance(cfg)
		Expect(err).ShouldNot(HaveOccurred())
		resources, _ := component.Objects()

		reporter, ok := rtest.GetResource(resources, "tigera.io.report", ns, "", "v1", "PodTemplate").(*corev1.PodTemplate)
		Expect(ok).To(BeTrue())
		Expect(reporter.Template.Spec.Containers).To(HaveLen(1))
		container := test.GetContainer(reporter.Template.Spec.Containers, "reporter")
		Expect(container.Resources).To(Equal(complianceResources))

	})

	Context("Standalone cluster", func() {
		It("should render all resources for a default configuration", func() {
			component, err := render.Compliance(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{"allow-tigera.compliance-access", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"allow-tigera.default-deny", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"tigera-compliance-controller", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-controller", ns, rbac, "v1", "Role"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-controller", ns, rbac, "v1", "RoleBinding"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-controller", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-reporter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera.io.report", ns, "", "v1", "PodTemplate"},
				{"tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-snapshotter", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", ns, "apps", "v1", "DaemonSet"},
				{"inventory", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"network-access", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"tigera-compliance-server", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding"},
				{"allow-tigera.compliance-server", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRole"},
				{"compliance", ns, "", "v1", "Service"},
				{"compliance-server", ns, "apps", "v1", "Deployment"},
			}

			Expect(len(resources)).To(Equal(len(expectedResources)))

			for i, expectedRes := range expectedResources {
				rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}

			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "inventory", "", "projectcalico.org", "v3", "GlobalReportType"), "inventory")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "network-access", "", "projectcalico.org", "v3", "GlobalReportType"), "network-access")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"), "policy-audit")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"), "cis-benchmark")

			clusterRole := rtest.GetResource(resources, "tigera-compliance-server", "", rbac, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"globalreporttypes", "globalreports"},
					Verbs:     []string{"get", "list", "watch"},
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
				{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"compliancereports"},
					Verbs:     []string{"get"},
				},
			}))

			d := rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))

			envs := d.Spec.Template.Spec.Containers[0].Env
			expectedEnvs := []corev1.EnvVar{
				{Name: "LINSEED_CLIENT_KEY", Value: "/tigera-compliance-controller-tls/tls.key"},
				{Name: "LINSEED_CLIENT_CERT", Value: "/tigera-compliance-controller-tls/tls.crt"},
			}
			for _, expected := range expectedEnvs {
				Expect(envs).To(ContainElement(expected))
			}

			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))

			d = rtest.GetResource(resources, "compliance-snapshotter", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))

			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))

			d = rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))

			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))
		})
	})

	Context("Management cluster", func() {
		It("should render all resources for a default configuration", func() {
			cfg.ManagementCluster = &operatorv1.ManagementCluster{}
			component, err := render.Compliance(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{"allow-tigera.compliance-access", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"allow-tigera.default-deny", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"tigera-compliance-controller", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-controller", ns, rbac, "v1", "Role"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-controller", ns, rbac, "v1", "RoleBinding"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-controller", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-reporter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera.io.report", ns, "", "v1", "PodTemplate"},
				{"tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-snapshotter", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", ns, "apps", "v1", "DaemonSet"},
				{"inventory", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"network-access", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"tigera-compliance-server", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding"},
				{"allow-tigera.compliance-server", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRole"},
				{"compliance", ns, "", "v1", "Service"},
				{"compliance-server", ns, "apps", "v1", "Deployment"},
			}

			Expect(len(resources)).To(Equal(len(expectedResources)))

			for i, expectedRes := range expectedResources {
				rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}

			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "inventory", "", "projectcalico.org", "v3", "GlobalReportType"), "inventory")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "network-access", "", "projectcalico.org", "v3", "GlobalReportType"), "network-access")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"), "policy-audit")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"), "cis-benchmark")

			dpComplianceServer := rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			complianceController := rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			complianceSnapshotter := rtest.GetResource(resources, "compliance-snapshotter", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			complianceBenchmarker := rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].Env).Should(ContainElements())
			Expect(complianceController.Spec.Template.Spec.Containers[0].Env).Should(ContainElements())
			Expect(complianceSnapshotter.Spec.Template.Spec.Containers[0].Env).Should(ContainElements())
			Expect(complianceBenchmarker.Spec.Template.Spec.Containers[0].Env).Should(ContainElements())
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].Env).Should(ContainElements())
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts).To(HaveLen(2))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("tigera-ca-bundle"))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath).To(Equal("/etc/pki/tls/certs"))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal(render.ComplianceServerCertSecret))
			Expect(dpComplianceServer.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/tigera-compliance-server-tls"))

			Expect(dpComplianceServer.Spec.Template.Spec.Volumes).To(HaveLen(2))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[0].Name).To(Equal(render.ComplianceServerCertSecret))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal(render.ComplianceServerCertSecret))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[1].Name).To(Equal("tigera-ca-bundle"))
			Expect(dpComplianceServer.Spec.Template.Spec.Volumes[1].ConfigMap.Name).To(Equal("tigera-ca-bundle"))

			clusterRole := rtest.GetResource(resources, "tigera-compliance-server", "", rbac, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"globalreporttypes", "globalreports"},
					Verbs:     []string{"get", "list", "watch"},
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
				{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"compliancereports"},
					Verbs:     []string{"get"},
				},
			}))
		})
	})

	Context("ManagedCluster", func() {
		It("should render all resources for a default configuration", func() {
			cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
			component, err := render.Compliance(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			ns := "tigera-compliance"
			rbac := "rbac.authorization.k8s.io"

			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{"allow-tigera.compliance-access", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"allow-tigera.default-deny", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"tigera-compliance-controller", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-controller", ns, rbac, "v1", "Role"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-controller", ns, rbac, "v1", "RoleBinding"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-controller", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-reporter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera.io.report", ns, "", "v1", "PodTemplate"},
				{"tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-snapshotter", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", ns, "apps", "v1", "DaemonSet"},
				{"inventory", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"network-access", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"tigera-compliance-server", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRole"},
				{"tigera-linseed", ns, rbac, "v1", "RoleBinding"},
			}

			Expect(len(resources)).To(Equal(len(expectedResources)))

			for i, expectedRes := range expectedResources {
				rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}

			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "inventory", "", "projectcalico.org", "v3", "GlobalReportType"), "inventory")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "network-access", "", "projectcalico.org", "v3", "GlobalReportType"), "network-access")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"), "policy-audit")
			rtest.ExpectGlobalReportType(rtest.GetResource(resources, "cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"), "cis-benchmark")

			clusterRole := rtest.GetResource(resources, "tigera-compliance-server", "", rbac, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"globalreporttypes", "globalreports"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups: []string{"authorization.k8s.io"},
					Resources: []string{"subjectaccessreviews"},
					Verbs:     []string{"create"},
				},
			}))
		})
	})

	Describe("node selection & affinity", func() {
		renderCompliance := func(i *operatorv1.InstallationSpec) (server, controller, snapshotter *appsv1.Deployment, reporter *corev1.PodTemplate, benchmarker *appsv1.DaemonSet) {
			cfg.Installation = i
			component, err := render.Compliance(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()
			server = rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			controller = rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			snapshotter = rtest.GetResource(resources, "compliance-snapshotter", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			reporter = rtest.GetResource(resources, "tigera.io.report", ns, "", "v1", "PodTemplate").(*corev1.PodTemplate)
			benchmarker = rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			return
		}
		It("should apply controlPlaneTolerations", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}
			dpComplianceServer, dpComplianceController, complianceSnapshotter, complianceReporter, complianceBenchmarker := renderCompliance(&operatorv1.InstallationSpec{
				ControlPlaneTolerations: []corev1.Toleration{t},
			})
			Expect(dpComplianceServer.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, t)))
			Expect(dpComplianceController.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, t)))
			Expect(complianceSnapshotter.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, t)))
			Expect(complianceReporter.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, t)))
			Expect(complianceBenchmarker.Spec.Template.Spec.Tolerations).To(ContainElements(rmeta.TolerateAll))
		})

		It("should apply controlPlaneNodeSelectors", func() {
			dpComplianceServer, dpComplianceController, complianceSnapshotter, _, _ := renderCompliance(&operatorv1.InstallationSpec{
				ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
			})
			Expect(dpComplianceServer.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			Expect(dpComplianceController.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
			Expect(complianceSnapshotter.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
		})
	})

	Context("Certificate management enabled", func() {

		It("should render init containers and volume changes", func() {
			ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			complianceTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceServerCertSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.ServerKeyPair = complianceTLS

			controllerKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceControllerSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.ControllerKeyPair = controllerKeyPair

			benchmarkerKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceBenchmarkerSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.BenchmarkerKeyPair = benchmarkerKeyPair

			snapshotterKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceSnapshotterSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.SnapshotterKeyPair = snapshotterKeyPair

			reporterKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceReporterSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.ReporterKeyPair = reporterKeyPair

			component, err := render.Compliance(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()
			expectedResources := []struct {
				name    string
				ns      string
				group   string
				version string
				kind    string
			}{
				{"allow-tigera.compliance-access", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"allow-tigera.default-deny", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"tigera-compliance-controller", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-controller", ns, rbac, "v1", "Role"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-controller", ns, rbac, "v1", "RoleBinding"},
				{"tigera-compliance-controller", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-controller", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-reporter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-reporter", "", rbac, "v1", "ClusterRoleBinding"},
				{"tigera.io.report", ns, "", "v1", "PodTemplate"},
				{"tigera-compliance-snapshotter", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-snapshotter", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-snapshotter", ns, "apps", "v1", "Deployment"},
				{"tigera-compliance-benchmarker", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRole"},
				{"tigera-compliance-benchmarker", "", rbac, "v1", "ClusterRoleBinding"},
				{"compliance-benchmarker", ns, "apps", "v1", "DaemonSet"},
				{"inventory", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"network-access", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"policy-audit", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"cis-benchmark", "", "projectcalico.org", "v3", "GlobalReportType"},
				{"tigera-compliance-server", ns, "", "v1", "ServiceAccount"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRoleBinding"},
				{"allow-tigera.compliance-server", ns, "projectcalico.org", "v3", "NetworkPolicy"},
				{"tigera-compliance-server", "", rbac, "v1", "ClusterRole"},
				{"compliance", ns, "", "v1", "Service"},
				{"compliance-server", ns, "apps", "v1", "Deployment"},
			}

			for i, expectedRes := range expectedResources {
				rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			}
			Expect(len(resources)).To(Equal(len(expectedResources)))

			server := rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(server.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			csrInitContainer := server.Spec.Template.Spec.InitContainers[0]
			Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ComplianceServerCertSecret)))

			controller := rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(controller.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			csrInitContainer = controller.Spec.Template.Spec.InitContainers[0]
			Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ComplianceControllerSecret)))

			benchmarker := rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			Expect(benchmarker.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			csrInitContainer = benchmarker.Spec.Template.Spec.InitContainers[0]
			Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ComplianceBenchmarkerSecret)))

			snapshotter := rtest.GetResource(resources, "compliance-snapshotter", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(snapshotter.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			csrInitContainer = snapshotter.Spec.Template.Spec.InitContainers[0]
			Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ComplianceSnapshotterSecret)))

			reporter := rtest.GetResource(resources, "tigera.io.report", ns, "", "v1", "PodTemplate").(*corev1.PodTemplate)
			Expect(reporter.Template.Spec.InitContainers).To(HaveLen(1))
			csrInitContainer = reporter.Template.Spec.InitContainers[0]
			Expect(csrInitContainer.Name).To(Equal(fmt.Sprintf("%v-key-cert-provisioner", render.ComplianceReporterSecret)))
		})
		It("should render init containers with resource requests and limits", func() {
			ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			complianceTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceServerCertSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.ServerKeyPair = complianceTLS

			controllerKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceControllerSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.ControllerKeyPair = controllerKeyPair

			benchmarkerKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceBenchmarkerSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.BenchmarkerKeyPair = benchmarkerKeyPair

			snapshotterKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceSnapshotterSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.SnapshotterKeyPair = snapshotterKeyPair

			reporterKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.ComplianceReporterSecret, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())
			cfg.ReporterKeyPair = reporterKeyPair
			cfg.Compliance = &operatorv1.Compliance{
				Spec: operatorv1.ComplianceSpec{
					ComplianceServerDeployment: &operatorv1.ComplianceServerDeployment{
						Spec: &operatorv1.ComplianceServerDeploymentSpec{
							Template: &operatorv1.ComplianceServerDeploymentPodTemplateSpec{
								Spec: &operatorv1.ComplianceServerDeploymentPodSpec{
									InitContainers: []operatorv1.ComplianceServerDeploymentInitContainer{{
										Name:      "tigera-compliance-server-tls-key-cert-provisioner",
										Resources: &complianceResources,
									}},
								},
							},
						},
					},
					ComplianceControllerDeployment: &operatorv1.ComplianceControllerDeployment{
						Spec: &operatorv1.ComplianceControllerDeploymentSpec{
							Template: &operatorv1.ComplianceControllerDeploymentPodTemplateSpec{
								Spec: &operatorv1.ComplianceControllerDeploymentPodSpec{
									InitContainers: []operatorv1.ComplianceControllerDeploymentInitContainer{{
										Name:      "tigera-compliance-controller-tls-key-cert-provisioner",
										Resources: &complianceResources,
									}},
								},
							},
						},
					},
					ComplianceSnapshotterDeployment: &operatorv1.ComplianceSnapshotterDeployment{
						Spec: &operatorv1.ComplianceSnapshotterDeploymentSpec{
							Template: &operatorv1.ComplianceSnapshotterDeploymentPodTemplateSpec{
								Spec: &operatorv1.ComplianceSnapshotterDeploymentPodSpec{
									InitContainers: []operatorv1.ComplianceSnapshotterDeploymentInitContainer{{
										Name:      "tigera-compliance-snapshotter-tls-key-cert-provisioner",
										Resources: &complianceResources,
									}},
								},
							},
						},
					},

					ComplianceBenchmarkerDaemonSet: &operatorv1.ComplianceBenchmarkerDaemonSet{
						Spec: &operatorv1.ComplianceBenchmarkerDaemonSetSpec{
							Template: &operatorv1.ComplianceBenchmarkerDaemonSetPodTemplateSpec{
								Spec: &operatorv1.ComplianceBenchmarkerDaemonSetPodSpec{
									InitContainers: []operatorv1.ComplianceBenchmarkerDaemonSetInitContainer{{
										Name:      "tigera-compliance-benchmarker-tls-key-cert-provisioner",
										Resources: &complianceResources,
									}},
								},
							},
						},
					},
					ComplianceReporterPodTemplate: &operatorv1.ComplianceReporterPodTemplate{
						Template: &operatorv1.ComplianceReporterPodTemplateSpec{
							Spec: &operatorv1.ComplianceReporterPodSpec{
								InitContainers: []operatorv1.ComplianceReporterPodTemplateInitContainer{{
									Name:      "tigera-compliance-reporter-tls-key-cert-provisioner",
									Resources: &complianceResources,
								}},
							},
						},
					},
				},
			}
			component, err := render.Compliance(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			server, ok := rtest.GetResource(resources, "compliance-server", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(server.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			initContainer := test.GetContainer(server.Spec.Template.Spec.InitContainers, "tigera-compliance-server-tls-key-cert-provisioner")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Resources).To(Equal(complianceResources))

			controller := rtest.GetResource(resources, "compliance-controller", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(controller.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			initContainer = test.GetContainer(controller.Spec.Template.Spec.InitContainers, "tigera-compliance-controller-tls-key-cert-provisioner")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Resources).To(Equal(complianceResources))

			benchmarker := rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			Expect(ok).To(BeTrue())
			Expect(benchmarker.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			initContainer = test.GetContainer(benchmarker.Spec.Template.Spec.InitContainers, "tigera-compliance-benchmarker-tls-key-cert-provisioner")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Resources).To(Equal(complianceResources))

			snapshotter := rtest.GetResource(resources, "compliance-snapshotter", ns, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(snapshotter.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			initContainer = test.GetContainer(snapshotter.Spec.Template.Spec.InitContainers, "tigera-compliance-snapshotter-tls-key-cert-provisioner")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Resources).To(Equal(complianceResources))

			reporter := rtest.GetResource(resources, "tigera.io.report", ns, "", "v1", "PodTemplate").(*corev1.PodTemplate)
			Expect(ok).To(BeTrue())
			Expect(reporter.Template.Spec.InitContainers).To(HaveLen(1))
			initContainer = test.GetContainer(reporter.Template.Spec.InitContainers, "tigera-compliance-reporter-tls-key-cert-provisioner")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Resources).To(Equal(complianceResources))
		})
	})

	Context("Render Benchmarker", func() {
		It("should render benchmarker properly for non GKE environments", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderNone
			component, err := render.Compliance(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			dsBenchMarker := rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			volumeMounts := dsBenchMarker.Spec.Template.Spec.Containers[0].VolumeMounts

			Expect(volumeMounts).To(HaveLen(7))

			Expect(volumeMounts[0].Name).To(Equal("var-lib-etcd"))
			Expect(volumeMounts[0].MountPath).To(Equal("/var/lib/etcd"))
			Expect(volumeMounts[1].Name).To(Equal("var-lib-kubelet"))
			Expect(volumeMounts[1].MountPath).To(Equal("/var/lib/kubelet"))
			Expect(volumeMounts[2].Name).To(Equal("etc-systemd"))
			Expect(volumeMounts[2].MountPath).To(Equal("/etc/systemd"))
			Expect(volumeMounts[3].Name).To(Equal("etc-kubernetes"))
			Expect(volumeMounts[3].MountPath).To(Equal("/etc/kubernetes"))
			Expect(volumeMounts[4].Name).To(Equal("usr-bin"))
			Expect(volumeMounts[4].MountPath).To(Equal("/usr/local/bin"))
			Expect(volumeMounts[5].Name).To(Equal("tigera-ca-bundle"))
			Expect(volumeMounts[5].MountPath).To(Equal("/etc/pki/tls/certs"))
			Expect(volumeMounts[6].Name).To(Equal("tigera-compliance-benchmarker-tls"))
			Expect(volumeMounts[6].MountPath).To(Equal("/tigera-compliance-benchmarker-tls"))
		})

		It("should render benchmarker properly for GKE environments", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
			component, err := render.Compliance(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			resources, _ := component.Objects()

			dsBenchMarker := rtest.GetResource(resources, "compliance-benchmarker", ns, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			volumeMounts := dsBenchMarker.Spec.Template.Spec.Containers[0].VolumeMounts

			Expect(volumeMounts).To(HaveLen(8))

			Expect(volumeMounts[0].Name).To(Equal("var-lib-etcd"))
			Expect(volumeMounts[0].MountPath).To(Equal("/var/lib/etcd"))
			Expect(volumeMounts[1].Name).To(Equal("var-lib-kubelet"))
			Expect(volumeMounts[1].MountPath).To(Equal("/var/lib/kubelet"))
			Expect(volumeMounts[2].Name).To(Equal("etc-systemd"))
			Expect(volumeMounts[2].MountPath).To(Equal("/etc/systemd"))
			Expect(volumeMounts[3].Name).To(Equal("etc-kubernetes"))
			Expect(volumeMounts[3].MountPath).To(Equal("/etc/kubernetes"))
			Expect(volumeMounts[4].Name).To(Equal("usr-bin"))
			Expect(volumeMounts[4].MountPath).To(Equal("/usr/local/bin"))
			Expect(volumeMounts[5].Name).To(Equal("tigera-ca-bundle"))
			Expect(volumeMounts[5].MountPath).To(Equal("/etc/pki/tls/certs"))
			Expect(volumeMounts[6].Name).To(Equal("tigera-compliance-benchmarker-tls"))
			Expect(volumeMounts[6].MountPath).To(Equal("/tigera-compliance-benchmarker-tls"))
			Expect(volumeMounts[7].Name).To(Equal("home-kubernetes"))
			Expect(volumeMounts[7].MountPath).To(Equal("/home/kubernetes"))
		})
	})

	Context("allow-tigera rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "allow-tigera.compliance-access", Namespace: "tigera-compliance"},
			{Name: "allow-tigera.compliance-server", Namespace: "tigera-compliance"},
		}

		getExpectedPolicy := func(policyName types.NamespacedName, scenario testutils.AllowTigeraScenario) *v3.NetworkPolicy {
			if policyName.Name == "allow-tigera.compliance-access" {
				return testutils.SelectPolicyByClusterTypeAndProvider(
					scenario,
					expectedCompliancePolicyForUnmanaged,
					expectedCompliancePolicyForUnmanagedOpenshift,
					expectedCompliancePolicyForManaged,
					expectedCompliancePolicyForManagedOpenshift,
				)
			} else if !scenario.ManagedCluster && policyName.Name == "allow-tigera.compliance-server" {
				return testutils.SelectPolicyByProvider(scenario, expectedComplianceServerPolicy, expectedComplianceServerPolicyForOpenshift)
			}

			return nil
		}

		DescribeTable("should render allow-tigera policy",
			func(scenario testutils.AllowTigeraScenario) {
				cfg.OpenShift = scenario.OpenShift
				if scenario.ManagedCluster {
					cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
				} else {
					cfg.ManagementClusterConnection = nil
				}
				component, err := render.Compliance(cfg)
				Expect(err).ShouldNot(HaveOccurred())
				resources, _ := component.Objects()

				for _, policyName := range policyNames {
					policy := testutils.GetAllowTigeraPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},
			Entry("for management/standalone, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.AllowTigeraScenario{ManagedCluster: true, OpenShift: true}),
		)
	})

	Context("multi-tenant rendering", func() {
		tenantANamespace := "tenant-a"
		tenantBNamespace := "tenant-b"
		It("should render expected components inside expected namespace for each compliance instance", func() {
			cfg.Namespace = tenantANamespace
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())

			tenantAResources, _ := tenantACompliance.Objects()

			// Should render the correct resources
			tenantAExpectedResources := []client.Object{
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server", Namespace: tenantANamespace}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.MultiTenantComplianceManagedClustersAccessClusterRoleName}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.MultiTenantComplianceManagedClustersAccessClusterRoleName}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceSnapshotterServiceAccount}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceSnapshotterServiceAccount}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceBenchmarkerServiceAccount}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceBenchmarkerServiceAccount}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceControllerServiceAccount}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceControllerServiceAccount}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceReporterServiceAccount}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceReporterServiceAccount}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.compliance-server", Namespace: tenantANamespace}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "compliance", Namespace: tenantANamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "compliance-server", Namespace: tenantANamespace}},
			}

			rtest.ExpectResources(tenantAResources, tenantAExpectedResources)

			for _, deploymentName := range []string{"compliance-server"} {
				deployment := rtest.GetResource(tenantAResources, deploymentName, tenantANamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
				envs := deployment.Spec.Template.Spec.Containers[0].Env
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TIGERA_COMPLIANCE_JOB_NAMESPACE", Value: tenantANamespace}))
			}

			cfg.Namespace = tenantBNamespace
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantB",
					Namespace: tenantBNamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-b-id",
				},
			}
			tenantBCompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())

			tenantBResources, _ := tenantBCompliance.Objects()

			// Should render the correct resources
			tenantBExpectedResources := []client.Object{
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server", Namespace: tenantBNamespace}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.MultiTenantComplianceManagedClustersAccessClusterRoleName}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.MultiTenantComplianceManagedClustersAccessClusterRoleName}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceSnapshotterServiceAccount}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceSnapshotterServiceAccount}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceBenchmarkerServiceAccount}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceBenchmarkerServiceAccount}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceControllerServiceAccount}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceControllerServiceAccount}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceReporterServiceAccount}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.ComplianceReporterServiceAccount}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera.compliance-server", Namespace: tenantBNamespace}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-compliance-server"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "compliance", Namespace: tenantBNamespace}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "compliance-server", Namespace: tenantBNamespace}},
			}

			rtest.ExpectResources(tenantBResources, tenantBExpectedResources)

			for _, deploymentName := range []string{"compliance-server"} {
				deployment := rtest.GetResource(tenantBResources, deploymentName, tenantBNamespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
				envs := deployment.Spec.Template.Spec.Containers[0].Env
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TIGERA_COMPLIANCE_JOB_NAMESPACE", Value: tenantBNamespace}))
			}
		})

		It("should render multi-tenant environment variables", func() {
			cfg.Namespace = tenantANamespace
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())

			tenantAResources, _ := tenantACompliance.Objects()
			d := rtest.GetResource(tenantAResources, render.ComplianceServerName, cfg.Namespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			envs := d.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "TENANT_NAMESPACE", Value: cfg.Tenant.Namespace}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "MULTI_CLUSTER_FORWARDING_ENDPOINT", Value: fmt.Sprintf("https://tigera-manager.%s.svc:9443", cfg.Tenant.Namespace)}))
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: fmt.Sprintf("https://tigera-linseed.%s.svc", cfg.Tenant.Namespace)}))
		})

		It("should render impersonation permissions as part of tigera-compliance-server ClusterRole", func() {
			cfg.Namespace = tenantANamespace
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ := tenantACompliance.Objects()
			cr := rtest.GetResource(resources, render.ComplianceServerServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts"},
					Verbs:         []string{"impersonate"},
					ResourceNames: []string{render.ComplianceServerServiceAccount},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"groups"},
					Verbs:     []string{"impersonate"},
					ResourceNames: []string{
						serviceaccount.AllServiceAccountsGroup,
						"system:authenticated",
						fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, render.ComplianceNamespace),
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
		})

		It("should render managed cluster permissions as part of compliance-server-managed-cluster-access ClusterRole", func() {
			cfg.Namespace = tenantANamespace
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ := tenantACompliance.Objects()
			cr := rtest.GetResource(resources, render.MultiTenantComplianceManagedClustersAccessClusterRoleName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters"},
					Verbs: []string{
						"get",
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
			rb := rtest.GetResource(resources, render.MultiTenantComplianceManagedClustersAccessClusterRoleName, "", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(render.MultiTenantComplianceManagedClustersAccessClusterRoleName))
			Expect(rb.Subjects).To(ContainElements([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.ComplianceServerServiceAccount,
					Namespace: render.ComplianceNamespace,
				},
			}))
		})

		It("should render linseed API permissions as part of tigera-compliance-snapshotter ClusterRole", func() {
			cfg.Namespace = tenantANamespace
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ := tenantACompliance.Objects()
			cr := rtest.GetResource(resources, render.ComplianceSnapshotterServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"snapshots"},
					Verbs: []string{
						"get", "create",
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
			rb := rtest.GetResource(resources, render.ComplianceSnapshotterServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(render.ComplianceSnapshotterServiceAccount))
			Expect(rb.Subjects).To(ContainElements([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.ComplianceSnapshotterServiceAccount,
					Namespace: tenantANamespace,
				},
			}))
		})

		It("should render linseed API permissions as part of tigera-compliance-benchmarker ClusterRole", func() {
			cfg.Namespace = tenantANamespace
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ := tenantACompliance.Objects()
			cr := rtest.GetResource(resources, render.ComplianceBenchmarkerServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"benchmarks"},
					Verbs: []string{
						"get", "create",
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
			rb := rtest.GetResource(resources, render.ComplianceBenchmarkerServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(render.ComplianceBenchmarkerServiceAccount))
			Expect(rb.Subjects).To(ContainElements([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.ComplianceBenchmarkerServiceAccount,
					Namespace: tenantANamespace,
				},
			}))
		})

		It("should render linseed API permissions as part of tigera-compliance-controller ClusterRole", func() {
			cfg.Namespace = tenantANamespace
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ := tenantACompliance.Objects()
			cr := rtest.GetResource(resources, render.ComplianceControllerServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"compliancereports"},
					Verbs: []string{
						"create", "get",
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
			rb := rtest.GetResource(resources, render.ComplianceControllerServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(render.ComplianceControllerServiceAccount))
			Expect(rb.Subjects).To(ContainElements([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.ComplianceControllerServiceAccount,
					Namespace: tenantANamespace,
				},
			}))
		})

		It("should render linseed API permissions as part of tigera-compliance-reporter ClusterRole", func() {
			cfg.Namespace = tenantANamespace
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ := tenantACompliance.Objects()
			cr := rtest.GetResource(resources, render.ComplianceReporterServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"compliancereports"},
					Verbs: []string{
						"create",
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
			rb := rtest.GetResource(resources, render.ComplianceReporterServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(render.ComplianceReporterServiceAccount))
			Expect(rb.Subjects).To(ContainElements([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      render.ComplianceReporterServiceAccount,
					Namespace: tenantANamespace,
				},
			}))
		})
	})

	Context("single-tenant rendering", func() {

		It("should NOT render impersonation permissions as part of tigera-compliance-server ClusterRole", func() {
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenantA",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			tenantACompliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ := tenantACompliance.Objects()
			cr := rtest.GetResource(resources, render.ComplianceServerServiceAccount, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"serviceaccounts"},
					Verbs:         []string{"impersonate"},
					ResourceNames: []string{render.ComplianceServerServiceAccount},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"groups"},
					Verbs:     []string{"impersonate"},
					ResourceNames: []string{
						serviceaccount.AllServiceAccountsGroup,
						"system:authenticated",
						fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, render.ComplianceNamespace),
					},
				},
			}
			Expect(cr.Rules).NotTo(ContainElements(expectedRules))
		})

		It("should render single-tenant environment variables", func() {
			cfg.ExternalElastic = true
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenantA",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			compliance, err := render.Compliance(cfg)
			Expect(err).NotTo(HaveOccurred())

			resources, _ := compliance.Objects()
			server := rtest.GetResource(resources, render.ComplianceServerName, cfg.Namespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(server.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))

			controller := rtest.GetResource(resources, render.ComplianceControllerName, cfg.Namespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(controller.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))

			reporterTemplate := rtest.GetResource(resources, "tigera.io.report", cfg.Namespace, corev1.GroupName, "v1", "PodTemplate").(*corev1.PodTemplate)
			Expect(reporterTemplate.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))

			snapshotter := rtest.GetResource(resources, render.ComplianceSnapshotterName, cfg.Namespace, appsv1.GroupName, "v1", "Deployment").(*appsv1.Deployment)
			Expect(snapshotter.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))

			benchmarker := rtest.GetResource(resources, render.ComplianceBenchmarkerName, cfg.Namespace, appsv1.GroupName, "v1", "DaemonSet").(*appsv1.DaemonSet)
			Expect(benchmarker.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "TENANT_ID", Value: cfg.Tenant.Spec.ID}))
		})
	})
})
