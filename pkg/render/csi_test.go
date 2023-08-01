// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.
//
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
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("CSI rendering tests", func() {
	var defaultInstance *operatorv1.InstallationSpec
	var cfg render.CSIConfiguration

	BeforeEach(func() {
		defaultInstance = &operatorv1.InstallationSpec{
			KubeletVolumePluginPath: "/var/lib/kubelet",
		}
		cfg = render.CSIConfiguration{
			Installation: defaultInstance,
		}
	})

	It("should render properly with KubeletVolumePluginPath default value", func() {
		expectedCreateObjs := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "csi.tigera.io", ns: "", group: "storage", version: "v1", kind: "CSIDriver"},
			{name: "csi-node-driver", ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}

		comp := render.CSI(&cfg)
		Expect(comp.ResolveImages(nil)).To(BeNil())
		createObjs, delObjs := comp.Objects()

		Expect(createObjs).To(HaveLen(len(expectedCreateObjs)))
		Expect(delObjs).To(HaveLen(0))

		for i, expectedRes := range expectedCreateObjs {
			rtest.ExpectResource(createObjs[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		ds := rtest.GetResource(createObjs, render.CSIDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(2))

		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeTrue())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.Privileged).To(BeTrue())
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*ds.Spec.Template.Spec.Containers[1].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(ds.Spec.Template.Spec.Containers[1].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(ds.Spec.Template.Spec.Containers[1].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
	})

	It("should render properly when KubeletVolumePluginPath is set to 'None'", func() {
		cfg.Installation.KubeletVolumePluginPath = "None"
		expectedDelObjs := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "csi.tigera.io", ns: "", group: "storage", version: "v1", kind: "CSIDriver"},
			{name: "csi-node-driver", ns: common.CalicoNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
		}
		comp := render.CSI(&cfg)
		Expect(comp.ResolveImages(nil)).To(BeNil())
		createObjs, delObjs := comp.Objects()

		Expect(len(createObjs)).To(Equal(0))
		Expect(len(delObjs)).To(Equal(len(expectedDelObjs)))

		for i, expectedRes := range expectedDelObjs {
			rtest.ExpectResource(delObjs[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should set priority class to system-node-critical", func() {
		resources, _ := render.CSI(&cfg).Objects()
		ds := rtest.GetResource(resources, render.CSIDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal("system-node-critical"))
	})

	It("should propagate imagePullSecrets and registry Installation field changes to DaemonSet", func() {
		privatePullSecret := []corev1.LocalObjectReference{
			{
				Name: "privatePullSecret",
			},
		}
		privateRegistry := "private/registry.io/"
		cfg.Installation.ImagePullSecrets = privatePullSecret
		cfg.Installation.Registry = privateRegistry
		resources, _ := render.CSI(&cfg).Objects()
		ds := rtest.GetResource(resources, render.CSIDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.ImagePullSecrets).To(Equal(privatePullSecret))
		for _, container := range ds.Spec.Template.Spec.Containers {
			Expect(strings.HasPrefix(container.Image, privateRegistry))
		}
	})

	It("should render CSI's PSP and the corresponding clusterroles when UsePSP is set true", func() {
		cfg.UsePSP = true
		resources, _ := render.CSI(&cfg).Objects()

		ds := rtest.GetResource(resources, render.CSIDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds).NotTo(BeNil())
		Expect(ds.Spec.Template.Spec.ServiceAccountName).To(Equal("csi-node-driver"))

		serviceAccount := rtest.GetResource(resources, render.CSIDaemonSetName, render.CSIDaemonSetNamespace, "", "v1", "ServiceAccount")
		Expect(serviceAccount).ToNot(BeNil())

		psp := rtest.GetResource(resources, render.CSIDaemonSetName, "", "policy", "v1beta1", "PodSecurityPolicy").(*policyv1beta1.PodSecurityPolicy)
		Expect(psp).ToNot(BeNil())
		Expect(psp.Spec.Privileged).To(BeTrue())
		Expect(*psp.Spec.AllowPrivilegeEscalation).To(BeTrue())
		Expect(psp.Spec.RunAsUser.Rule).To(Equal(policyv1beta1.RunAsUserStrategyRunAsAny))

		role := rtest.GetResource(resources, render.CSIDaemonSetName, render.CSIDaemonSetNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(role).ToNot(BeNil())
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{render.CSIDaemonSetName},
		}))

		roleBinding := rtest.GetResource(resources, render.CSIDaemonSetName, render.CSIDaemonSetNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(roleBinding).ToNot(BeNil())
		Expect(roleBinding.Subjects).To(HaveLen(1))
		Expect(roleBinding.Subjects).To(ContainElement(
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      render.CSIDaemonSetName,
				Namespace: render.CSIDaemonSetNamespace,
			},
		))
	})

	It("should not add ServiceAccountName field when UsePSP is false", func() {
		cfg.UsePSP = false
		resources, _ := render.CSI(&cfg).Objects()

		ds := rtest.GetResource(resources, render.CSIDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.ServiceAccountName).To(BeEmpty())
	})

	It("should use private images when Variant = enterprise", func() {
		cfg.Installation.Variant = operatorv1.TigeraSecureEnterprise
		comp := render.CSI(&cfg)
		Expect(comp.ResolveImages(nil)).To(BeNil())
		createObjs, _ := comp.Objects()
		dsResource := rtest.GetResource(createObjs, "csi-node-driver", common.CalicoNamespace, "apps", "v1", "DaemonSet")
		Expect(dsResource.(*appsv1.DaemonSet).Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("%s%s:%s", components.TigeraRegistry, components.ComponentCSIPrivate.Image, components.ComponentCSIPrivate.Version)))
		Expect(dsResource.(*appsv1.DaemonSet).Spec.Template.Spec.Containers[1].Image).To(Equal(fmt.Sprintf("%s%s:%s", components.TigeraRegistry, components.ComponentCSINodeDriverRegistrarPrivate.Image, components.ComponentCSINodeDriverRegistrarPrivate.Version)))
	})

	It("should use private images when Variant = Calico", func() {
		comp := render.CSI(&cfg)
		Expect(comp.ResolveImages(nil)).To(BeNil())
		createObjs, _ := comp.Objects()
		dsResource := rtest.GetResource(createObjs, "csi-node-driver", common.CalicoNamespace, "apps", "v1", "DaemonSet")
		Expect(dsResource.(*appsv1.DaemonSet).Spec.Template.Spec.Containers[0].Image).To(Equal(fmt.Sprintf("%s%s:%s", components.CalicoRegistry, components.ComponentCalicoCSI.Image, components.ComponentCalicoCSI.Version)))
		Expect(dsResource.(*appsv1.DaemonSet).Spec.Template.Spec.Containers[1].Image).To(Equal(fmt.Sprintf("%s%s:%s", components.CalicoRegistry, components.ComponentCalicoCSIRegistrar.Image, components.ComponentCalicoCSIRegistrar.Version)))
	})

	It("should render the correct env and/or images when FIPS mode is enabled (OSS)", func() {
		fipsEnabled := operatorv1.FIPSModeEnabled
		cfg.Installation.FIPSMode = &fipsEnabled
		cfg.Installation.Variant = operatorv1.Calico

		comp := render.CSI(&cfg)
		Expect(comp.ResolveImages(nil)).To(BeNil())
		createObjs, _ := comp.Objects()
		dsResource := rtest.GetResource(createObjs, "csi-node-driver", common.CalicoNamespace, "apps", "v1", "DaemonSet")
		Expect(dsResource.(*appsv1.DaemonSet).Spec.Template.Spec.Containers[0].Image).To(ContainSubstring("-fips"))
		Expect(dsResource.(*appsv1.DaemonSet).Spec.Template.Spec.Containers[1].Image).To(ContainSubstring("-fips"))
	})

	It("should render the labels when the provider is openshift", func() {
		cfg.OpenShift = true
		comp := render.CSI(&cfg)
		Expect(comp.ResolveImages(nil)).To(BeNil())
		createObjs, _ := comp.Objects()
		dsResource := rtest.GetResource(createObjs, "csi.tigera.io", "", "storage", "v1", "CSIDriver")
		Expect(dsResource.(*storagev1.CSIDriver).ObjectMeta.Labels["security.openshift.io/csi-ephemeral-volume-profile"]).To(Equal("restricted"))

	})
})
