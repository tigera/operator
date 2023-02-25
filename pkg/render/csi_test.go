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

	Context("With csi-node-driver DaemonSet overrides", func() {
		It("should handle csiNodeDriverDaemonSet overrides", func() {
			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			defaultInstance.CSINodeDriverDaemonSet = &operatorv1.CSINodeDriverDaemonSet{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.CSINodeDriverDaemonSetSpec{
					Template: &operatorv1.CSINodeDriverDaemonSetPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.CSINodeDriverDaemonSetPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							Affinity:    affinity,
							Tolerations: []corev1.Toleration{toleration},
						},
					},
				},
			}

			component := render.CSI(&cfg)
			resources, _ := component.Objects()
			dsResource := rtest.GetResource(resources, render.CSIDaemonSetName, common.CalicoNamespace, "apps", "v1", "DaemonSet")
			Expect(dsResource).ToNot(BeNil())

			ds := dsResource.(*appsv1.DaemonSet)

			Expect(ds.Labels).To(HaveLen(1))
			Expect(ds.Labels["top-level"]).To(Equal("label1"))
			Expect(ds.Annotations).To(HaveLen(1))
			Expect(ds.Annotations["top-level"]).To(Equal("annot1"))
			// At runtime, the operator will also add some standard labels to the
			// daemonset such as "k8s-app=csi-node-driver". But the csi-node-driver daemonset object
			// produced by the render will have 1 label (name) so we expect one plus the one
			// provided.
			Expect(ds.Spec.Template.Labels).To(HaveLen(2))
			Expect(ds.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			Expect(ds.Spec.Template.Annotations).To(HaveLen(1))
			Expect(ds.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))
			Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(ds.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(ds.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(ds.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
		})
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
})
