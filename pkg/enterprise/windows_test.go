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

package enterprise_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	client "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("windows enterprise image override", func() {

	ent := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
	calico := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}

	It("selects the enterprise windows images for the enterprise variant", func() {
		Expect(ext.ResolveImage(render.ComponentNameWindowsNodeImg, components.ComponentCalicoNodeWindows, ent)).To(Equal(components.ComponentTigeraNodeWindows))
		Expect(ext.ResolveImage(render.ComponentNameWindowsCNIImg, components.ComponentCalicoCNIWindows, ent)).To(Equal(components.ComponentTigeraCNIWindows))
	})

	It("leaves the defaults in place for the Calico variant", func() {
		Expect(ext.ResolveImage(render.ComponentNameWindowsNodeImg, components.ComponentCalicoNodeWindows, calico)).To(Equal(components.ComponentCalicoNodeWindows))
		Expect(ext.ResolveImage(render.ComponentNameWindowsCNIImg, components.ComponentCalicoCNIWindows, calico)).To(Equal(components.ComponentCalicoCNIWindows))
	})
})

var _ = Describe("windows enterprise modifier", func() {

	// newObjs returns a windows daemonset with the node containers and the OSS
	// cni-log-dir mount the modifier swaps out.
	newObjs := func() []client.Object {
		nodeContainer := func(name string) corev1.Container {
			return corev1.Container{
				Name:         name,
				VolumeMounts: []corev1.VolumeMount{{MountPath: "/var/log/calico/cni", Name: "cni-log-dir"}},
			}
		}
		return []client.Object{
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.WindowsDaemonSetName},
				Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{nodeContainer("felix"), nodeContainer("node"), nodeContainer("confd")},
				}}},
			},
		}
	}

	ds := func(objs []client.Object) *appsv1.DaemonSet {
		d, _ := extensions.FindObject[*appsv1.DaemonSet](objs, common.WindowsDaemonSetName)
		return d
	}
	container := func(d *appsv1.DaemonSet, name string) *corev1.Container {
		for i := range d.Spec.Template.Spec.Containers {
			if d.Spec.Template.Spec.Containers[i].Name == name {
				return &d.Spec.Template.Spec.Containers[i]
			}
		}
		return nil
	}

	ctxFor := func(provider operatorv1.Provider, tls certificatemanagement.KeyPairInterface, bundle certificatemanagement.TrustedBundleRO) extensions.RenderContext {
		return extensions.RenderContext{
			Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise, KubernetesProvider: provider},
			Component: render.WindowsExtensionContext{
				NodeReporterMetricsPort: 9081,
				PrometheusServerTLS:     tls,
				TrustedBundle:           bundle,
			},
		}
	}

	It("appends the node-metrics service", func() {
		out, _ := applyExtensions(ext, render.ComponentNameWindows, ctxFor(operatorv1.ProviderNone, nil, nil), newObjs(), nil)
		svc, ok := extensions.FindObject[*corev1.Service](out, render.WindowsNodeMetricsService)
		Expect(ok).To(BeTrue())
		Expect(svc.Namespace).To(Equal(common.CalicoNamespace))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(9081)))
	})

	It("swaps the cni log mount for the calico log volume and adds enterprise env", func() {
		out, _ := applyExtensions(ext, render.ComponentNameWindows, ctxFor(operatorv1.ProviderNone, nil, nil), newObjs(), nil)
		d := ds(out)

		Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(HaveField("Name", "var-log-calico")))
		for _, name := range []string{"felix", "node", "confd"} {
			c := container(d, name)
			Expect(c.VolumeMounts).To(ContainElement(HaveField("Name", "var-log-calico")))
			Expect(c.VolumeMounts).NotTo(ContainElement(HaveField("Name", "cni-log-dir")))
			Expect(c.Env).To(ContainElements(
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: "9081"},
				corev1.EnvVar{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			))
		}
	})

	It("sets the trusted DNS server on openshift", func() {
		out, _ := applyExtensions(ext, render.ComponentNameWindows, ctxFor(operatorv1.ProviderOpenShift, nil, nil), newObjs(), nil)
		Expect(container(ds(out), "node").Env).To(ContainElement(corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"}))
	})

	It("mounts the prometheus reporter keypair when present", func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		cm, err := certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		tls, err := cm.GetOrCreateKeyPair(cli, render.NodePrometheusTLSServerSecret, common.OperatorNamespace(), []string{"calico-node-metrics-windows"})
		Expect(err).NotTo(HaveOccurred())
		bundle := cm.CreateTrustedBundle()

		out, _ := applyExtensions(ext, render.ComponentNameWindows, ctxFor(operatorv1.ProviderNone, tls, bundle), newObjs(), nil)
		d := ds(out)

		Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(tls.Volume()))
		Expect(d.Spec.Template.Annotations).To(HaveKey(tls.HashAnnotationKey()))
		Expect(container(d, "node").Env).To(ContainElement(HaveField("Name", "FELIX_PROMETHEUSREPORTERCERTFILE")))
		Expect(container(d, "node").VolumeMounts).To(ContainElement(tls.VolumeMount(render.Windows(&render.WindowsConfiguration{}).SupportedOSType())))
	})

	It("does nothing for the Calico variant", func() {
		ctx := extensions.RenderContext{Installation: &operatorv1.InstallationSpec{Variant: operatorv1.Calico}}
		out, _ := applyExtensions(ext, render.ComponentNameWindows, ctx, newObjs(), nil)
		_, ok := extensions.FindObject[*corev1.Service](out, render.WindowsNodeMetricsService)
		Expect(ok).To(BeFalse())
		Expect(ds(out).Spec.Template.Spec.Volumes).To(BeEmpty())
	})
})
