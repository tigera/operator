// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kubeproxy

import (
	"context"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	// gopkg.in/yaml.v2 didn't parse all the fields but this package did
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("kube-proxy controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r *Reconciler
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var k8sService *corev1.Service
	var K8sEndpointSlice *discoveryv1.EndpointSlice

	kpManagementEnabled := operatorv1.KubeProxyManagementEnabled
	kpManagementDisabled := operatorv1.KubeProxyManagementDisabled

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(discoveryv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a CRUD interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		k8sService = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
				ClusterIP:  "1.2.3.4",
				Ports: []corev1.ServicePort{
					{Name: "https", Port: 443, TargetPort: intstr.FromInt(443)},
				},
			},
		}
		K8sEndpointSlice = &discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Name: "kubernetes-epv4", Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"5.6.7.8", "5.6.7.9", "5.6.7.10"}},
			},
			Ports: []discoveryv1.EndpointPort{{Port: ptr.Int32ToPtr(6443)}},
		}

		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		r = &Reconciler{
			cli:    c,
			scheme: scheme,
			status: mockStatus,
		}
	})

	createResource := func(obj client.Object) {
		Expect(c.Create(ctx, obj)).NotTo(HaveOccurred())
	}
	createInstallationCR := func(bpfEnabled bool, managed *operatorv1.KubeProxyManagementType) {
		linuxDataplaneBPF := operatorv1.LinuxDataplaneBPF
		if !bpfEnabled {
			linuxDataplaneBPF = operatorv1.LinuxDataplaneIptables
		}
		createResource(&operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					KubeProxyManagement: managed,
					LinuxDataplane:      &linuxDataplaneBPF,
				},
			},
		})
	}
	createKubeProxyDS := func(addNodeSelector bool) {
		nodeSelector := map[string]string{}
		if addNodeSelector {
			nodeSelector[render.DisableKubeProxyKey] = "true"
		}
		createResource(&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: utils.KubeProxyDaemonSetName, Namespace: utils.KubeProxyNamespace},
			Spec: appsv1.DaemonSetSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: corev1.PodSpec{
						NodeSelector: nodeSelector,
					},
				},
			},
		})
	}
	createFelixConfiguration := func(bpfEnabled bool) {
		createResource(&crdv1.FelixConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: crdv1.FelixConfigurationSpec{
				BPFEnabled: ptr.BoolToPtr(bpfEnabled),
			},
		})
	}
	checkKubeProxyState := func(kp *appsv1.DaemonSet, hasNodeSelector bool) {
		if hasNodeSelector {
			Expect(kp.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(kp.Spec.Template.Spec.NodeSelector[render.DisableKubeProxyKey]).To(Equal("true"))
		} else {
			Expect(kp.Spec.Template.Spec.NodeSelector).To(HaveLen(0))
		}
	}

	table.DescribeTable("handle kube-proxy DaemonSet correctly based on BPF auto-install requirements",
		func(bpfEnabled bool, kpManaged *operatorv1.KubeProxyManagementType) {
			kp := &appsv1.DaemonSet{}
			nodeSelectorIncluded := !bpfEnabled
			By("applying the resources")
			createInstallationCR(bpfEnabled, kpManaged)
			createFelixConfiguration(bpfEnabled)
			createKubeProxyDS(nodeSelectorIncluded)
			createResource(k8sService)
			createResource(K8sEndpointSlice)

			By("reading the KubeProxy DaemonSet initial state")
			err := c.Get(ctx, types.NamespacedName{Namespace: utils.KubeProxyNamespace, Name: utils.KubeProxyDaemonSetName}, kp)
			Expect(err).NotTo(HaveOccurred())
			checkKubeProxyState(kp, nodeSelectorIncluded)

			By("triggering a reconcile")
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("re-reading the KubeProxy DaemonSet")
			err = c.Get(ctx, types.NamespacedName{Namespace: utils.KubeProxyNamespace, Name: utils.KubeProxyDaemonSetName}, kp)
			Expect(err).NotTo(HaveOccurred())

			By("checking if NodeSelector changed")
			// It should change only if KubeProxyManagement is Enabled
			if kpManaged == &kpManagementEnabled {
				nodeSelectorIncluded = !nodeSelectorIncluded
			}
			checkKubeProxyState(kp, nodeSelectorIncluded)
		},
		table.Entry("disable kube-proxy if BPFEnabled is false and kubeProxyManagement is Enabled",
			true, &kpManagementEnabled,
		),
		table.Entry("enable kube-proxy if BPFEnabled is false and kubeProxyManagement is Enabled",
			false, &kpManagementEnabled,
		),
		table.Entry("doesn't change kube-proxy if kubeProxyManagement is Disabled",
			false, &kpManagementDisabled,
		),
		table.Entry("doesn't change kube-proxy if kubeProxyManagement is unset",
			true, nil,
		),
	)

})
