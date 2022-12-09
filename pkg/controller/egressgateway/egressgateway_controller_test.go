// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package egressgateway

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/test"
	"k8s.io/apimachinery/pkg/types"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Egress Gateway controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileEgressGateway
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var installation *operatorv1.Installation

	Context("image reconciliation", func() {
		BeforeEach(func() {
			// The schema contains all objects that should be known to the fake client when the test runs.
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
			// Create a client that will have a crud interface of k8s objects.
			c = fake.NewClientBuilder().WithScheme(scheme).Build()
			ctx = context.Background()
			installation = &operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.InstallationSpec{
					Variant:  operatorv1.TigeraSecureEnterprise,
					Registry: "some.registry.org/",
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.TigeraSecureEnterprise,
					Computed: &operatorv1.InstallationSpec{
						Registry: "my-reg",
						// The test is provider agnostic.
						KubernetesProvider: operatorv1.ProviderNone,
					},
				},
			}
			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()

			r = ReconcileEgressGateway{
				client:          c,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				status:          mockStatus,
				licenseAPIReady: &utils.ReadyFlag{},
			}

			Expect(c.Create(ctx, &crdv1.IPPool{ObjectMeta: metav1.ObjectMeta{Name: "ippool-1"}, Spec: crdv1.IPPoolSpec{
				CIDR:             "1.2.3.0/24",
				VXLANMode:        crdv1.VXLANModeAlways,
				IPIPMode:         crdv1.IPIPModeNever,
				NATOutgoing:      true,
				Disabled:         false,
				DisableBGPExport: true,
			},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &crdv1.IPPool{ObjectMeta: metav1.ObjectMeta{Name: "ippool-2"}, Spec: crdv1.IPPoolSpec{
				CIDR:             "1.2.4.0/24",
				VXLANMode:        crdv1.VXLANModeAlways,
				IPIPMode:         crdv1.IPIPModeNever,
				NATOutgoing:      true,
				Disabled:         false,
				DisableBGPExport: true,
			},
			})).NotTo(HaveOccurred())

			// Mark that the watch for license key was successful.
			r.licenseAPIReady.MarkAsReady()
		})

		It("should render accurate resources for egress gateway", func() {
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRNotFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
			mockStatus.On("ReadyToMonitor")
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

			By("applying the Egress Gateway CR with just the required fields to the fake cluster")
			var replicas int32 = 2
			ipPools := []string{"ippool-1", "ippool-2"}
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools:  ipPools,
					Labels:   labels,
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			dep := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-red",
					Namespace: "calico-egress",
				},
			}
			By("ensuring the egw resources created properly with default values")
			Expect(test.GetResource(c, &dep)).To(BeNil())
			Expect(dep.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(dep.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			initContainer := dep.Spec.Template.Spec.InitContainers[0]
			Expect(initContainer.Image).To(Equal(fmt.Sprintf("some.registry.org/%s:%s",
				components.ComponentEgressGateway.Image, components.ComponentEgressGateway.Version)))
			egwContainer := dep.Spec.Template.Spec.Containers[0]
			Expect(egwContainer.Image).To(Equal(fmt.Sprintf("some.registry.org/%s:%s",
				components.ComponentEgressGateway.Image, components.ComponentEgressGateway.Version)))

			expectedInitEnvVar := []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
				{Name: "EGRESS_VXLAN_PORT", Value: "4790"},
			}
			for _, elem := range expectedInitEnvVar {
				Expect(initContainer.Env).To(ContainElement(elem))
			}

			expectedEgwEnvVar := []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
				{Name: "HEALTH_PORT", Value: "8080"},
				{Name: "ICMP_PROBE_INTERVAL", Value: "5s"},
				{Name: "ICMP_PROBE_TIMEOUT", Value: "15s"},
				{Name: "HTTP_PROBE_INTERVAL", Value: "10s"},
				{Name: "HTTP_PROBE_TIMEOUT", Value: "30s"},
				{Name: "LOG_SEVERITY", Value: "info"},
				{Name: "HEALTH_TIMEOUT_DATASTORE", Value: "1m30s"},
			}
			for _, elem := range expectedEgwEnvVar {
				Expect(egwContainer.Env).To(ContainElement(elem))
			}

			By("update egw with health port")
			Expect(c.Get(ctx, types.NamespacedName{Name: "calico-red", Namespace: "calico-egress"}, egw)).NotTo(HaveOccurred())
			var updatedHealthPort int32 = 9090
			egw.Spec.EgressGatewayFailureDetection = &operatorv1.EgressGatewayFailureDetection{
				HealthPort: &updatedHealthPort,
			}
			logSeverity := "debug"
			egw.Spec.LogSeverity = &logSeverity
			Expect(c.Update(ctx, egw)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			egwContainer = dep.Spec.Template.Spec.Containers[0]
			expectedEgwEnvVar = []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
				{Name: "HEALTH_PORT", Value: "9090"},
				{Name: "ICMP_PROBE_INTERVAL", Value: "5s"},
				{Name: "ICMP_PROBE_TIMEOUT", Value: "15s"},
				{Name: "HTTP_PROBE_INTERVAL", Value: "10s"},
				{Name: "HTTP_PROBE_TIMEOUT", Value: "30s"},
				{Name: "LOG_SEVERITY", Value: "debug"},
				{Name: "HEALTH_TIMEOUT_DATASTORE", Value: "1m30s"},
			}
			for _, elem := range expectedEgwEnvVar {
				Expect(egwContainer.Env).To(ContainElement(elem))
			}

			By("setting ICMP probe IPs and HTTP URLs, should set default value for other fields")
			Expect(c.Get(ctx, types.NamespacedName{Name: "calico-red", Namespace: "calico-egress"}, egw)).NotTo(HaveOccurred())
			egw.Spec.EgressGatewayFailureDetection = &operatorv1.EgressGatewayFailureDetection{
				ICMPProbes: &operatorv1.ICMPProbes{IPs: []string{"1.2.3.4"}},
				HTTPProbes: &operatorv1.HTTPProbes{URLs: []string{"abcd.com"}},
			}
			Expect(c.Update(ctx, egw)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			egwContainer = dep.Spec.Template.Spec.Containers[0]
			expectedEgwEnvVar = []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4097"},
				{Name: "HEALTH_PORT", Value: "8080"},
				{Name: "ICMP_PROBE_INTERVAL", Value: "5s"},
				{Name: "ICMP_PROBE_TIMEOUT", Value: "15s"},
				{Name: "HTTP_PROBE_INTERVAL", Value: "10s"},
				{Name: "HTTP_PROBE_TIMEOUT", Value: "30s"},
				{Name: "LOG_SEVERITY", Value: "debug"},
				{Name: "HEALTH_TIMEOUT_DATASTORE", Value: "1m30s"},
			}

			for _, elem := range expectedEgwEnvVar {
				Expect(egwContainer.Env).To(ContainElement(elem))
			}

			By("setting AWS elastic IPs")
			nativeIP := operatorv1.NativeIPEnabled
			Expect(c.Get(ctx, types.NamespacedName{Name: "calico-red", Namespace: "calico-egress"}, egw)).NotTo(HaveOccurred())
			egw.Spec.AWS = &operatorv1.AwsEgressGateway{ElasticIPs: []string{"4.5.6.7"}, NativeIP: &nativeIP}
			Expect(c.Update(ctx, egw)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("updating felix config")
			egw_blue := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-blue", Namespace: "calico-gw"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools:  ipPools,
					Labels:   labels,
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw_blue)).NotTo(HaveOccurred())
			vxlanPort := 4800
			vxlanVni := 4100
			Expect(c.Create(ctx, &crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: crdv1.FelixConfigurationSpec{
					EgressIPVXLANPort: &vxlanPort,
					EgressIPVXLANVNI:  &vxlanVni,
				},
			})).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(c, &dep)).To(BeNil())
			dep_blue := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-blue",
					Namespace: "calico-gw",
				},
			}
			Expect(test.GetResource(c, &dep_blue)).To(BeNil())
			initContainer = dep.Spec.Template.Spec.InitContainers[0]
			initContainer_blue := dep_blue.Spec.Template.Spec.InitContainers[0]
			expectedInitEnvVar = []corev1.EnvVar{
				{Name: "EGRESS_VXLAN_VNI", Value: "4100"},
				{Name: "EGRESS_VXLAN_PORT", Value: "4800"},
			}
			for _, elem := range expectedInitEnvVar {
				Expect(initContainer.Env).To(ContainElement(elem))
				Expect(initContainer_blue.Env).To(ContainElement(elem))
			}

		})

		It("Should throw an error when ippool is not present", func() {
			mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
			mockStatus.On("SetDegraded", "Error validating egress gateway", "ippools.crd.projectcalico.org \"ippool-3\" not found").Return().Maybe()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			ipPools := []string{"ippool-3"}
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools:  ipPools,
					Labels:   labels,
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())

			mockStatus.AssertExpectations(GinkgoT())

		})

		It("Should throw an error when elastic IPs are specified and native IP disabled", func() {
			mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
			mockStatus.On("SetDegraded", "Error validating egress gateway", "NativeIP should be enabled when elastic IPs are used").Return().Maybe()
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			var replicas int32 = 2
			ipPools := []string{"ippool-1"}
			labels := map[string]string{"egress-code": "red"}
			egw := &operatorv1.EgressGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-red", Namespace: "calico-egress"},
				Spec: operatorv1.EgressGatewaySpec{
					Replicas: &replicas,
					IPPools:  ipPools,
					Labels:   labels,
					AWS:      &operatorv1.AwsEgressGateway{ElasticIPs: []string{"5.6.7.8"}},
				},
				Status: operatorv1.EgressGatewayStatus{
					State: operatorv1.TigeraStatusReady,
				},
			}
			Expect(c.Create(ctx, egw)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())

			mockStatus.AssertExpectations(GinkgoT())

		})

	})
})
