// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package installation

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("windows-controller installation tests", func() {
	var twentySix int32 = 26
	Context("Reconcile tests", func() {
		var c client.Client
		var ctx context.Context
		var cancel context.CancelFunc
		var r ReconcileWindows
		var scheme *runtime.Scheme
		var mockStatus *status.MockStatus

		var cr *operator.Installation

		BeforeEach(func() {
			// The schema contains all objects that should be known to the fake client when the test runs.
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(schedv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

			// Create a client that will have a crud interface of k8s objects.
			c = fake.NewClientBuilder().WithScheme(scheme).Build()
			ctx, cancel = context.WithCancel(context.Background())

			// Create an object we can use throughout the test to do the core reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("AddCertificateSigningRequests", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create dns service which is autodetected by windows-controller
			Expect(c.Create(ctx,
				&corev1.Service{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kube-dns",
						Namespace: "kube-system",
					},
					Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.10"}},
				})).ToNot(HaveOccurred())

			// Create default FelixConfiguration with VXLANVNI set up
			vni := 4096
			Expect(c.Create(ctx,
				&crdv1.FelixConfiguration{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
					Spec: crdv1.FelixConfigurationSpec{VXLANVNI: &vni},
				})).ToNot(HaveOccurred())

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileWindows{
				config:               nil, // there is no fake for config
				client:               c,
				scheme:               scheme,
				autoDetectedProvider: operator.ProviderNone,
				status:               mockStatus,
				amazonCRDExists:      true,
				enterpriseCRDsExist:  true,
			}

			ca, err := tls.MakeCA("test")
			Expect(err).NotTo(HaveOccurred())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			// We start off with a 'standard' installation, with nothing special
			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:               operator.TigeraSecureEnterprise,
					Registry:              "some.registry.org/",
					CertificateManagement: &operator.CertificateManagement{CACert: cert},
				},
			}
			Expect(updateInstallationWithDefaults(ctx, r.client, cr, r.autoDetectedProvider)).NotTo(HaveOccurred())
			certificateManager, err := certificatemanager.Create(c, nil, "")
			Expect(err).NotTo(HaveOccurred())
			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		})
		AfterEach(func() {
			cancel()
		})
		Context("Windows daemonset tests", func() {
			var degradedMsg []string
			var degradedErr []string
			var dsWin appsv1.DaemonSet
			var winNode *corev1.Node

			BeforeEach(func() {
				// Delete the default installation
				_ = c.Delete(ctx, cr)

				// Add a SetDegraded callback to mockStatus to save and verify the messages and errors
				degradedMsg = []string{}
				degradedErr = []string{}
				mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Run(func(args mock.Arguments) {
					degradedMsg = append(degradedMsg, args.Get(1).(string))
					degradedErr = append(degradedErr, args.Get(2).(string))
				})

				dsWin = appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      common.WindowsDaemonSetName,
						Namespace: common.CalicoNamespace,
					},
				}

				// Windows node
				winNode = &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "nodewin1",
						Labels: map[string]string{
							"kubernetes.io/os": "windows",
						},
					},
					Status: corev1.NodeStatus{
						NodeInfo: corev1.NodeSystemInfo{
							ContainerRuntimeVersion: "containerd://1.6.8",
						},
					},
				}

				// Delete the windows node if it exists
				_ = c.Delete(ctx, winNode)

				// Add a VXLAN IP pool, which is supported by Calico for Windows
				cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{
							CIDR:          "192.168.0.0/16",
							Encapsulation: "VXLAN",
							NATOutgoing:   "Enabled",
							NodeSelector:  "all()",
							BlockSize:     &twentySix,
						},
					},
				}
				Expect(updateInstallationWithDefaults(ctx, r.client, cr, r.autoDetectedProvider)).NotTo(HaveOccurred())

				// Set serviceCIDRs in the installation (required for Calico for Windows)
				cr.Spec.ServiceCIDRs = []string{"10.96.0.0/12"}

				// Create the service endpoint configmap for k8s API (required for Calico for Windows)
				k8sapi.Endpoint = k8sapi.ServiceEndpoint{
					Host: "1.2.3.4",
					Port: "6443",
				}

			})

			It("should render the Windows daemonset when configuration is complete and valid and there are Windows nodes", func() {
				// Create the installation resource
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				// The calico-node-windows daemonset should not be rendered as there
				// are no Windows nodes
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))

				// Create the Windows nodes
				Expect(c.Create(ctx, winNode)).ToNot(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should be rendered
				Expect(test.GetResource(c, &dsWin)).To(BeNil())
				Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))
			})

			It("should not render the Windows daemonset when there are no Windows nodes", func() {
				// Create the installation resource
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))
			})

			It("should not render the Windows daemonset when it is explicitly disabled in the installation resource", func() {
				// Create the Windows node
				Expect(c.Create(ctx, winNode)).ToNot(HaveOccurred())

				disabled := operator.WindowsDataplaneDisabled
				cr.Spec.CalicoNetwork.WindowsDataplane = &disabled

				// Create the installation resource
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{}))
				Expect(degradedErr).To(ConsistOf([]string{}))
			})

			It("should render the Windows daemonset in a degraded state when the kubernetes-service-endpoint configmap is incomplete", func() {
				// Create the Windows node
				Expect(c.Create(ctx, winNode)).ToNot(HaveOccurred())

				// Create the installation resource
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				// Have a configmap with no port
				k8sapi.Endpoint = k8sapi.ServiceEndpoint{
					Host: "1.2.3.4",
				}

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should be rendered, but in a degraded state
				Expect(test.GetResource(c, &dsWin)).To(BeNil())
				Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
				Expect(degradedMsg).To(ConsistOf([]string{"Services endpoint configmap 'kubernetes-services-endpoint' does not have all required information for the Calico Windows daemonset configuration"}))
				Expect(degradedErr).To(ConsistOf([]string{"Services endpoint configmap 'kubernetes-services-endpoint' must be configured for Calico for Windows"}))
			})

			It("should render the Windows daemonset in a degraded state when the encapsulation is VXLANCrossSubnet (not supported)", func() {
				// Create the Windows node
				Expect(c.Create(ctx, winNode)).ToNot(HaveOccurred())

				// VXLANCrossSubnet is not supported
				cr.Spec.CalicoNetwork.IPPools[0].Encapsulation = "VXLANCrossSubnet"

				// Create the installation resource
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should be rendered, but in a degraded state
				Expect(test.GetResource(c, &dsWin)).To(BeNil())
				Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
				Expect(degradedMsg).To(ConsistOf([]string{"Encapsulation not supported by Calico for Windows"}))
				Expect(degradedErr).To(ConsistOf([]string{"IPv4 IPPool encapsulation VXLANCrossSubnet is not supported by Calico for Windows"}))
			})

			It("should not render the Windows daemonset when the kube-dns service cannot be found", func() {
				// Create the Windows node
				Expect(c.Create(ctx, winNode)).ToNot(HaveOccurred())

				// Create dns service which is autodetected by windows-controller
				Expect(c.Delete(ctx,
					&corev1.Service{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "kube-dns",
							Namespace: "kube-system",
						},
					})).ToNot(HaveOccurred())

				// Create the installation resource
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("services \"kube-dns\" not found"))

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"kube-dns service not found"}))
				Expect(degradedErr).To(ConsistOf([]string{"services \"kube-dns\" not found"}))
			})

			It("should not render the Windows daemonset when FelixConfiguration.Spec.VXLANVNI is nil", func() {
				// Create the Windows node
				Expect(c.Create(ctx, winNode)).ToNot(HaveOccurred())

				// Delete existing default FelixConfig and recreate with no VXLANVNI
				Expect(c.Delete(ctx,
					&crdv1.FelixConfiguration{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
					})).ToNot(HaveOccurred())
				Expect(c.Create(ctx,
					&crdv1.FelixConfiguration{
						ObjectMeta: metav1.ObjectMeta{
							Name: "default",
						},
						Spec: crdv1.FelixConfigurationSpec{},
					})).ToNot(HaveOccurred())

				// Create the installation resource
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("VXLANVNI not specified in FelixConfigurationSpec"))

				// The calico-node-windows daemonset should not be rendered
				Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
				Expect(dsWin.Spec).To(Equal(appsv1.DaemonSetSpec{}))
				Expect(degradedMsg).To(ConsistOf([]string{"Error reading VXLANVNI from FelixConfiguration"}))
				Expect(degradedErr).To(ConsistOf([]string{"VXLANVNI not specified in FelixConfigurationSpec"}))
			})

			It("should render the Windows daemonset in a degraded state with no ServiceCIDRs, no configmap and unsupported encapsulation with all messages", func() {
				// Create the Windows node
				Expect(c.Create(ctx, winNode)).ToNot(HaveOccurred())

				cr.Spec.ServiceCIDRs = []string{}
				k8sapi.Endpoint = k8sapi.ServiceEndpoint{}
				cr.Spec.CalicoNetwork.IPPools[0].Encapsulation = "IPIP"

				// Create the installation resource
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// The calico-node-windows daemonset should be rendered, but in a degraded state
				Expect(test.GetResource(c, &dsWin)).To(BeNil())
				Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
				Expect(degradedMsg).To(ConsistOf([]string{
					"Calico for Windows requires at least one Kubernetes service CIDR to be configured in InstallationSpec.ServiceCIDRs",
					"Services endpoint configmap 'kubernetes-services-endpoint' does not have all required information for the Calico Windows daemonset configuration",
					"Encapsulation not supported by Calico for Windows"}))
				Expect(degradedErr).To(ConsistOf([]string{
					"InstallationSpec.ServiceCIDRs must be configured for Calico for Windows",
					"Services endpoint configmap 'kubernetes-services-endpoint' must be configured for Calico for Windows",
					"IPv4 IPPool encapsulation IPIP is not supported by Calico for Windows"}))
			})
		})
	})
	Context("image reconciliation tests", func() {
		type testConf struct {
			EnableWindows bool
		}
		for _, testConfig := range []testConf{
			{false},
			{true},
		} {
			enableWindows := testConfig.EnableWindows
			Describe(fmt.Sprintf("enableWindows: %v", enableWindows), func() {
				var c client.Client
				var ctx context.Context
				var cancel context.CancelFunc
				var r ReconcileWindows
				var scheme *runtime.Scheme
				var mockStatus *status.MockStatus

				BeforeEach(func() {
					// The schema contains all objects that should be known to the fake client when the test runs.
					scheme = runtime.NewScheme()
					Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
					Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
					Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
					Expect(schedv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
					Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
					Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

					// Create a client that will have a crud interface of k8s objects.
					c = fake.NewClientBuilder().WithScheme(scheme).Build()
					ctx, cancel = context.WithCancel(context.Background())

					// Create dns service which is autodetected by windows-controller
					Expect(c.Create(ctx,
						&corev1.Service{
							TypeMeta: metav1.TypeMeta{},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "kube-dns",
								Namespace: "kube-system",
							},
							Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.10"}},
						})).ToNot(HaveOccurred())

					// Create default FelixConfiguration with VXLANVNI set up
					vni := 4096
					Expect(c.Create(ctx,
						&crdv1.FelixConfiguration{
							TypeMeta: metav1.TypeMeta{},
							ObjectMeta: metav1.ObjectMeta{
								Name: "default",
							},
							Spec: crdv1.FelixConfigurationSpec{VXLANVNI: &vni},
						})).ToNot(HaveOccurred())

					if enableWindows {
						// Create a Windows node so that the calico-node-windows daemonset is rendered
						node := &corev1.Node{
							ObjectMeta: metav1.ObjectMeta{
								Name: "nodewin1",
								Labels: map[string]string{
									"kubernetes.io/os": "windows",
								},
							},
						}

						node.Status = corev1.NodeStatus{
							NodeInfo: corev1.NodeSystemInfo{
								ContainerRuntimeVersion: "containerd://1.6.8",
							},
						}

						Expect(c.Create(ctx, node)).ToNot(HaveOccurred())
					}

					// Create an object we can use throughout the test to do the compliance reconcile loops.
					mockStatus = &status.MockStatus{}
					mockStatus.On("AddDaemonsets", mock.Anything).Return()
					mockStatus.On("AddDeployments", mock.Anything).Return()
					mockStatus.On("AddStatefulSets", mock.Anything).Return()
					mockStatus.On("AddCronJobs", mock.Anything)
					mockStatus.On("IsAvailable").Return(true)
					mockStatus.On("OnCRFound").Return()
					mockStatus.On("ClearDegraded")
					mockStatus.On("AddCertificateSigningRequests", mock.Anything)
					mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
					mockStatus.On("ReadyToMonitor")
					mockStatus.On("SetMetaData", mock.Anything).Return()
					mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

					// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
					r = ReconcileWindows{
						config:               nil, // there is no fake for config
						client:               c,
						scheme:               scheme,
						autoDetectedProvider: operator.ProviderNone,
						status:               mockStatus,
						amazonCRDExists:      true,
						enterpriseCRDsExist:  true,
					}

					certificateManager, err := certificatemanager.Create(c, nil, "")
					Expect(err).NotTo(HaveOccurred())
					prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusTLSSecretName})
					Expect(err).NotTo(HaveOccurred())
					Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
					Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
					Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
					// We start off with a 'standard' installation, with nothing special

					// Create installation CR with defaults
					instance := &operator.Installation{
						ObjectMeta: metav1.ObjectMeta{Name: "default"},
						Spec: operator.InstallationSpec{
							Variant:               operator.TigeraSecureEnterprise,
							Registry:              "some.registry.org/",
							CertificateManagement: &operator.CertificateManagement{CACert: prometheusTLS.GetCertificatePEM()},
						},
						Status: operator.InstallationStatus{
							Variant: operator.TigeraSecureEnterprise,
							Computed: &operator.InstallationSpec{
								Registry: "my-reg",
								// The test is provider agnostic.
								KubernetesProvider: operator.ProviderNone,
							},
						},
					}
					Expect(updateInstallationWithDefaults(ctx, r.client, instance, r.autoDetectedProvider)).NotTo(HaveOccurred())
					Expect(c.Create(ctx, instance)).NotTo(HaveOccurred())
				})
				AfterEach(func() {
					cancel()
				})

				It("should use builtin images", func() {
					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					if enableWindows {
						dsWin := appsv1.DaemonSet{
							TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      common.WindowsDaemonSetName,
								Namespace: common.CalicoNamespace,
							},
						}
						Expect(test.GetResource(c, &dsWin)).To(BeNil())
						Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
						nodeWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "node")
						Expect(nodeWin).ToNot(BeNil())
						Expect(nodeWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s:%s",
								components.ComponentTigeraNodeWindows.Image,
								components.ComponentTigeraNodeWindows.Version)))
						felixWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "felix")
						Expect(felixWin).ToNot(BeNil())
						Expect(felixWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s:%s",
								components.ComponentTigeraNodeWindows.Image,
								components.ComponentTigeraNodeWindows.Version)))
						confdWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "confd")
						Expect(confdWin).ToNot(BeNil())
						Expect(confdWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s:%s",
								components.ComponentTigeraNodeWindows.Image,
								components.ComponentTigeraNodeWindows.Version)))
						Expect(dsWin.Spec.Template.Spec.InitContainers).To(HaveLen(2))
						cniWin := test.GetContainer(dsWin.Spec.Template.Spec.InitContainers, "install-cni")
						Expect(cniWin).ToNot(BeNil())
						Expect(cniWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s:%s",
								components.ComponentTigeraCNIWindows.Image,
								components.ComponentTigeraCNIWindows.Version)))
					} else {
						dsWin := appsv1.DaemonSet{
							TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      common.WindowsDaemonSetName,
								Namespace: common.CalicoNamespace,
							},
						}
						Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
					}
				})
				It("should use images from imageset", func() {
					imageSet := &operator.ImageSet{
						ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
						Spec: operator.ImageSetSpec{
							Images: []operator.Image{
								{Image: "tigera/kube-controllers", Digest: "sha256:tigerakubecontrollerhash"},
								{Image: "tigera/typha", Digest: "sha256:tigeratyphahash"},
								{Image: "tigera/cnx-node", Digest: "sha256:tigeracnxnodehash"},
								{Image: "tigera/cni", Digest: "sha256:tigeracnihash"},
								{Image: "tigera/pod2daemon-flexvol", Digest: "sha256:calicoflexvolhash"},
								{Image: "tigera/key-cert-provisioner", Digest: "sha256:calicocsrinithash"},
								{Image: "tigera/csi", Digest: "sha256:calicocsihash"},
								{Image: "tigera/node-driver-registrar", Digest: "sha256:caliconodedriverregistrarhash"},
							},
						},
					}
					if enableWindows {
						imageSet.Spec.Images = append(imageSet.Spec.Images, []operator.Image{
							{Image: "tigera/cnx-node-windows", Digest: "sha256:tigeracnxnodewindowshash"},
							{Image: "tigera/cni-windows", Digest: "sha256:tigeracniwindowshash"},
						}...)
					}
					Expect(c.Create(ctx, imageSet)).ToNot(HaveOccurred())

					_, err := r.Reconcile(ctx, reconcile.Request{})
					Expect(err).ShouldNot(HaveOccurred())

					if enableWindows {
						dsWin := appsv1.DaemonSet{
							TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      common.WindowsDaemonSetName,
								Namespace: common.CalicoNamespace,
							},
						}
						Expect(test.GetResource(c, &dsWin)).To(BeNil())
						Expect(dsWin.Spec.Template.Spec.Containers).To(HaveLen(3))
						nodeWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "node")
						Expect(nodeWin).ToNot(BeNil())
						Expect(nodeWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s@%s",
								components.ComponentTigeraNodeWindows.Image,
								"sha256:tigeracnxnodewindowshash")))
						felixWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "felix")
						Expect(felixWin).ToNot(BeNil())
						Expect(felixWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s@%s",
								components.ComponentTigeraNodeWindows.Image,
								"sha256:tigeracnxnodewindowshash")))
						confdWin := test.GetContainer(dsWin.Spec.Template.Spec.Containers, "confd")
						Expect(confdWin).ToNot(BeNil())
						Expect(confdWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s@%s",
								components.ComponentTigeraNodeWindows.Image,
								"sha256:tigeracnxnodewindowshash")))
						Expect(dsWin.Spec.Template.Spec.InitContainers).To(HaveLen(2))
						cniWin := test.GetContainer(dsWin.Spec.Template.Spec.InitContainers, "install-cni")
						Expect(cniWin).ToNot(BeNil())
						Expect(cniWin.Image).To(Equal(
							fmt.Sprintf("some.registry.org/%s@%s",
								components.ComponentTigeraCNIWindows.Image,
								"sha256:tigeracniwindowshash")))
					} else {
						dsWin := appsv1.DaemonSet{
							TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      common.WindowsDaemonSetName,
								Namespace: common.CalicoNamespace,
							},
						}
						Expect(test.GetResource(c, &dsWin)).To(HaveOccurred())
					}
				})
			})
		}
	})
})
