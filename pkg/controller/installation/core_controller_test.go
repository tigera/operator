// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

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
	"bytes"
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	kfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	osconfigv1 "github.com/openshift/api/config/v1"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/installation/windows"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/test"
)

var mismatchedError = fmt.Errorf("Installation spec.kubernetesProvider 'DockerEnterprise' does not match auto-detected value 'OpenShift'")

type fakeNamespaceMigration struct{}

func (f *fakeNamespaceMigration) NeedsCoreNamespaceMigration(ctx context.Context) (bool, error) {
	return false, nil
}
func (f *fakeNamespaceMigration) Run(ctx context.Context, log logr.Logger) error {
	return nil
}
func (f *fakeNamespaceMigration) NeedCleanup() bool {
	return false
}
func (f *fakeNamespaceMigration) CleanupMigration(ctx context.Context) error {
	return nil
}

var _ = Describe("Testing core-controller installation", func() {

	table.DescribeTable("checking rendering configuration",
		func(detectedProvider, configuredProvider operator.Provider, expectedErr error) {
			configuredInstallation := &operator.Installation{}
			configuredInstallation.Spec.KubernetesProvider = configuredProvider

			err := mergeProvider(configuredInstallation, detectedProvider)
			if expectedErr == nil {
				Expect(err).To(BeNil())
				Expect(configuredInstallation.Spec.KubernetesProvider).To(Equal(detectedProvider))
			} else {
				Expect(err).To(Equal(expectedErr))
			}
		},
		table.Entry("Same detected/configured provider", operator.ProviderOpenShift, operator.ProviderOpenShift, nil),
		table.Entry("Different detected/configured provider", operator.ProviderOpenShift, operator.ProviderDockerEE, mismatchedError),
		table.Entry("Same detected/configured managed provider", operator.ProviderEKS, operator.ProviderEKS, nil),
	)

	table.DescribeTable("test cidrWithinCidr function",
		func(CIDR, pool string, expectedResult bool) {
			if expectedResult {
				Expect(cidrWithinCidr(CIDR, pool)).To(BeTrue(), "Expected pool %s to be within CIDR %s", pool, CIDR)
			} else {
				Expect(cidrWithinCidr(CIDR, pool)).To(BeFalse(), "Expected pool %s to not be within CIDR %s", pool, CIDR)
			}
		},

		table.Entry("Default as CIDR and pool", "192.168.0.0/16", "192.168.0.0/16", true),
		table.Entry("Pool larger than CIDR should fail", "192.168.0.0/16", "192.168.0.0/15", false),
		table.Entry("Pool larger than CIDR should fail", "192.168.2.0/24", "192.168.0.0/16", false),
		table.Entry("Non overlapping CIDR and pool should fail", "192.168.0.0/16", "172.168.0.0/16", false),
		table.Entry("CIDR with smaller pool", "192.168.0.0/16", "192.168.2.0/24", true),
		table.Entry("IPv6 matching CIDR and pool", "fd00:1234::/32", "fd00:1234::/32", true),
		table.Entry("IPv6 Pool larger than CIDR should fail", "fd00:1234::/32", "fd00:1234::/31", false),
		table.Entry("IPv6 Pool larger than CIDR should fail", "fd00:1234:5600::/40", "fd00:1234::/32", false),
		table.Entry("IPv6 Non overlapping CIDR and pool should fail", "fd00:1234::/32", "fd00:5678::/32", false),
		table.Entry("IPv6 CIDR with smaller pool", "fd00:1234::/32", "fd00:1234:5600::/40", true),
	)
	var defaultMTU int32 = 1440
	var twentySix int32 = 26
	var hpEnabled operator.HostPortsType = operator.HostPortsEnabled
	var hpDisabled operator.HostPortsType = operator.HostPortsDisabled
	table.DescribeTable("Installation and Openshift should be merged and defaulted by mergeAndFillDefaults",
		func(i *operator.Installation, on *osconfigv1.Network, expectSuccess bool, calicoNet *operator.CalicoNetworkSpec) {
			if expectSuccess {
				Expect(mergeAndFillDefaults(i, on, nil, nil)).To(BeNil())
			} else {
				Expect(mergeAndFillDefaults(i, on, nil, nil)).ToNot(BeNil())
				return
			}

			if calicoNet == nil {
				Expect(i.Spec.CalicoNetwork).To(BeNil())
				return
			}
			if calicoNet.IPPools == nil {
				Expect(i.Spec.CalicoNetwork).To(BeNil())
				return
			}
			if len(calicoNet.IPPools) == 0 {
				Expect(i.Spec.CalicoNetwork.IPPools).To(HaveLen(0))
				return
			}
			Expect(i.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
			pool := i.Spec.CalicoNetwork.IPPools[0]
			pExpect := calicoNet.IPPools[0]
			Expect(pool).To(Equal(pExpect))
			Expect(i.Spec.CalicoNetwork.HostPorts).To(Equal(calicoNet.HostPorts))
		},

		table.Entry("Empty config (with OpenShift) defaults IPPool", &operator.Installation{},
			&osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "192.168.0.0/16"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "192.168.0.0/16",
						Encapsulation: "IPIP",
						NATOutgoing:   "Enabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("Openshift only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "10.0.0.0/8",
						Encapsulation: "IPIP",
						NATOutgoing:   "Enabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("CIDR specified from OpenShift config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							operator.IPPool{
								CIDR:          "10.0.0.0/24",
								Encapsulation: "VXLAN",
								NATOutgoing:   "Disabled",
							},
						},
					},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "10.0.0.0/24",
						Encapsulation: "VXLAN",
						NATOutgoing:   "Disabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("Failure when IPPool is smaller than OpenShift Network",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							operator.IPPool{
								CIDR:          "10.0.0.0/16",
								Encapsulation: "VXLAN",
								NATOutgoing:   "Disabled",
							},
						},
					},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/24"},
					},
				},
			}, false, nil),
		table.Entry("Empty IPPool list results in no IPPool with OpenShift",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{},
					},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools:   []operator.IPPool{},
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("Normal defaults with no IPPools",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			}, nil, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "192.168.0.0/16",
						Encapsulation: "IPIP",
						NATOutgoing:   "Enabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("HostPorts disabled",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						HostPorts: &hpDisabled,
					},
				},
			}, nil, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "192.168.0.0/16",
						Encapsulation: "IPIP",
						NATOutgoing:   "Enabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
				MTU:       &defaultMTU,
				HostPorts: &hpDisabled,
			}),
	)
	Context("image reconciliation tests", func() {
		var c client.Client
		var cs *kfake.Clientset
		var ctx context.Context
		var cancel context.CancelFunc
		var r ReconcileInstallation
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

			// Create a client that will have a crud interface of k8s objects.
			c = fake.NewFakeClientWithScheme(scheme)
			ctx, cancel = context.WithCancel(context.Background())

			// Create a fake clientset for the autoscaler.
			var replicas int32 = 1
			objs := []runtime.Object{
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
					Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
				},
			}
			cs = kfake.NewSimpleClientset(objs...)

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

			// Create the indexer and informer shared by the typhaAutoscaler and
			// calicoWindowsUpgrader.
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			syncPeriodOption := windows.CalicoWindowsUpgraderSyncPeriod(2 * time.Second)

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				config:                nil, // there is no fake for config
				client:                c,
				scheme:                scheme,
				autoDetectedProvider:  operator.ProviderNone,
				status:                mockStatus,
				typhaAutoscaler:       newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				calicoWindowsUpgrader: windows.NewCalicoWindowsUpgrader(cs, c, nodeIndexInformer, mockStatus, syncPeriodOption),
				namespaceMigration:    &fakeNamespaceMigration{},
				amazonCRDExists:       true,
				enterpriseCRDsExist:   true,
				migrationChecked:      true,
			}

			r.typhaAutoscaler.start(ctx)
			r.calicoWindowsUpgrader.Start(ctx)

			// We start off with a 'standard' installation, with nothing special
			Expect(c.Create(
				ctx,
				&operator.Installation{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec: operator.InstallationSpec{
						Variant:               operator.TigeraSecureEnterprise,
						Registry:              "some.registry.org/",
						CertificateManagement: &operator.CertificateManagement{},
					},
					Status: operator.InstallationStatus{
						Variant: operator.TigeraSecureEnterprise,
						Computed: &operator.InstallationSpec{
							Registry: "my-reg",
							// The test is provider agnostic.
							KubernetesProvider: operator.ProviderNone,
						},
					},
				})).NotTo(HaveOccurred())
		})
		AfterEach(func() {
			cancel()
		})

		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-kube-controllers",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-kube-controllers")
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraKubeControllers.Image,
					components.ComponentTigeraKubeControllers.Version)))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      common.TyphaDeploymentName,
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			typha := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-typha")
			Expect(typha).ToNot(BeNil())
			Expect(typha.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraTypha.Image,
					components.ComponentTigeraTypha.Version)))
			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, render.CSRInitContainerName)
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentCSRInitContainer.Image,
					components.ComponentCSRInitContainer.Version)))

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      common.NodeDaemonSetName,
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			node := test.GetContainer(ds.Spec.Template.Spec.Containers, "calico-node")
			Expect(node).ToNot(BeNil())
			Expect(node.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraNode.Image,
					components.ComponentTigeraNode.Version)))
			Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(4))
			fv := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")
			Expect(fv).ToNot(BeNil())
			Expect(fv.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentFlexVolume.Image,
					components.ComponentFlexVolume.Version)))
			cni := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
			Expect(cni).ToNot(BeNil())
			Expect(cni.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraCNI.Image,
					components.ComponentTigeraCNI.Version)))
			csrinit = test.GetContainer(ds.Spec.Template.Spec.InitContainers, render.CSRInitContainerName)
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentCSRInitContainer.Image,
					components.ComponentCSRInitContainer.Version)))
			csrinit2 := test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-%s", render.CalicoNodeMetricsService, render.CSRInitContainerName))
			Expect(csrinit2).ToNot(BeNil())
			Expect(csrinit2.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentCSRInitContainer.Image,
					components.ComponentCSRInitContainer.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operator.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operator.ImageSetSpec{
					Images: []operator.Image{
						{Image: "tigera/kube-controllers", Digest: "sha256:tigerakubecontrollerhash"},
						{Image: "tigera/typha", Digest: "sha256:tigeratyphahash"},
						{Image: "tigera/cnx-node", Digest: "sha256:tigeracnxnodehash"},
						{Image: "tigera/cni", Digest: "sha256:tigeracnihash"},
						{Image: "calico/pod2daemon-flexvol", Digest: "sha256:calicoflexvolhash"},
						{Image: "tigera/key-cert-provisioner", Digest: "sha256:calicocsrinithash"},
						{Image: "tigera/calico-windows-upgrade", Digest: "sha256:calicowindowshash"},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-kube-controllers",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-kube-controllers")
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraKubeControllers.Image,
					"sha256:tigerakubecontrollerhash")))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      common.TyphaDeploymentName,
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			typha := test.GetContainer(d.Spec.Template.Spec.Containers, "calico-typha")
			Expect(typha).ToNot(BeNil())
			Expect(typha.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraTypha.Image,
					"sha256:tigeratyphahash")))
			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(1))
			csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, render.CSRInitContainerName)
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentCSRInitContainer.Image,
					"sha256:calicocsrinithash")))

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      common.NodeDaemonSetName,
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			node := test.GetContainer(ds.Spec.Template.Spec.Containers, "calico-node")
			Expect(node).ToNot(BeNil())
			Expect(node.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraNode.Image,
					"sha256:tigeracnxnodehash")))
			Expect(ds.Spec.Template.Spec.InitContainers).To(HaveLen(4))
			fv := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "flexvol-driver")
			Expect(fv).ToNot(BeNil())
			Expect(fv.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentFlexVolume.Image,
					"sha256:calicoflexvolhash")))
			cni := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
			Expect(cni).ToNot(BeNil())
			Expect(cni.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraCNI.Image,
					"sha256:tigeracnihash")))
			csrinit = test.GetContainer(ds.Spec.Template.Spec.InitContainers, render.CSRInitContainerName)
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentCSRInitContainer.Image,
					"sha256:calicocsrinithash")))
			csrinit2 := test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-%s", render.CalicoNodeMetricsService, render.CSRInitContainerName))
			Expect(csrinit2).ToNot(BeNil())
			Expect(csrinit2.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentCSRInitContainer.Image,
					"sha256:calicocsrinithash")))

			inst := operator.Installation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &inst)).To(BeNil())
			Expect(inst.Status.ImageSet).To(Equal("enterprise-" + components.EnterpriseRelease))
		})
	})

	Context("Docker Enterprise defaults", func() {
		It("Sets the default ipv4 autodetection method to skipInterface", func() {
			installation := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderDockerEE,
				},
			}
			Expect(mergeAndFillDefaults(installation, nil, nil, nil)).To(BeNil())
			Expect(installation.Spec.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface).Should(Equal("^br-.*"))
		})
	})

	table.DescribeTable("test Node Affinity defaults",
		func(expected bool, provider operator.Provider, result []v1.NodeSelectorTerm) {
			installation := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: provider,
				},
			}
			Expect(mergeAndFillDefaults(installation, nil, nil, nil)).To(BeNil())
			if expected {
				Expect(installation.Spec.TyphaAffinity).ToNot(BeNil())
				Expect(installation.Spec.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms).Should(Equal(result))
			} else {
				Expect(installation.Spec.TyphaAffinity).To(BeNil())
			}
		},
		table.Entry("AKS provider sets default",
			true,
			operator.ProviderAKS,
			[]v1.NodeSelectorTerm{{
				MatchExpressions: []v1.NodeSelectorRequirement{
					{
						Key:      "type",
						Operator: corev1.NodeSelectorOpNotIn,
						Values:   []string{"virtual-node"},
					},
					{
						Key:      "kubernetes.azure.com/cluster",
						Operator: v1.NodeSelectorOpExists,
					},
				},
			}},
		),
		table.Entry("Expect no default value for DockerEE provider",
			false,
			operator.ProviderDockerEE,
			[]v1.NodeSelectorTerm{},
		),
	)

	Context("management cluster exists", func() {
		var c client.Client
		var cs *kfake.Clientset
		var ctx context.Context
		var cancel context.CancelFunc
		var r ReconcileInstallation
		var cr *operator.Installation

		var scheme *runtime.Scheme
		var mockStatus *status.MockStatus

		var internalManagerTLSSecret *corev1.Secret
		var expectedDNSNames []string

		BeforeEach(func() {
			// The schema contains all objects that should be known to the fake client when the test runs.
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(schedv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(operator.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

			// Create a client that will have a crud interface of k8s objects.
			c = fake.NewFakeClientWithScheme(scheme)
			ctx, cancel = context.WithCancel(context.Background())

			// Create a fake clientset for the autoscaler.
			var replicas int32 = 1
			objs := []runtime.Object{
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
					Spec: appsv1.DeploymentSpec{
						Replicas: &replicas,
					},
				},
			}
			cs = kfake.NewSimpleClientset(objs...)

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
			mockStatus.On("SetWindowsUpgradeStatus", mock.Anything, mock.Anything, mock.Anything, nil)

			// Create the indexer and informer shared by the typhaAutoscaler and
			// calicoWindowsUpgrader.
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			syncPeriodOption := windows.CalicoWindowsUpgraderSyncPeriod(2 * time.Second)

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				config:                nil, // there is no fake for config
				client:                c,
				scheme:                scheme,
				autoDetectedProvider:  operator.ProviderNone,
				status:                mockStatus,
				typhaAutoscaler:       newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				calicoWindowsUpgrader: windows.NewCalicoWindowsUpgrader(cs, c, nodeIndexInformer, mockStatus, syncPeriodOption),
				namespaceMigration:    &fakeNamespaceMigration{},
				amazonCRDExists:       true,
				enterpriseCRDsExist:   true,
				migrationChecked:      true,
				clusterDomain:         dns.DefaultClusterDomain,
			}
			r.typhaAutoscaler.start(ctx)
			r.calicoWindowsUpgrader.Start(ctx)

			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:  operator.TigeraSecureEnterprise,
					Registry: "some.registry.org/",
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
			// We start off with a 'standard' installation, with nothing special
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			Expect(c.Create(
				ctx,
				&operator.ManagementCluster{
					ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name},
				})).NotTo(HaveOccurred())

			internalManagerTLSSecret = &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ManagerInternalTLSSecretName,
					Namespace: common.OperatorNamespace(),
				},
			}

			expectedDNSNames = dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, dns.DefaultClusterDomain)
			expectedDNSNames = append(expectedDNSNames, "localhost")
		})
		AfterEach(func() {
			cancel()
		})

		It("should create an internal manager TLS cert secret", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			dnsNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, dns.DefaultClusterDomain)
			dnsNames = append(dnsNames, "localhost")
			Expect(test.GetResource(c, internalManagerTLSSecret)).To(BeNil())
			test.VerifyCert(internalManagerTLSSecret, render.ManagerInternalSecretKeyName, render.ManagerInternalSecretCertName, dnsNames...)
		})

		It("should replace the internal manager TLS cert secret if its DNS names are invalid", func() {
			// Create a internal manager TLS secret with old DNS name.
			oldSecret, err := secret.CreateTLSSecret(nil,
				render.ManagerInternalTLSSecretName, common.OperatorNamespace(), render.ManagerInternalSecretKeyName,
				render.ManagerInternalSecretCertName, rmeta.DefaultCertificateDuration, nil, "tigera-manager.tigera-manager.svc",
			)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, oldSecret)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			dnsNames := dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, dns.DefaultClusterDomain)
			dnsNames = append(dnsNames, "localhost")
			Expect(test.GetResource(c, internalManagerTLSSecret)).To(BeNil())
			test.VerifyCert(internalManagerTLSSecret, render.ManagerInternalSecretKeyName, render.ManagerInternalSecretCertName, dnsNames...)
		})

		It("should create node and typha TLS cert secrets if not provided and add OwnerReference to those", func() {

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			cfgMap := &corev1.ConfigMap{}

			Expect(c.Get(ctx, client.ObjectKey{Name: render.TyphaCAConfigMapName, Namespace: common.OperatorNamespace()}, cfgMap)).ShouldNot(HaveOccurred())
			Expect(cfgMap.GetOwnerReferences()).To(HaveLen(1))

			Expect(c.Get(ctx, client.ObjectKey{Name: render.NodeTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

			Expect(c.Get(ctx, client.ObjectKey{Name: render.TyphaTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))
		})

		It("should not add OwnerReference to user supplied node and typha certs", func() {

			testCA := test.MakeTestCA("core-test")
			crtContent := &bytes.Buffer{}
			keyContent := &bytes.Buffer{}
			Expect(testCA.Config.WriteCertConfig(crtContent, keyContent)).NotTo(HaveOccurred())

			// Take CA cert and create ConfigMap
			caConfigMap := &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.TyphaCAConfigMapName,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string]string{
					render.TyphaCABundleName: crtContent.String(),
				},
			}
			Expect(c.Create(ctx, caConfigMap)).NotTo(HaveOccurred())

			nodeSecret, err := secret.CreateTLSSecret(testCA,
				render.NodeTLSSecretName, common.OperatorNamespace(), render.TLSSecretKeyName,
				render.TLSSecretCertName, rmeta.DefaultCertificateDuration, nil, render.FelixCommonName,
			)
			nodeSecret.Data[render.CommonName] = []byte(render.FelixCommonName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, nodeSecret)).NotTo(HaveOccurred())

			typhaSecret, err := secret.CreateTLSSecret(testCA,
				render.TyphaTLSSecretName, common.OperatorNamespace(), render.TLSSecretKeyName,
				render.TLSSecretCertName, rmeta.DefaultCertificateDuration, nil, render.TyphaCommonName,
			)
			typhaSecret.Data[render.CommonName] = []byte(render.TyphaCommonName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, typhaSecret)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(test.GetResource(c, nodeSecret)).To(BeNil())
			Expect(nodeSecret.GetOwnerReferences()).To(HaveLen(0))

			Expect(test.GetResource(c, typhaSecret)).To(BeNil())
			Expect(typhaSecret.GetOwnerReferences()).To(HaveLen(0))
		})
	})
	Context("Reconcile tests", func() {
		var c client.Client
		var cs *kfake.Clientset
		var ctx context.Context
		var cancel context.CancelFunc
		var r ReconcileInstallation
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

			// Create a client that will have a crud interface of k8s objects.
			c = fake.NewFakeClientWithScheme(scheme)
			ctx, cancel = context.WithCancel(context.Background())

			// Create a fake clientset for the autoscaler.
			var replicas int32 = 1
			objs := []runtime.Object{
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node2",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&corev1.Node{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node3",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
					Spec: corev1.NodeSpec{},
				},
				&appsv1.Deployment{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
					Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
				},
			}
			cs = kfake.NewSimpleClientset(objs...)

			// Create an object we can use throughout the test to do the core reconcile loops.
			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("AddCertificateSigningRequests", mock.Anything)
			mockStatus.On("ReadyToMonitor")

			// Create the indexer and informer shared by the typhaAutoscaler and
			// calicoWindowsUpgrader.
			nlw := test.NewNodeListWatch(cs)

			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			syncPeriodOption := windows.CalicoWindowsUpgraderSyncPeriod(2 * time.Second)

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				config:                nil, // there is no fake for config
				client:                c,
				scheme:                scheme,
				autoDetectedProvider:  operator.ProviderNone,
				status:                mockStatus,
				typhaAutoscaler:       newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				calicoWindowsUpgrader: windows.NewCalicoWindowsUpgrader(cs, c, nodeIndexInformer, mockStatus, syncPeriodOption),
				namespaceMigration:    &fakeNamespaceMigration{},
				amazonCRDExists:       true,
				enterpriseCRDsExist:   true,
				migrationChecked:      true,
			}

			r.typhaAutoscaler.start(ctx)
			r.calicoWindowsUpgrader.Start(ctx)

			// We start off with a 'standard' installation, with nothing special
			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:               operator.TigeraSecureEnterprise,
					Registry:              "some.registry.org/",
					CertificateManagement: &operator.CertificateManagement{},
				},
			}
		})
		AfterEach(func() {
			cancel()
		})

		It("should Reconcile with default config", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that with non-AWS CNI no FelixConfiguration is created
			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).Should(HaveOccurred())
		})

		It("should Reconcile with AWS CNI config", func() {
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginAmazonVPC}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration is created with RouteTableRange
			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.RouteTableRange).NotTo(BeNil())
			Expect(*fc.Spec.RouteTableRange).To(Equal(crdv1.RouteTableRange{Min: 65, Max: 99}))
		})

		It("should Reconcile with GKE CNI config", func() {
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginGKE}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration is created with RouteTableRange
			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.RouteTableRange).NotTo(BeNil())
			Expect(*fc.Spec.RouteTableRange).To(Equal(crdv1.RouteTableRange{Min: 10, Max: 250}))
		})

		It("should Reconcile with AWS CNI and not change existing FelixConfig", func() {
			fc := &crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: crdv1.FelixConfigurationSpec{
					RouteTableRange:   &crdv1.RouteTableRange{Min: 15, Max: 55},
					LogSeverityScreen: "Error",
				},
			}
			err := c.Create(ctx, fc)
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginAmazonVPC}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration has not changed
			fc = &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.RouteTableRange).NotTo(BeNil())
			Expect(*fc.Spec.RouteTableRange).To(Equal(crdv1.RouteTableRange{Min: 15, Max: 55}))
			Expect(fc.Spec.LogSeverityScreen).To(Equal("Error"))
		})

		It("should Reconcile with AWS CNI and update existing FelixConfig", func() {
			fc := &crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: crdv1.FelixConfigurationSpec{
					LogSeverityScreen: "Error",
				},
			}
			err := c.Create(ctx, fc)
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginAmazonVPC}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration is created with RouteTableRange
			fc = &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.RouteTableRange).NotTo(BeNil())
			Expect(*fc.Spec.RouteTableRange).To(Equal(crdv1.RouteTableRange{Min: 65, Max: 99}))
			Expect(fc.Spec.LogSeverityScreen).To(Equal("Error"))
		})
		It("should Reconcile with GKE and create a resource quota", func() {
			cr.Spec.KubernetesProvider = operator.ProviderGKE
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			rq := corev1.ResourceQuota{
				TypeMeta: metav1.TypeMeta{Kind: "ResourceQuota", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-critical-pods",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &rq)).To(BeNil())
		})

		It("should Reconcile with no active operator ConfigMap", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			cm := corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &cm)).To(BeNil())
			Expect(cm.Data["active-namespace"]).To(Equal("tigera-operator"))
		})
		It("should exit Reconcile when active operator is a different namespace", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{"active-namespace": "other-namespace"},
			})).NotTo(HaveOccurred())

			exited := false
			osExitOverride = func(_ int) { exited = true }
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			Expect(exited).Should(BeTrue())
		})
		It("should not exit Reconcile when active operator is current namespace", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{"active-namespace": "tigera-operator"},
			})).NotTo(HaveOccurred())

			exited := false
			osExitOverride = func(_ int) { exited = false }
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(exited).Should(BeFalse())
			cm := corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &cm)).To(BeNil())
			Expect(cm.Data["active-namespace"]).To(Equal("tigera-operator"))
		})
		It("should not overwrite active-operator CM when it already exists", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{
					"active-namespace": "tigera-operator",
					"extra-dummy":      "dummy-value",
				},
			})).NotTo(HaveOccurred())

			exited := false
			osExitOverride = func(_ int) { exited = false }
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(exited).Should(BeFalse())
			cm := corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "active-operator",
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(c, &cm)).To(BeNil())
			Expect(cm.Data["active-namespace"]).To(Equal("tigera-operator"))
			Expect(cm.Data).To(HaveKey("extra-dummy"))
		})

		Context("calicoWindowsUpgrader", func() {
			BeforeEach(func() {
				// calicoWindowsUpgrader only upgrades nodes on AKS.
				cr.Spec.KubernetesProvider = operator.ProviderAKS
			})

			It("should do nothing if node is up to date", func() {
				cr.Spec.Variant = operator.TigeraSecureEnterprise
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// Create node with current Enterprise version.
				n1 := test.CreateWindowsNode(cs, "windows1", cr.Spec.Variant, components.ComponentTigeraWindows.Version)

				mockStatus.On("SetWindowsUpgradeStatus", []string{}, []string{}, []string{"windows1"}, nil)

				// Node is up to date and should not have changed.
				Consistently(func() error {
					return test.AssertNodesUnchanged(cs, n1)
				}, 10*time.Second, 100*time.Millisecond).Should(BeNil())
			})

			It("should trigger upgrade of out-of-date Calico Windows nodes", func() {
				// Set variant to Calico and set maxUnavailable to 2.
				cr.Spec.Variant = operator.TigeraSecureEnterprise
				two := intstr.FromInt(2)
				cr.Spec.NodeUpdateStrategy = appsv1.DaemonSetUpdateStrategy{
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &two,
					},
				}
				Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				// Create two nodes that should be upgraded to the latest Enterprise version
				// - n1 is running Calico
				// - n2 is running an older Enterprise version
				n1 := test.CreateWindowsNode(cs, "windows1", operator.Calico, "v3.21.999")
				n2 := test.CreateWindowsNode(cs, "windows2", operator.TigeraSecureEnterprise, "v3.11.999")

				mockStatus.On("SetWindowsUpgradeStatus", mock.Anything, mock.Anything, mock.Anything, nil)

				// Ensure that outdated nodes have the new label and taint.
				Eventually(func() error {
					return test.AssertNodesHadUpgradeTriggered(cs, n1, n2)
				}, 10*time.Second).Should(BeNil())

				Eventually(func() bool {
					return mockStatus.WasCalled("SetWindowsUpgradeStatus", mock.Anything, mock.Anything, mock.Anything, nil)
				}, 5*time.Second).Should(BeTrue())

				mockStatus.AssertExpectations(GinkgoT())

				Consistently(func() error {
					return test.AssertNodesHadUpgradeTriggered(cs, n1, n2)
				}, 10*time.Second).Should(BeNil())
			})
		})
	})
})
