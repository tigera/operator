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

package installation

import (
	"bytes"
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/test"
)

var errMismatchedError = fmt.Errorf("installation spec.kubernetesProvider 'DockerEnterprise' does not match auto-detected value 'OpenShift'")

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

func (f *fakeNamespaceMigration) CleanupMigration(ctx context.Context, log logr.Logger) error {
	return nil
}

var _ = Describe("Testing core-controller installation", func() {
	var c client.Client
	var cs *kfake.Clientset
	var ctx context.Context
	var cancel context.CancelFunc
	var r ReconcileInstallation
	var cr *operator.Installation
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus

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
		table.Entry("Different detected/configured provider", operator.ProviderOpenShift, operator.ProviderDockerEE, errMismatchedError),
		table.Entry("Same detected/configured managed provider", operator.ProviderEKS, operator.ProviderEKS, nil),
	)

	notReady := &utils.ReadyFlag{}
	ready := &utils.ReadyFlag{}
	ready.MarkAsReady()

	Context("image reconciliation tests", func() {
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
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
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
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				config:               nil, // there is no fake for config
				client:               c,
				scheme:               scheme,
				autoDetectedProvider: operator.ProviderNone,
				status:               mockStatus,
				typhaAutoscaler:      newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:   &fakeNamespaceMigration{},
				enterpriseCRDsExist:  true,
				migrationChecked:     true,
				tierWatchReady:       ready,
				newComponentHandler:  utils.NewComponentHandler,
			}

			r.typhaAutoscaler.start(ctx)
			certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())

			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

			// We start off with a 'standard' installation, with nothing special
			Expect(c.Create(
				ctx,
				&operator.Installation{
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
				})).NotTo(HaveOccurred())

			// In most clusters, the IP pool controller is responsible for creating IP pools. The Installation controller waits for this,
			// so we need to create those pools here.
			pool := crdv1.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: crdv1.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    crdv1.VXLANModeAlways,
				},
			}
			Expect(c.Create(ctx, &pool)).NotTo(HaveOccurred())
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
			csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.TyphaTLSSecretName))
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraCSRInitContainer.Image,
					components.ComponentTigeraCSRInitContainer.Version)))

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
					components.ComponentTigeraFlexVolume.Image,
					components.ComponentTigeraFlexVolume.Version)))
			cni := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
			Expect(cni).ToNot(BeNil())
			Expect(cni.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraCNI.Image,
					components.ComponentTigeraCNI.Version)))
			csrinit = test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodeTLSSecretName))
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraCSRInitContainer.Image,
					components.ComponentTigeraCSRInitContainer.Version)))
			csrinit2 := test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodePrometheusTLSServerSecret))
			Expect(csrinit2).ToNot(BeNil())
			Expect(csrinit2.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentTigeraCSRInitContainer.Image,
					components.ComponentTigeraCSRInitContainer.Version)))
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
			Expect(c.Create(ctx, imageSet)).ToNot(HaveOccurred())

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
			csrinit := test.GetContainer(d.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.TyphaTLSSecretName))
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraCSRInitContainer.Image,
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
					components.ComponentTigeraFlexVolume.Image,
					"sha256:calicoflexvolhash")))
			cni := test.GetContainer(ds.Spec.Template.Spec.InitContainers, "install-cni")
			Expect(cni).ToNot(BeNil())
			Expect(cni.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraCNI.Image,
					"sha256:tigeracnihash")))
			csrinit = test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodeTLSSecretName))
			Expect(csrinit).ToNot(BeNil())
			Expect(csrinit.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraCSRInitContainer.Image,
					"sha256:calicocsrinithash")))
			csrinit2 := test.GetContainer(ds.Spec.Template.Spec.InitContainers, fmt.Sprintf("%s-key-cert-provisioner", render.NodePrometheusTLSServerSecret))
			Expect(csrinit2).ToNot(BeNil())
			Expect(csrinit2.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentTigeraCSRInitContainer.Image,
					"sha256:calicocsrinithash")))

			inst := operator.Installation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &inst)).To(BeNil())
			Expect(inst.Status.ImageSet).To(Equal("enterprise-" + components.EnterpriseRelease))
		})

		It("should error if correct variant imageset with wrong version", func() {
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()
			imageSet := &operator.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-wrong"},
			}
			Expect(c.Create(ctx, imageSet)).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
		})
		It("should succeed if other variant imageset exists", func() {
			imageSet := &operator.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "calico-versiondoesntmatter"},
			}
			Expect(c.Create(ctx, imageSet)).ToNot(HaveOccurred())

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
		})

		It("should update version", func() {
			instance := &operator.Installation{}
			Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, instance)).NotTo(HaveOccurred())

			instance.Status.CalicoVersion = "v3.14"
			Expect(c.Update(ctx, instance)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, instance)).NotTo(HaveOccurred())
			Expect(instance.Status.CalicoVersion).To(Equal(components.EnterpriseRelease))
			Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, instance)).NotTo(HaveOccurred())

			instance.Status.CalicoVersion = "v3.23"
			instance.Spec.Variant = operator.Calico
			Expect(c.Update(ctx, instance)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, instance)).NotTo(HaveOccurred())
			Expect(instance.Status.CalicoVersion).To(Equal(components.CalicoRelease))
		})
	})

	Context("Docker Enterprise defaults", func() {
		It("Sets the default ipv4 autodetection method to skipInterface", func() {
			installation := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderDockerEE,
				},
			}
			currentPools := crdv1.IPPoolList{}
			currentPools.Items = append(currentPools.Items, crdv1.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: crdv1.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    crdv1.VXLANModeAlways,
				},
			})
			Expect(MergeAndFillDefaults(installation, nil, &currentPools)).To(BeNil())
			Expect(installation.Spec.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface).Should(Equal("^br-.*"))
			Expect(installation.Spec.CalicoNetwork.NodeAddressAutodetectionV6).Should(BeNil())
		})
	})

	table.DescribeTable("test Node Affinity defaults",
		func(expected bool, provider operator.Provider, result []corev1.NodeSelectorTerm) {
			installation := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: provider,
				},
			}
			Expect(MergeAndFillDefaults(installation, nil, nil)).To(BeNil())
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
			[]corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{
					{
						Key:      "type",
						Operator: corev1.NodeSelectorOpNotIn,
						Values:   []string{"virtual-node"},
					},
					{
						Key:      "kubernetes.azure.com/cluster",
						Operator: corev1.NodeSelectorOpExists,
					},
				},
			}},
		),
		table.Entry("Expect no default value for DockerEE provider",
			false,
			operator.ProviderDockerEE,
			[]corev1.NodeSelectorTerm{},
		),
	)

	Context("management cluster exists", func() {
		var expectedDNSNames []string
		var certificateManager certificatemanager.CertificateManager

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
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
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
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				config:               nil, // there is no fake for config
				client:               c,
				scheme:               scheme,
				autoDetectedProvider: operator.ProviderNone,
				status:               mockStatus,
				typhaAutoscaler:      newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:   &fakeNamespaceMigration{},
				amazonCRDExists:      true,
				enterpriseCRDsExist:  true,
				migrationChecked:     true,
				clusterDomain:        dns.DefaultClusterDomain,
				tierWatchReady:       ready,
				newComponentHandler:  utils.NewComponentHandler,
			}
			r.typhaAutoscaler.start(ctx)

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

			// In most clusters, the IP pool controller is responsible for creating IP pools. The Installation controller waits for this,
			// so we need to create those pools here.
			pool := crdv1.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: crdv1.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    crdv1.VXLANModeAlways,
				},
			}
			Expect(c.Create(ctx, &pool)).NotTo(HaveOccurred())

			// Configure ourselves as a management cluster.
			Expect(c.Create(ctx, &operator.ManagementCluster{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultTSEEInstanceKey.Name}})).NotTo(HaveOccurred())

			expectedDNSNames = dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, dns.DefaultClusterDomain)
			expectedDNSNames = append(expectedDNSNames, "localhost")
			var err error
			certificateManager, err = certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		It("should create node and typha TLS cert secrets if not provided and add OwnerReference to those", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			cfgMap := &corev1.ConfigMap{}

			Expect(c.Get(ctx, client.ObjectKey{Name: "tigera-ca-bundle", Namespace: common.CalicoNamespace}, cfgMap)).ShouldNot(HaveOccurred())
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
				render.NodeTLSSecretName, common.OperatorNamespace(), "key.key",
				"cert.crt", tls.DefaultCertificateDuration, nil, render.FelixCommonName,
			)
			nodeSecret.Data[render.CommonName] = []byte(render.FelixCommonName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(c.Create(ctx, nodeSecret)).NotTo(HaveOccurred())

			typhaSecret, err := secret.CreateTLSSecret(testCA,
				render.TyphaTLSSecretName, common.OperatorNamespace(), "key.key",
				"cert.crt", tls.DefaultCertificateDuration, nil, render.TyphaCommonName,
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
		createNodeDaemonSet := func() {
			Expect(c.Create(
				ctx,
				&appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
					Spec: appsv1.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: render.CalicoNodeObjectName}},
							},
						},
					},
				})).NotTo(HaveOccurred())
		}

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
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
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
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)

			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				config:               nil, // there is no fake for config
				client:               c,
				scheme:               scheme,
				autoDetectedProvider: operator.ProviderNone,
				status:               mockStatus,
				typhaAutoscaler:      newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:   &fakeNamespaceMigration{},
				amazonCRDExists:      true,
				enterpriseCRDsExist:  true,
				migrationChecked:     true,
				tierWatchReady:       ready,
				newComponentHandler:  utils.NewComponentHandler,
			}

			r.typhaAutoscaler.start(ctx)
			ca, err := tls.MakeCA("test")
			Expect(err).NotTo(HaveOccurred())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block

			// In most clusters, the IP pool controller is responsible for creating IP pools. The Installation controller waits for this,
			// so we need to create those pools here.
			pool := crdv1.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: crdv1.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    crdv1.VXLANModeAlways,
				},
			}
			Expect(c.Create(ctx, &pool)).NotTo(HaveOccurred())

			// We start off with a 'standard' installation, with nothing special
			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:               operator.TigeraSecureEnterprise,
					Registry:              "some.registry.org/",
					CertificateManagement: &operator.CertificateManagement{CACert: cert},
				},
				Status: operator.InstallationStatus{},
			}
			certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		It("should Reconcile with default config", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// We should get a felix configuration with the health port defaulted (but nothing else).
			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.HealthPort).NotTo(BeNil())
			Expect(*fc.Spec.HealthPort).To(Equal(9099))

			// This is only set on EKS / GKE.
			Expect(fc.Spec.RouteTableRange).To(BeNil())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("false"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeFalse())
		})

		It("should set BPFEnabled to ture on FelixConfiguration if BPF is enabled on installation", func() {
			createNodeDaemonSet()

			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("true"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())
		})

		It("should set BPFEnabled to false on FelixConfiguration if BPF is disabled on installation", func() {
			createNodeDaemonSet()

			// Enable BPF.
			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("true"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())

			// Set dataplane to IPTables.
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			network = operator.LinuxDataplaneIptables
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Update(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc = &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("false"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeFalse())
		})

		It("should set BPFEnabled on FelixConfiguration if FELIX_BPFENABLED Env var is set by old version of operator", func() {
			createNodeDaemonSet()

			ds := &appsv1.DaemonSet{}
			err := c.Get(ctx,
				types.NamespacedName{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
				ds)
			Expect(err).NotTo(HaveOccurred())
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
				{Name: "FELIX_BPFENABLED", Value: "true", ValueFrom: nil},
			}
			Expect(c.Update(ctx, ds)).NotTo(HaveOccurred())

			network := operator.LinuxDataplaneBPF
			cr.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{LinuxDataplane: &network}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())

			// Should set correct annoation and BPFEnabled field.
			Expect(fc.Annotations).NotTo(BeNil())
			Expect(fc.Annotations[render.BPFOperatorAnnotation]).To(Equal("true"))
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(BeTrue())
		})

		It("generates FelixConfiguration with correct DNS service for Rancher", func() {
			cr.Spec.KubernetesProvider = operator.ProviderRKE2
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// We should get a felix configuration with Rancher's DNS service.
			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.DNSTrustedServers).NotTo(BeNil())
			Expect(*fc.Spec.DNSTrustedServers).To(ConsistOf("k8s-service:kube-system/rke2-coredns-rke2-coredns"))
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
			Expect(err).ShouldNot(HaveOccurred())
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
			Expect(err).ShouldNot(HaveOccurred())
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

		It("should Reconcile with FelixConfig natPortRange set", func() {
			fc := &crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: crdv1.FelixConfigurationSpec{
					NATPortRange: &numorstring.Port{MinPort: 15, MaxPort: 55},
				},
			}
			err := c.Create(ctx, fc)
			Expect(err).ShouldNot(HaveOccurred())
			cr.Spec.CNI = &operator.CNISpec{Type: operator.PluginAmazonVPC}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Check that FelixConfiguration has not changed
			fc = &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.NATPortRange).NotTo(BeNil())
			Expect(*fc.Spec.NATPortRange).To(Equal(numorstring.Port{MinPort: 15, MaxPort: 55}))
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

		It("should reconcile with creating new installation status condition with one item", func() {
			generation := int64(2)
			ts := &operator.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Spec:       operator.TigeraStatusSpec{},
				Status: operator.TigeraStatusStatus{
					Conditions: []operator.TigeraStatusCondition{
						{
							Type:               operator.ComponentAvailable,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "calico",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Status.Conditions).To(HaveLen(1))

			Expect(cr.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(cr.Status.Conditions[0].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[0].Reason).To(Equal(string(operator.AllObjectsAvailable)))
			Expect(cr.Status.Conditions[0].Message).To(Equal("All Objects are available"))
		})

		It("should reconcile with Empty tigera status condition", func() {
			ts := &operator.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Spec:       operator.TigeraStatusSpec{},
				Status:     operator.TigeraStatusStatus{},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "calico",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Status.Conditions).To(HaveLen(0))
		})

		It("should reconcile with creating new installation status with multiple conditions as true", func() {
			generation := int64(2)
			ts := &operator.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Spec:       operator.TigeraStatusSpec{},
				Status: operator.TigeraStatusStatus{
					Conditions: []operator.TigeraStatusCondition{
						{
							Type:               operator.ComponentAvailable,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operator.ComponentProgressing,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.ResourceNotReady),
							Message:            "Progressing Installation.operator.tigera.io",
							ObservedGeneration: generation,
						},
						{
							Type:               operator.ComponentDegraded,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.ResourceUpdateError),
							Message:            "Error resolving ImageSet for components",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "calico",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Status.Conditions).To(HaveLen(3))

			Expect(cr.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(cr.Status.Conditions[0].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[0].Reason).To(Equal(string(operator.AllObjectsAvailable)))
			Expect(cr.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(cr.Status.Conditions[0].ObservedGeneration).To(Equal(int64(2)))

			Expect(cr.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(cr.Status.Conditions[1].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[1].Reason).To(Equal(string(operator.ResourceNotReady)))
			Expect(cr.Status.Conditions[1].Message).To(Equal("Progressing Installation.operator.tigera.io"))
			Expect(cr.Status.Conditions[1].ObservedGeneration).To(Equal(int64(2)))

			Expect(cr.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(cr.Status.Conditions[2].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[2].Reason).To(Equal(string(operator.ResourceUpdateError)))
			Expect(cr.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
			Expect(cr.Status.Conditions[2].ObservedGeneration).To(Equal(int64(2)))
		})

		It("should reconcile with Existing conditions and toggle Available to true & others to false", func() {
			generation := int64(2)
			ts := &operator.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Spec:       operator.TigeraStatusSpec{},
				Status: operator.TigeraStatusStatus{
					Conditions: []operator.TigeraStatusCondition{
						{
							Type:               operator.ComponentAvailable,
							Status:             operator.ConditionTrue,
							Reason:             string(operator.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operator.ComponentProgressing,
							Status:             operator.ConditionFalse,
							Reason:             string(operator.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
						{
							Type:               operator.ComponentDegraded,
							Status:             operator.ConditionFalse,
							Reason:             string(operator.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			cr.Status.Conditions = []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionStatus(operator.ConditionFalse),
					Reason:             string(operator.NotApplicable),
					Message:            "Not Applicable",
					LastTransitionTime: metav1.NewTime(time.Now()),
				},
				{
					Type:               "Progressing",
					Status:             metav1.ConditionStatus(operator.ConditionTrue),
					LastTransitionTime: metav1.NewTime(time.Now()),
					Reason:             string(operator.ResourceNotReady),
					Message:            "All resources are not available",
				},
				{
					Type:               "Degraded",
					Status:             metav1.ConditionStatus(operator.ConditionFalse),
					Reason:             string(operator.NotApplicable),
					Message:            "Not Applicable",
					LastTransitionTime: metav1.NewTime(time.Now()),
				},
			}
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "calico",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())

			err = c.Get(ctx, types.NamespacedName{Name: "default"}, cr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cr.Status.Conditions).To(HaveLen(3))

			Expect(cr.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(cr.Status.Conditions[0].Status)).To(Equal(string(operator.ConditionTrue)))
			Expect(cr.Status.Conditions[0].Reason).To(Equal(string(operator.AllObjectsAvailable)))
			Expect(cr.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(cr.Status.Conditions[0].ObservedGeneration).To(Equal(int64(2)))

			Expect(cr.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(cr.Status.Conditions[1].Status)).To(Equal(string(operator.ConditionFalse)))
			Expect(cr.Status.Conditions[1].Reason).To(Equal(string(operator.NotApplicable)))
			Expect(cr.Status.Conditions[1].Message).To(Equal("Not Applicable"))
			Expect(cr.Status.Conditions[1].ObservedGeneration).To(Equal(int64(2)))

			Expect(cr.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(cr.Status.Conditions[2].Status)).To(Equal(string(operator.ConditionFalse)))
			Expect(cr.Status.Conditions[2].Reason).To(Equal(string(operator.NotApplicable)))
			Expect(cr.Status.Conditions[2].Message).To(Equal("Not Applicable"))
			Expect(cr.Status.Conditions[2].ObservedGeneration).To(Equal(int64(2)))
		})

		It("should render allow-tigera policy when tier and tier watch are ready", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(2))
			Expect(policies.Items[0].Name).To(Equal("allow-tigera.default-deny"))
			Expect(policies.Items[1].Name).To(Equal("allow-tigera.kube-controller-access"))
		})

		It("should omit allow-tigera policy and not degrade when tier is not ready", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			Expect(c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should omit allow-tigera policy and not degrade when tier watch is not ready", func() {
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			r.tierWatchReady = notReady

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should omit allow-tigera policy and not degrade when installation is calico", func() {
			cr.Spec.Variant = operator.Calico
			cr.Status.Variant = operator.Calico
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			r.enterpriseCRDsExist = false
			Expect(c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			policies := v3.NetworkPolicyList{}
			Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
			Expect(policies.Items).To(HaveLen(0))
		})
	})

	Context("Using EKS networking", func() {
		var certificateManager certificatemanager.CertificateManager

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
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
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
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = ReconcileInstallation{
				config:               nil, // there is no fake for config
				client:               c,
				scheme:               scheme,
				autoDetectedProvider: operator.ProviderNone,
				status:               mockStatus,
				typhaAutoscaler:      newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:   &fakeNamespaceMigration{},
				amazonCRDExists:      true,
				enterpriseCRDsExist:  true,
				migrationChecked:     true,
				clusterDomain:        dns.DefaultClusterDomain,
				tierWatchReady:       ready,
				newComponentHandler:  utils.NewComponentHandler,
			}
			r.typhaAutoscaler.start(ctx)

			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:            operator.TigeraSecureEnterprise,
					Registry:           "some.registry.org/",
					KubernetesProvider: operator.ProviderEKS,
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
						IPAM: &operator.IPAMSpec{
							Type: operator.IPAMPluginAmazonVPC,
						},
					},
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
			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

			// NOTE: We do NOT create an IP pool for this test suite, as it is not needed for the Amazon VPC plugin.

			var err error
			certificateManager, err = certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		It("should reconcile successfully and create resources", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			secret := &corev1.Secret{}
			cfgMap := &corev1.ConfigMap{}

			Expect(c.Get(ctx, client.ObjectKey{Name: "tigera-ca-bundle", Namespace: common.CalicoNamespace}, cfgMap)).ShouldNot(HaveOccurred())
			Expect(cfgMap.GetOwnerReferences()).To(HaveLen(1))

			Expect(c.Get(ctx, client.ObjectKey{Name: render.NodeTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))

			Expect(c.Get(ctx, client.ObjectKey{Name: render.TyphaTLSSecretName, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
			Expect(secret.GetOwnerReferences()).To(HaveLen(1))
		})
	})

	Context("with a fake component handler", func() {
		var componentHandler *fakeComponentHandler

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
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
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
			mockStatus.On("SetMetaData", mock.Anything).Return()

			// Create the indexer and informer used by the typhaAutoscaler
			nlw := test.NewNodeListWatch(cs)
			nodeIndexInformer := cache.NewSharedIndexInformer(nlw, &corev1.Node{}, 0, cache.Indexers{})

			go nodeIndexInformer.Run(ctx.Done())
			for nodeIndexInformer.HasSynced() {
				time.Sleep(100 * time.Millisecond)
			}

			componentHandler = newFakeComponentHandler()
			r = ReconcileInstallation{
				config:               nil, // there is no fake for config
				client:               c,
				scheme:               scheme,
				autoDetectedProvider: operator.ProviderNone,
				status:               mockStatus,
				typhaAutoscaler:      newTyphaAutoscaler(cs, nodeIndexInformer, test.NewTyphaListWatch(cs), mockStatus),
				namespaceMigration:   &fakeNamespaceMigration{},
				enterpriseCRDsExist:  true,
				migrationChecked:     true,
				tierWatchReady:       ready,
				newComponentHandler: func(logr.Logger, client.Client, *runtime.Scheme, metav1.Object) utils.ComponentHandler {
					return componentHandler
				},
			}

			r.typhaAutoscaler.start(ctx)
			certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
			Expect(err).NotTo(HaveOccurred())

			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())

			// We start off with a 'standard' installation, with nothing special
			Expect(c.Create(
				ctx,
				&operator.Installation{
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
				})).NotTo(HaveOccurred())

			// In most clusters, the IP pool controller is responsible for creating IP pools. The Installation controller waits for this,
			// so we need to create those pools here.
			pool := crdv1.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "default-pool-v4"},
				Spec: crdv1.IPPoolSpec{
					CIDR:         "192.168.0.0/16",
					NATOutgoing:  true,
					BlockSize:    26,
					NodeSelector: "all()",
					VXLANMode:    crdv1.VXLANModeAlways,
				},
			}
			Expect(c.Create(ctx, &pool)).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		// This test ensures that all resources with the CNIFinalizer applied to them are also returned by
		// render.CNIPluginFinalizedObjects.
		It("should have the correct number of resources with CNIFinalizer", func() {
			// Trigger a reconcile.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Review the resources that were created to count the resources with a CNIFinalizer set.
			numCreated := 0
			for _, o := range componentHandler.objectsToCreate {
				for _, f := range o.GetFinalizers() {
					if f == render.CNIFinalizer {
						numCreated++
						break
					}
				}
			}
			Expect(numCreated).To(Equal(len(render.CNIPluginFinalizedObjects())))
		})
	})
})

func newFakeComponentHandler() *fakeComponentHandler {
	return &fakeComponentHandler{
		objectsToCreate: make([]client.Object, 0),
		objectsToDelete: make([]client.Object, 0),
	}
}

type fakeComponentHandler struct {
	objectsToCreate []client.Object
	objectsToDelete []client.Object
}

func (f *fakeComponentHandler) CreateOrUpdateOrDelete(ctx context.Context, component render.Component, _ status.StatusManager) error {
	c, d := component.Objects()
	f.objectsToCreate = append(f.objectsToCreate, c...)
	f.objectsToDelete = append(f.objectsToDelete, d...)
	return nil
}
