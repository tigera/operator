// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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
	"strconv"
	"time"

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"k8s.io/apimachinery/pkg/types"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/test"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Testing bore-controller installation", func() {

	var c client.Client
	var cs *kfake.Clientset
	var ctx context.Context
	var cancel context.CancelFunc
	var r ReconcileInstallation
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus

	ready := &utils.ReadyFlag{}
	ready.MarkAsReady()

	Context("Reconcile tests BPF Upgrade", func() {

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
			}

			r.typhaAutoscaler.start(ctx)
			certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())
			prometheusTLS, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusTLSSecretName})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()
		})

		It("adrianaTODO should query calico-node DS and if FELIX_BPFENABLED true and FelixConfig unset then set BPF enabled", func() {

			// Arrange.
			// FELIX_BPFENABLED env var only set in BPF datatplane.
			createInstallation(c, ctx, operator.LinuxDataplaneBPF)

			// Create calico-node Daemonset with FELIX_BPFENABLED env var set.
			envVars := []corev1.EnvVar{{Name: "FELIX_BPFENABLED", Value: "true"}}
			container := corev1.Container{
				Name: render.CalicoNodeObjectName,
				Env:  envVars,
			}
			ds := &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{container},
						},
					},
				},
				Status: appsv1.DaemonSetStatus{
					CurrentNumberScheduled: 13,
				},
			}
			Expect(c.Create(ctx, ds)).NotTo(HaveOccurred())

			// Act.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Assert.
			bpfEnabled := true
			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.BPFEnabled).NotTo(BeNil())
			Expect(*fc.Spec.BPFEnabled).To(Equal(&bpfEnabled))

			sum := 4
			Expect(sum).To(Equal(4))
		})

		It("should use builtin images", func() {

			createInstallation(c, ctx, operator.LinuxDataplaneBPF)

			ds := getDS3(false)
			Expect(c.Create(ctx, ds)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			fc := &crdv1.FelixConfiguration{}
			err = c.Get(ctx, types.NamespacedName{Name: "default"}, fc)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(fc.Spec.HealthPort).NotTo(BeNil())
			Expect(*fc.Spec.HealthPort).To(Equal(9099))
			//Expect(fc.Spec.BPFLogLevel).To(Equal("Info"))

			sum := 5
			Expect(sum).To(Equal(5))
		})
	})

})

func createInstallation(c client.Client, ctx context.Context, dp operator.LinuxDataplaneOption) {
	ca, err := tls.MakeCA("test")
	Expect(err).NotTo(HaveOccurred())
	cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block

	//We start off with a 'standard' installation, with nothing special except setting the dataplane.
	cr := &operator.Installation{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: operator.InstallationSpec{
			Variant:               operator.Calico,
			Registry:              "some.registry.org/",
			CertificateManagement: &operator.CertificateManagement{CACert: cert},
			CalicoNetwork: &operator.CalicoNetworkSpec{
				LinuxDataplane: &dp,
			},
		},
	}
	Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
}

// DS env var set	FELIX_BPFENABLED: true
//func getDS1() *appsv1.DaemonSet {
//
//	envVars := []corev1.EnvVar{{Name: "FELIX_BPFENABLED", Value: "true"}}
//	container := corev1.Container{
//		Name: render.CalicoNodeObjectName,
//		Env:  envVars,
//	}
//
//	ds := &appsv1.DaemonSet{
//		ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
//		Spec: appsv1.DaemonSetSpec{
//			Template: corev1.PodTemplateSpec{
//				ObjectMeta: metav1.ObjectMeta{},
//				Spec: corev1.PodSpec{
//					Containers: []corev1.Container{container},
//				},
//			},
//		},
//		Status: appsv1.DaemonSetStatus{
//			CurrentNumberScheduled: 13,
//		},
//	}
//	return ds
//}

// DS env var NOT set
//func getDS2() *appsv1.DaemonSet {
//
//	envVars := []corev1.EnvVar{}
//	container := corev1.Container{
//		Name: render.CalicoNodeObjectName,
//		Env:  envVars,
//	}
//
//	ds := &appsv1.DaemonSet{
//		ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace},
//		Spec: appsv1.DaemonSetSpec{
//			Template: corev1.PodTemplateSpec{
//				ObjectMeta: metav1.ObjectMeta{},
//				Spec: corev1.PodSpec{
//					Containers: []corev1.Container{container},
//				},
//			},
//		},
//		Status: appsv1.DaemonSetStatus{
//			CurrentNumberScheduled: 2,
//		},
//	}
//	return ds
//}

// DS annotation set
func getDS3(annotation bool) *appsv1.DaemonSet {

	dsAnnotations := make(map[string]string)
	dsAnnotations[render.BpfOperatorAnnotation] = strconv.FormatBool(annotation)

	container := corev1.Container{Name: render.CalicoNodeObjectName}

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.NodeDaemonSetName,
			Namespace:   common.CalicoNamespace,
			Annotations: dsAnnotations,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{container}},
			},
		},
		//Status: appsv1.DaemonSetStatus{CurrentNumberScheduled: 3},
	}

	return ds
}
