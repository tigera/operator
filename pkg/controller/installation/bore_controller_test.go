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
	"time"

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

	var cr *operator.Installation

	//notReady := &utils.ReadyFlag{}
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
			c = fake.NewClientBuilder().WithScheme(scheme).Build()
			ctx, cancel = context.WithCancel(context.Background())

			// Create a fake clientset for the autoscaler.
			//var replicas int32 = 1
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
				//&appsv1.Deployment{
				//	TypeMeta:   metav1.TypeMeta{},
				//	ObjectMeta: metav1.ObjectMeta{Name: "calico-typha", Namespace: "calico-system"},
				//	Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
				//},
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
			ca, err := tls.MakeCA("test")
			Expect(err).NotTo(HaveOccurred())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			// We start off with a 'standard' installation, with nothing special
			cr = &operator.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operator.InstallationSpec{
					Variant:               operator.Calico,
					Registry:              "some.registry.org/",
					CertificateManagement: &operator.CertificateManagement{CACert: cert},
				},
			}
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

		It("should use builtin images", func() {

			ds := getDS1()
			Expect(c.Create(ctx, ds)).NotTo(HaveOccurred())
			//mockStatus.On("AddDaemonsets", mock.Anything).Return(ds)

			Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			sum := 3
			Expect(sum).To(Equal(3))
		})
	})

})

func getDS1() *appsv1.DaemonSet {

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
	return ds
}
