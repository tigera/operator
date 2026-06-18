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
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
)

var _ = Describe("kube-controllers enterprise modifier", func() {
	// kubeControllersDeployment is a minimal stand-in for the calico-kube-controllers
	// deployment the base render produces, so the modifier has something to mount onto.
	kubeControllersDeployment := func() *appsv1.Deployment {
		return &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.KubeController, Namespace: common.CalicoNamespace},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: kubecontrollers.KubeController}},
					},
				},
			},
		}
	}

	It("mounts the metrics serving TLS keypair onto the deployment", func() {
		rc, _, err := ext.ExtendContext(newControllerContext(operatorv1.CalicoEnterprise))
		Expect(err).NotTo(HaveOccurred())

		objs, _ := applyExtensions(ext, render.ComponentNameKubeControllers, rc, []client.Object{kubeControllersDeployment()}, nil)
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController)
		Expect(ok).To(BeTrue())

		c := dp.Spec.Template.Spec.Containers[0]
		Expect(c.Env).To(ContainElements(
			corev1.EnvVar{Name: "TLS_KEY_PATH", Value: "/calico-kube-controllers-metrics-tls/tls.key"},
			corev1.EnvVar{Name: "TLS_CRT_PATH", Value: "/calico-kube-controllers-metrics-tls/tls.crt"},
			corev1.EnvVar{Name: "CLIENT_COMMON_NAME", Value: monitor.PrometheusClientTLSSecretName},
		))
		Expect(c.VolumeMounts).To(ContainElement(HaveField("Name", kubecontrollers.KubeControllerPrometheusTLSSecret)))
		Expect(dp.Spec.Template.Spec.Volumes).To(ContainElement(HaveField("Name", kubecontrollers.KubeControllerPrometheusTLSSecret)))
		Expect(dp.Spec.Template.Annotations).NotTo(BeEmpty(), "expected the cert hash annotation")
	})

	It("adds the cert-management init container when certificate management is enabled", func() {
		rc, _, err := ext.ExtendContext(certManagementControllerContext())
		Expect(err).NotTo(HaveOccurred())

		objs, _ := applyExtensions(ext, render.ComponentNameKubeControllers, rc, []client.Object{kubeControllersDeployment()}, nil)
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController)
		Expect(ok).To(BeTrue())

		Expect(dp.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.InitContainers[0].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", kubecontrollers.KubeControllerPrometheusTLSSecret)))
	})
})

// certManagementControllerContext builds a controller context whose certificate
// manager issues cert-management (CSR-based) keypairs.
func certManagementControllerContext() extensions.ControllerContext {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
	Expect(err).NotTo(HaveOccurred())
	caCert, _, err := ca.Config.GetPEMBytes()
	Expect(err).NotTo(HaveOccurred())

	installation := &operatorv1.InstallationSpec{
		Variant:               operatorv1.CalicoEnterprise,
		CertificateManagement: &operatorv1.CertificateManagement{CACert: caCert},
	}
	certManager, err := certificatemanager.Create(c, installation, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	return extensions.ControllerContext{
		RenderContext: extensions.RenderContext{
			Installation:       installation,
			FelixConfiguration: &v3.FelixConfiguration{},
			TrustedBundle:      certManager.CreateTrustedBundle(),
			ClusterDomain:      "cluster.local",
		},
		Controller:         extensions.InstallationController,
		Ctx:                context.Background(),
		Client:             c,
		CertificateManager: certManager,
	}
}
