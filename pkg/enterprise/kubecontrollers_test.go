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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
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

var _ = Describe("calico-kube-controllers enterprise surface", func() {
	calicoKubeControllersCfg := func(cc extensions.ControllerContext) *kubecontrollers.KubeControllersConfiguration {
		return &kubecontrollers.KubeControllersConfiguration{
			Installation:      cc.Installation,
			ClusterDomain:     cc.ClusterDomain,
			TrustedBundle:     cc.TrustedBundle,
			MetricsPort:       9094,
			Namespace:         common.CalicoNamespace,
			BindingNamespaces: []string{common.CalicoNamespace},
		}
	}

	// render builds the base calico-kube-controllers objects and applies the
	// enterprise modifier, exactly as the component handler does.
	renderKubeControllers := func(cc extensions.ControllerContext, rc extensions.RenderContext) []client.Object {
		comp := kubecontrollers.NewCalicoKubeControllers(calicoKubeControllersCfg(cc))
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()
		out, _ := applyExtensions(ext, render.ComponentNameKubeControllers, rc, create, del)
		return out
	}

	kubeContainer := func(objs []client.Object) *corev1.Container {
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController)
		Expect(ok).To(BeTrue())
		return &dp.Spec.Template.Spec.Containers[0]
	}

	It("layers the enterprise rules, controllers, and metrics TLS on (WAF off)", func() {
		rc, _, err := ext.ExtendContext(newControllerContext(operatorv1.CalicoEnterprise))
		Expect(err).NotTo(HaveOccurred())
		objs := renderKubeControllers(newControllerContext(operatorv1.CalicoEnterprise), rc)

		role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, kubecontrollers.KubeControllerRole)
		Expect(ok).To(BeTrue())
		Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))

		c := kubeContainer(objs)
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage",
		}))
		// Metrics serving TLS wired from the keypair the hook created.
		Expect(c.Env).To(ContainElement(HaveField("Name", "TLS_KEY_PATH")))
		// WAF is off, so no WASM env and no webhook objects.
		Expect(c.Env).NotTo(ContainElement(HaveField("Name", "WASM_IMAGE")))
		_, ok = extensions.FindObject[*corev1.Service](objs, applicationlayer.WAFWebhookServiceName)
		Expect(ok).To(BeFalse())
	})

	It("layers the full WAF surface on when the GatewayAPI extension is enabled", func() {
		cc := wafControllerContext()
		rc, managed, err := ext.ExtendContext(cc)
		Expect(err).NotTo(HaveOccurred())
		names := []string{}
		for _, kp := range managed {
			names = append(names, kp.GetName())
		}
		Expect(names).To(ContainElement(applicationlayer.WAFWebhookServerTLSSecretName))

		objs := renderKubeControllers(cc, rc)

		role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, kubecontrollers.KubeControllerRole)
		Expect(ok).To(BeTrue())
		Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("wafpolicies"))))

		c := kubeContainer(objs)
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage,applicationlayer",
		}))
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name: "WASM_IMAGE", Value: "test-reg/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version,
		}))
		Expect(c.Env).To(ContainElement(corev1.EnvVar{Name: "WASM_PULL_SECRET", Value: enterprise.WASMPullSecretName}))
		Expect(c.Env).To(ContainElement(corev1.EnvVar{Name: "WASM_CA_CERT", Value: enterprise.WASMCACertName}))
		Expect(c.Env).To(ContainElement(HaveField("Name", "WAF_WEBHOOK_CERT_DIR")))
		Expect(c.Ports).To(ContainElement(corev1.ContainerPort{Name: "waf-webhook", ContainerPort: int32(9443), Protocol: corev1.ProtocolTCP}))

		// The webhook surface, the wasm pull secret, and the wasm CA bundle are rendered.
		_, ok = extensions.FindObject[*corev1.Service](objs, applicationlayer.WAFWebhookServiceName)
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*corev1.Secret](objs, enterprise.WASMPullSecretName)
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*corev1.ConfigMap](objs, enterprise.WASMCACertName)
		Expect(ok).To(BeTrue())
	})

	It("deletes the WAF webhook surface when the extension is disabled", func() {
		cc := newControllerContext(operatorv1.CalicoEnterprise)
		rc, _, err := ext.ExtendContext(cc)
		Expect(err).NotTo(HaveOccurred())

		comp := kubecontrollers.NewCalicoKubeControllers(calicoKubeControllersCfg(cc))
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()
		_, toDelete := applyExtensions(ext, render.ComponentNameKubeControllers, rc, create, del)

		_, ok := extensions.FindObject[*corev1.Service](toDelete, applicationlayer.WAFWebhookServiceName)
		Expect(ok).To(BeTrue(), "the webhook Service should be queued for deletion")
	})

	It("adds the WAF webhook ingress rule to the network policy when enabled", func() {
		cc := wafControllerContext()
		rc, _, err := ext.ExtendContext(cc)
		Expect(err).NotTo(HaveOccurred())

		comp := kubecontrollers.NewCalicoKubeControllersPolicy(calicoKubeControllersCfg(cc), nil)
		create, del := comp.Objects()
		objs, _ := applyExtensions(ext, render.ComponentNameKubeControllersPolicy, rc, create, del)

		policy, ok := extensions.FindObject[*v3.NetworkPolicy](objs, kubecontrollers.KubeControllerNetworkPolicyName)
		Expect(ok).To(BeTrue())
		Expect(policy.Spec.Ingress).To(ContainElement(v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(applicationlayer.WAFWebhookContainerPort)),
			},
		}))
	})
})

// wafControllerContext builds a controller context with a WAF-enabled GatewayAPI CR
// and an install pull secret, so the installation hook produces the full WAF data.
func wafControllerContext() extensions.ControllerContext {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	Expect(c.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pull", Namespace: common.OperatorNamespace()},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"reg.example.com":{"auth":"abc"}}}`)},
	})).NotTo(HaveOccurred())

	enabled := operatorv1.WAFExtensionStateEnabled
	Expect(c.Create(context.Background(), &operatorv1.GatewayAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: operatorv1.GatewayAPISpec{
			Extensions: &operatorv1.GatewayAPIExtensions{WAF: &operatorv1.WAFExtensionSpec{State: &enabled}},
		},
	})).NotTo(HaveOccurred())

	certManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	return extensions.ControllerContext{
		RenderContext: extensions.RenderContext{
			Installation: &operatorv1.InstallationSpec{
				Variant:          operatorv1.CalicoEnterprise,
				Registry:         "test-reg/",
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pull"}},
			},
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
